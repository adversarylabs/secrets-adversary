import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { type RuleContext } from "@adversarylabs/sdk";
import { isLikelyFalsePositiveSecret } from "./false-positives.js";
import { observationFor } from "./rules.js";
import { runModelSecretsReview } from "./model-review.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;

interface SourceFile { path: string; source: string }
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = scoped.map((file) => ({ path: file.path, source: file.content }));
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }

  const staticSeverities = detections.map((d) => String(d.rule.severity));
  const staticPrimaryConcern = detections[0]?.rule.title.toLowerCase();
  await runModelSecretsReview(
    ctx,
    detections.map((d) => ({
      ruleId: d.rule.id,
      file: d.file,
      line: d.line,
      snippet: d.snippet,
      message: d.label,
      severity: String(d.rule.severity),
    })),
    sources.map((s) => ({ path: s.path, content: s.source })),
    staticSeverities,
    staticPrimaryConcern,
  );
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locate(file.source, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    return locateAll(file.source, match.pattern).map((location) => ({
      rule,
      file: file.path,
      ...location,
      label: rule.title,
      data: { matchedPattern: match.pattern.pattern },
    }));
  });
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locate(source: string, expression: MatchExpression): { line: number; snippet: string } | undefined {
  return locateAll(source, expression)[0];
}

/** All non-false-positive matches for a content pattern, stable by line order. */
function locateAll(source: string, expression: MatchExpression): { line: number; snippet: string }[] {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  const re = new RegExp(expression.pattern, flags);
  const lines = source.split(/\r?\n/);
  const out: { line: number; snippet: string }[] = [];
  const seenLines = new Set<number>();
  let match: RegExpExecArray | null;
  while ((match = re.exec(source)) !== null) {
    if (match.index === undefined) break;
    // Avoid zero-length match infinite loops.
    if (match[0] === "") {
      re.lastIndex += 1;
      continue;
    }
    const lineNumber = source.slice(0, match.index).split(/\r?\n/).length;
    if (seenLines.has(lineNumber)) continue;
    const lineText = lines[lineNumber - 1] ?? "";
    const nearby = [lines[lineNumber - 2], lines[lineNumber], lines[lineNumber + 1]].filter(Boolean).join("\n");
    if (isLikelyFalsePositiveSecret(match[0], lineText, nearby)) continue;
    seenLines.add(lineNumber);
    out.push({ line: lineNumber, snippet: lineText.trim().slice(0, 240) });
  }
  return out;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
