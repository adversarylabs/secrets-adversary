import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { isLikelyFalsePositiveSecret } from "./false-positives.js";
import { observationFor } from "./rules.js";
import { runModelSecretsReview } from "./model-review.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}
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
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    const change = wholeTarget || file.status === "repository"
      ? { changedLines: new Set<number>(), status: "repository" as const }
      : await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      changedLines: change.changedLines,
      status: change.status,
    });
  }
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

  if (match.kind === "query-credential-http-error") {
    return sources
      .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
      .flatMap((file) => findQueryCredentialHttpErrors(rule, file));
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
    return locateAll(file.source, match.pattern)
      .filter((location) => directFindingEligible(file, location.line))
      .map((location) => ({
        rule,
        file: file.path,
        ...location,
        label: rule.title,
        data: { matchedPattern: match.pattern.pattern },
      }));
  });
}

interface FunctionBlock { body: string; start: number; signature: string }
interface BalancedSource { source: string; end: number }

function findQueryCredentialHttpErrors(rule: RuleSpec, file: SourceFile): Detection[] {
  const detections: Detection[] = [];
  for (const block of findFunctionBlocks(file.source)) {
    const request = /\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.(get|post|put|patch|delete|head|request)\s*\(/g;
    for (const match of block.body.matchAll(request)) {
      if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
      if (!hasRequestsReceiverProof(file.source, block, match[2], match.index)) continue;
      const opening = block.body.indexOf("(", match.index + match[0].length - 1);
      const call = balancedSource(block.body, opening, "(", ")");
      if (call === undefined) continue;
      const credential = credentialQueryMapping(block.body, match.index, opening, call.source);
      if (credential === undefined) continue;

      const response = match[1];
      const afterCall = block.body.slice(call.end);
      const raise = new RegExp(`\\b${escapeRegExp(response)}\\.raise_for_status\\s*\\(\\s*\\)`).exec(afterCall);
      if (raise?.index === undefined) continue;
      const between = afterCall.slice(0, raise.index);
      if (new RegExp(`^\\s*${escapeRegExp(response)}\\s*=`, "m").test(between)) continue;
      const raiseIndex = call.end + raise.index;
      if (hasSanitizedHttpErrorHandler(block.body, raiseIndex)) continue;

      const semanticIndexes = [credential.index, match.index, raiseIndex]
        .map((index) => block.start + index);
      const semanticLines = semanticIndexes
        .map((index) => file.source.slice(0, index).split(/\r?\n/).length);
      const line = file.status === "modified"
        ? semanticLines.find((candidate) => file.changedLines.has(candidate))
        : semanticLines[0];
      if (line === undefined) continue;

      detections.push({
        rule,
        file: file.path,
        line,
        snippet: file.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "",
        label: `${credential.name} enters a URL-bearing HTTP error`,
        data: {
          credential: credential.name,
          parameterLine: semanticLines[0],
          requestLine: semanticLines[1],
          raiseLine: semanticLines[2],
        },
      });
    }
  }
  return detections;
}

function hasRequestsReceiverProof(
  fileSource: string,
  block: FunctionBlock,
  receiver: string,
  requestIndex: number,
): boolean {
  if (!/(?:^|\n)\s*import\s+requests\b/.test(fileSource)) return false;
  if (receiver === "requests") return true;
  if (new RegExp(`\\b${escapeRegExp(receiver)}\\s*:\\s*requests\\.Session\\b`).test(block.signature)) {
    return true;
  }
  return new RegExp(
    `^\\s*${escapeRegExp(receiver)}\\s*(?::[^=\\n]+)?=\\s*requests\\.Session\\s*\\(`,
    "m",
  ).test(block.body.slice(0, requestIndex));
}

function credentialQueryMapping(
  body: string,
  requestIndex: number,
  callOpening: number,
  callSource: string,
): { name: string; index: number } | undefined {
  const params = /\bparams\s*=\s*/g.exec(callSource);
  if (params?.index === undefined) return undefined;
  const valueStart = params.index + params[0].length;
  if (callSource[valueStart] === "{") {
    const mapping = balancedSource(callSource, valueStart, "{", "}");
    if (mapping === undefined) return undefined;
    return secretMappingEntry(mapping.source, callOpening + valueStart);
  }

  const variable = /^[A-Za-z_]\w*/.exec(callSource.slice(valueStart))?.[0];
  if (variable === undefined) return undefined;
  const assignment = new RegExp(`^([ \\t]*)${escapeRegExp(variable)}\\s*=\\s*\\{`, "gm");
  let selected: RegExpExecArray | undefined;
  for (const candidate of body.slice(0, requestIndex).matchAll(assignment)) selected = candidate;
  if (selected?.index === undefined) return undefined;
  const opening = body.indexOf("{", selected.index);
  const mapping = balancedSource(body, opening, "{", "}");
  if (mapping === undefined || mapping.end > requestIndex) return undefined;
  return secretMappingEntry(mapping.source, opening);
}

function secretMappingEntry(source: string, sourceIndex: number): { name: string; index: number } | undefined {
  const entry = /["']([A-Za-z_][A-Za-z0-9_-]*)["']\s*:\s*([^,}\n]+)/g;
  for (const match of source.matchAll(entry)) {
    if (match.index === undefined || match[1] === undefined || match[2] === undefined) continue;
    const key = match[1];
    const value = match[2].trim();
    if (isSecretName(key) || isSecretName(value)) {
      return { name: isSecretName(value) ? value : key, index: sourceIndex + match.index };
    }
  }
  return undefined;
}

function isSecretName(value: string): boolean {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, "_");
  if (/(?:^|_)(?:page|next|continuation|cursor)_token(?:_|$)/.test(normalized)) return false;
  return /(?:^|_)(?:api_key|access_key|private_key|access_token|auth_token|secret|password|passwd|credential|bearer|auth|token)(?:_|$)/.test(normalized);
}

function hasSanitizedHttpErrorHandler(body: string, raiseIndex: number): boolean {
  const before = body.slice(Math.max(0, raiseIndex - 1_200), raiseIndex);
  if (!/^\s*try\s*:\s*$/m.test(before)) return false;
  const after = body.slice(raiseIndex, raiseIndex + 2_000);
  const handler = /^\s*except\s+(?:requests\.)?(?:exceptions\.)?(?:HTTPError|RequestException)\b[^:]*:\s*\n((?:[ \\t]+[^\n]*(?:\n|$)){1,12})/m.exec(after)?.[1];
  if (handler === undefined) return false;
  if (!/^\s*raise\b/m.test(handler)) return true;
  if (!/\bfrom\s+None\b/.test(handler)) return false;
  if (/\bstr\s*\(|\braise\s*$/m.test(handler)) return false;
  if (/\.(?:request|response)\.url\b/.test(handler) && !/urlsplit|urlparse|split\s*\(\s*["']\?["']|partition\s*\(\s*["']\?["']/.test(handler)) return false;
  return /status_code|urlsplit|urlparse|\.path\b|split\s*\(\s*["']\?["']|partition\s*\(\s*["']\?["']/.test(handler);
}

function balancedSource(
  source: string,
  opening: number,
  open: "(" | "{",
  close: ")" | "}",
): BalancedSource | undefined {
  if (opening < 0 || source[opening] !== open) return undefined;
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let index = opening; index < source.length; index += 1) {
    const character = source[index];
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === open) depth += 1;
    else if (character === close) {
      depth -= 1;
      if (depth === 0) return { source: source.slice(opening, index + 1), end: index + 1 };
    }
  }
  return undefined;
}

function findFunctionBlocks(source: string): FunctionBlock[] {
  const blocks: FunctionBlock[] = [];
  const definition = /^(?<indent>[ \\t]*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(/gm;
  for (const match of source.matchAll(definition)) {
    if (match.index === undefined) continue;
    const indent = match.groups?.indent?.length ?? 0;
    const opening = source.indexOf("(", match.index);
    const signature = balancedSource(source, opening, "(", ")");
    if (signature === undefined) continue;
    const signatureEnd = source.indexOf("\n", signature.end);
    if (signatureEnd < 0 || !source.slice(signature.end, signatureEnd).includes(":")) continue;
    const bodyStart = signatureEnd + 1;
    if (bodyStart <= 0) continue;
    let end = source.length;
    let cursor = bodyStart;
    while (cursor < source.length) {
      const nextNewline = source.indexOf("\n", cursor);
      const lineEnd = nextNewline < 0 ? source.length : nextNewline;
      const line = source.slice(cursor, lineEnd);
      if (line.trim() !== "" && (line.match(/^[ \\t]*/)?.[0].length ?? 0) <= indent) {
        end = cursor;
        break;
      }
      cursor = nextNewline < 0 ? source.length : nextNewline + 1;
    }
    blocks.push({
      body: source.slice(bodyStart, end),
      start: bodyStart,
      signature: source.slice(match.index, signatureEnd),
    });
  }
  return blocks;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function directFindingEligible(file: SourceFile, line: number): boolean {
  return file.status !== "modified" || file.changedLines.has(line);
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
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
