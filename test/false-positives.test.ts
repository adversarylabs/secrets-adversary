import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { isLikelyFalsePositiveSecret, isPlaceholderLikeToken } from "../src/false-positives.ts";
import { createApp } from "../src/index.ts";

test("placeholder AWS masks are false positives", () => {
  assert.equal(isPlaceholderLikeToken("XXXXXXXXXXXXXXXX"), true);
  assert.equal(isPlaceholderLikeToken("ABCDEFGHIJKLMNOP"), false);
  assert.equal(
    isLikelyFalsePositiveSecret("AKIAXXXXXXXXXXXXXXXX", `return "AKIAXXXXXXXXXXXXXXXX"`),
    true,
  );
  assert.equal(
    isLikelyFalsePositiveSecret("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    true,
  );
  assert.equal(
    isLikelyFalsePositiveSecret(
      "AKIAABCDEFGHIJKLMNOP",
      "// this is a test secret and not real: AKIAABCDEFGHIJKLMNOP",
    ),
    true,
  );
  assert.equal(
    isLikelyFalsePositiveSecret("AKIAABCDEFGHIJKLMNOP", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"),
    false,
  );
});

test("aws-key clean fixture includes redaction masks without findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aws-clean-"));
  try {
    await writeFile(join(dir, "config.env"), "AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX\n");
    const output = await createApp().run({ input: { source: { path: dir } } });
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "secrets.aws-key" || finding.ruleId === "secrets.aws.access-key-id"),
      false,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("aws-key still flags a realistic committed access key id", async () => {
  const dir = await mkdtemp(join(tmpdir(), "aws-vuln-"));
  try {
    await writeFile(join(dir, "config.env"), "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n");
    const output = await createApp().run({ input: { source: { path: dir } } });
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "secrets.aws-key" || finding.ruleId === "secrets.aws.access-key-id"),
      true,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
