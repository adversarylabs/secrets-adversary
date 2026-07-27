import assert from "node:assert/strict";
import test from "node:test";
import { isLikelyFalsePositiveSecret, isPlaceholderLikeToken } from "../src/false-positives.ts";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string) => createApp().run({ input: { source: { path: fixture(name) } } });

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
  const output = await review("rules/aws-key/clean");
  assert.equal(
    output.findings.some((finding) => finding.ruleId === "secrets.aws-key"),
    false,
    `unexpected aws-key findings: ${JSON.stringify(output.findings, null, 2)}`,
  );
});

test("aws-key still flags a realistic committed access key id", async () => {
  const output = await review("rules/aws-key/vulnerable");
  assert.equal(output.findings.some((finding) => finding.ruleId === "secrets.aws-key"), true);
});
