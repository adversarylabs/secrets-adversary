import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

async function withFixture(
  files: Record<string, string>,
  fn: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "secrets-adv-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const path = join(dir, rel);
      await writeFile(path, content);
    }
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const review = (path: string, raw = false) =>
  createApp().run({ input: { source: { path } }, includeRawObservations: raw });

/** Build synthetic detector samples without embedding provider-valid secret strings in source. */
function parts(...chunks: string[]): string {
  return chunks.join("");
}

const CASES: Array<{ id: string; vulnerable: () => Record<string, string>; clean: () => Record<string, string> }> = [
  {
    id: "secrets.aws.access-key-id",
    vulnerable: () => ({ "config.env": `AWS_ACCESS_KEY_ID=${parts("AKIA", "ABCDEFGHIJKLMNOP")}\n` }),
    clean: () => ({ "config.env": "AWS_ACCESS_KEY_ID=\n" }),
  },
  {
    id: "secrets.aws.secret-access-key",
    vulnerable: () => ({
      "aws.conf": `aws_secret_access_key=${parts("Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3", "/")}\n`,
    }),
    clean: () => ({ "aws.conf": "aws_secret_access_key=REDACTED\n" }),
  },
  {
    id: "secrets.github.pat",
    vulnerable: () => ({ "token.txt": `token=${parts("ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".slice(0, 36))}\n` }),
    clean: () => ({ "token.txt": "token=\n" }),
  },
  {
    id: "secrets.github.fine-grained",
    vulnerable: () => ({
      "pat.txt": `${parts("github", "_pat_", "11AAAAAAA0", "BcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abc")}\n`,
    }),
    clean: () => ({ "pat.txt": "token=\n" }),
  },
  {
    id: "secrets.ssh.private-key",
    vulnerable: () => ({
      "key.pem": [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfnFAKE",
        "-----END RSA PRIVATE KEY-----",
        "",
      ].join("\n"),
    }),
    clean: () => ({ "key.pem": "# public only\n" }),
  },
  {
    id: "secrets.private-key.openssh",
    vulnerable: () => ({
      "id_ed25519": [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "b3BlbnNzaC1rZXktdjEAAAAA",
        "-----END OPENSSH PRIVATE KEY-----",
        "",
      ].join("\n"),
    }),
    clean: () => ({ "id_ed25519": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJustAPublicKey\n" }),
  },
  {
    id: "secrets.stripe.live-key",
    vulnerable: () => ({ "stripe.env": `STRIPE_KEY=${parts("sk_", "live_", "xY9mKp2nQ4vR7sT1uW3zA5bC")}\n` }),
    clean: () => ({ "stripe.env": `STRIPE_KEY=${parts("sk_", "test_", "xY9mKp2nQ4vR7sT1uW3zA5bC")}\n` }),
  },
  {
    id: "secrets.dotenv.committed",
    vulnerable: () => ({ ".env": "API_SECRET=super-secret-value-12345\n" }),
    clean: () => ({ ".env": "API_SECRET=\n" }),
  },
  {
    id: "secrets.db.connection-string",
    vulnerable: () => ({ "db.url": "DATABASE_URL=postgres://user:p4ssw0rd@db.example.com:5432/app\n" }),
    clean: () => ({ "db.url": "DATABASE_URL=postgres://user:${DB_PASSWORD}@db.example.com:5432/app\n" }),
  },
  {
    id: "secrets.ai.provider-key",
    vulnerable: () => ({
      "ai.env": `ANTHROPIC_API_KEY=${parts("sk-ant-api", "03-", "AbCdEfGhIjKlMnOpQrStUvWxYz")}\n`,
    }),
    clean: () => ({ "ai.env": "ANTHROPIC_API_KEY=\n" }),
  },
  {
    id: "secrets.k8s.secret-manifest",
    vulnerable: () => ({
      "secret.yaml":
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  password: s3cretValueHere\n",
    }),
    clean: () => ({
      "secret.yaml":
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  password: ${PASSWORD}\n",
    }),
  },
  {
    id: "secrets.slack.token",
    // split so push protection does not see a full xoxb- token literal
    vulnerable: () => ({
      "slack.env": `SLACK_TOKEN=${parts("xox", "b-", "123456789012-1234567890123-", "AbCdEfGhIjKlMnOpQrStUv")}\n`,
    }),
    clean: () => ({ "slack.env": "SLACK_TOKEN=\n" }),
  },
  {
    id: "secrets.npm.token",
    vulnerable: () => ({
      ".npmrc": `//registry.npmjs.org/:_authToken=${parts("npm_", "AbCdEfGhIjKlMnOpQrStUv")}\n`,
    }),
    clean: () => ({ ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n" }),
  },
  {
    id: "secrets.sendgrid.api-key",
    vulnerable: () => ({
      "sendgrid.env": `SENDGRID_API_KEY=${parts(
        "SG.",
        "AbCdEfGhIjKlMnOpQrStUv",
        ".",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG",
      )}\n`,
    }),
    clean: () => ({ "sendgrid.env": "SENDGRID_API_KEY=\n" }),
  },
];

test("every P0 secrets rule has vulnerable and clean coverage", async () => {
  for (const rule of CASES) {
    await withFixture(rule.vulnerable(), async (dir) => {
      const vulnerable = await review(dir, true);
      assert.equal(
        vulnerable.findings.some(
          (f) =>
            f.ruleId === rule.id ||
            (rule.id === "secrets.aws.access-key-id" && f.ruleId === "secrets.aws-key"),
        ),
        true,
        `${rule.id} missed vulnerable; got ${vulnerable.findings.map((f) => f.ruleId).join(",")}`,
      );
    });
    await withFixture(rule.clean(), async (dir) => {
      const clean = await review(dir);
      assert.equal(
        clean.findings.some(
          (f) =>
            f.ruleId === rule.id ||
            (rule.id === "secrets.aws.access-key-id" && f.ruleId === "secrets.aws-key"),
        ),
        false,
        `${rule.id} flagged clean`,
      );
    });
  }
});

test("accepts a repository without secrets", async () => {
  const fixture = new URL("../fixtures/clean", import.meta.url).pathname;
  const output = await review(fixture);
  assert.deepEqual(output.findings, []);
});

test("deterministic envelope", async () => {
  await withFixture(CASES[0]!.vulnerable(), async (dir) => {
    const first = await review(dir, true);
    const second = await review(dir, true);
    assert.deepEqual(second, first);
    const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
    assert.equal(envelope.protocolVersion, 1);
  });
});
