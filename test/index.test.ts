import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

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
const flowFixture = (kind: "vulnerable" | "clean") =>
  new URL(`../fixtures/rules/query-credential-http-error/${kind}`, import.meta.url).pathname;

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
    id: "secrets.symfony.default-secret",
    vulnerable: () => ({
      "parameters.yml": `parameters:\n  secret: ${parts("This", "EzPlatformTokenIsNotSoSecret_PleaseChangeIt")}\n`,
    }),
    clean: () => ({
      "parameters.yml": "parameters:\n  secret: ${APP_SECRET}\n",
      ".env.example": "APP_SECRET=ThisTokenIsOnlyAnExample\n",
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

test("detects both known Symfony default secrets", async () => {
  const defaults = [
    parts("This", "TokenIsNotSoSecretChangeIt"),
    parts("This", "EzPlatformTokenIsNotSoSecret_PleaseChangeIt"),
  ];
  for (const value of defaults) {
    await withFixture({ "parameters.yml": `parameters:\n  secret: ${value}\n` }, async (dir) => {
      const output = await review(dir);
      assert.equal(output.findings.some((finding) => finding.ruleId === "secrets.symfony.default-secret"), true);
    });
  }
});

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

test("detects an escaping Requests error with a query credential", async () => {
  const output = await review(flowFixture("vulnerable"), true);
  const observation = output.rawObservations?.find(
    (item) => item.ruleId === "secrets.query-credential-http-error",
  );
  assert.equal(observation?.location?.file, "client.py");
  assert.equal(observation?.location?.line, 10);
  assert.deepEqual(observation?.evidence, {
    label: "api_key enters a URL-bearing HTTP error",
    credential: "api_key",
    parameterLine: 10,
    requestLine: 13,
    raiseLine: 14,
  });
});

test("keeps safe Requests credential and query handling quiet", async () => {
  const output = await review(flowFixture("clean"), true);
  assert.equal(
    output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
    false,
    JSON.stringify(output.rawObservations),
  );
});

test("detects inline credential params without requiring a project-specific key", async () => {
  await withFixture({
    "client.py": [
      "import requests",
      "def fetch(uri, token):",
      "    response = requests.get(uri, params={'access_token': token}, timeout=10)",
      "    response.raise_for_status()",
      "    return response.json()",
      "",
    ].join("\n"),
  }, async (dir) => {
    const output = await review(dir);
    assert.equal(
      output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
      true,
    );
  });
});

test("detects Requests Session errors that are logged and re-raised unchanged", async () => {
  await withFixture({
    "client.py": [
      "import logging",
      "import requests",
      "logger = logging.getLogger(__name__)",
      "def fetch(uri, api_key):",
      "    session = requests.Session()",
      "    params = {'auth': api_key}",
      "    response = session.get(uri, params=params, timeout=10)",
      "    try:",
      "        response.raise_for_status()",
      "    except requests.HTTPError:",
      "        logger.exception('request failed')",
      "        raise",
      "    return response.json()",
      "",
    ].join("\n"),
  }, async (dir) => {
    const output = await review(dir);
    assert.equal(
      output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
      true,
    );
  });
});

test("logging or capturing the original HTTP error remains reportable", async () => {
  for (const sink of [
    "logger.exception('request failed')",
    "print(exc)",
    "capture_exception(exc)",
  ]) {
    await withFixture({
      "client.py": [
        "import logging",
        "import requests",
        "logger = logging.getLogger(__name__)",
        "def fetch(session: requests.Session, uri, api_key):",
        "    response = session.get(uri, params={'api_key': api_key}, timeout=10)",
        "    try:",
        "        response.raise_for_status()",
        "    except requests.HTTPError as exc:",
        `        ${sink}`,
        "        return None",
        "",
      ].join("\n"),
    }, async (dir) => {
      const output = await review(dir);
      assert.equal(
        output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
        true,
        sink,
      );
    });
  }
});

test("comments docstrings and strings cannot synthesize a Requests flow", async () => {
  await withFixture({
    "client.py": [
      "import requests",
      "def documentation_only():",
      "    '''",
      "    response = requests.get(uri, params={'api_key': api_key})",
      "    response.raise_for_status()",
      "    '''",
      "    text = \"response = requests.get(uri, params={'api_key': api_key}); response.raise_for_status()\"",
      "    # response = requests.get(uri, params={'api_key': api_key})",
      "    # response.raise_for_status()",
      "    return text",
      "",
      "fake = '''def fetch():",
      "    response = requests.get(uri, params={'api_key': api_key})",
      "    response.raise_for_status()",
      "'''",
      "",
    ].join("\n"),
  }, async (dir) => {
    const output = await review(dir);
    assert.equal(
      output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
      false,
    );
  });
});

test("non-code params text inside a real Requests call stays quiet", async () => {
  await withFixture({
    "client.py": [
      "import requests",
      "def send_string_payload(uri, api_key):",
      "    response = requests.post(",
      "        uri,",
      "        data=\"params={'api_key': api_key}\",",
      "        timeout=10,",
      "    )",
      "    response.raise_for_status()",
      "    return response.json()",
      "",
      "def fetch_with_commented_example(uri, api_key):",
      "    response = requests.get(",
      "        uri,",
      "        # params={'api_key': api_key},",
      "        timeout=10,",
      "    )",
      "    response.raise_for_status()",
      "    return response.json()",
      "",
    ].join("\n"),
  }, async (dir) => {
    const output = await review(dir);
    assert.equal(
      output.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
      false,
    );
  });
});

test("query credential error findings stay local to semantic changes", async () => {
  const safe = [
    "import requests",
    "def fetch(session: requests.Session, uri, page, api_key):",
    "    params = {'page': page}",
    "    response = session.get(uri, params=params, timeout=10)",
    "    response.raise_for_status()",
    "    return response.json()",
    "",
  ].join("\n");
  const root = await gitRepository({ "client.py": safe });
  try {
    await writeFile(join(root, "client.py"), `${safe}\n# document client ownership\n`);
    const unrelated = await changedReview(root, ["client.py"]);
    assert.equal(
      unrelated.findings.some((item) => item.ruleId === "secrets.query-credential-http-error"),
      false,
    );

    await writeFile(
      join(root, "client.py"),
      safe.replace("{'page': page}", "{'api_key': api_key}"),
    );
    const changed = await changedReview(root, ["client.py"]);
    const observation = changed.rawObservations?.find(
      (item) => item.ruleId === "secrets.query-credential-http-error",
    );
    assert.equal(observation?.location?.line, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unrelated edit does not surface a legacy direct secret", async () => {
  const accessKey = parts("AKIA", "ABCDEFGHIJKLMNOP");
  const root = await gitRepository({ "config.env": `AWS_ACCESS_KEY_ID=${accessKey}\n` });
  try {
    await writeFile(join(root, "config.env"), `AWS_ACCESS_KEY_ID=${accessKey}\n# unrelated documentation update\n`);

    const output = await changedReview(root, ["config.env"]);
    assert.equal(
      output.findings.some((finding) =>
        finding.ruleId === "secrets.aws.access-key-id" || finding.ruleId === "secrets.aws-key"),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a newly added file remains fully eligible for direct secret findings", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  try {
    await writeFile(
      join(root, "config.env"),
      `AWS_ACCESS_KEY_ID=${parts("AKIA", "ABCDEFGHIJKLMNOP")}\n`,
    );

    const output = await changedReview(root, ["config.env"]);
    assert.equal(
      output.findings.some((finding) =>
        finding.ruleId === "secrets.aws.access-key-id" || finding.ruleId === "secrets.aws-key"),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("deterministic envelope", async () => {
  await withFixture(CASES[0]!.vulnerable(), async (dir) => {
    const first = await review(dir, true);
    const second = await review(dir, true);
    assert.deepEqual(second, first);
    const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
    assert.equal(envelope.protocolVersion, 1);
    assert.equal(envelope.result.adversary.version, "0.0.16");
  });
});

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "secrets-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
