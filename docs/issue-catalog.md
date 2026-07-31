# security/secrets — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `security/secrets`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Find **real committed credentials** with extreme precision. This adversary is trust-critical: one noisy FP destroys product credibility.

## LLM strategy (required for world-class)
**Enhance static:** validate candidate matches (is this a real key shape or a hash/UUID/public key?).  
**Discover new:** rare provider formats, multi-line cloud configs, and “almost redacted” leaks.  
**Never invent secrets.** LLM may only classify candidates produced by detectors or explicit high-entropy secret-like assignments.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Precise, deterministic signals with line-level evidence. High confidence only when AST/text facts are unambiguous. |
| **LLM enhancement** | Explain impact, connect multi-file stories, rank, rewrite recommendations, suppress FP when context proves safe. |
| **LLM discovery** | Propose novel issues *only* with concrete evidence (file:line + snippet). Must not invent CVEs or claim secrets without pattern match. |

### Trust / anti-FP rules (all issues)
1. Never report without **file + line + snippet** (or explicit multi-file evidence list).
2. Prefer **high confidence** only for deterministic facts; LLM-only findings default **medium/low** until a static rule exists.
3. Group related evidence into **one finding** with one remediation story.
4. Skip generated/vendor/third_party/node_modules unless explicitly in scope.
5. When unsure, **do not report**.

## Review verdicts (staff pass)

- **P0 implement:** `aws.access-key-id`, `aws.secret-access-key`, `github.pat`, `github.fine-grained`, `ssh.private-key`, `private-key.openssh`, `stripe.live-key`, `dotenv.committed`, `db.connection-string`, `ai.provider-key`, `k8s.secret-manifest`, `slack.token`, `npm.token`, `sendgrid.api-key`
- **P1:** `google.api-key`, `jwt.hardcoded`, `pypi.token`, `azure.storage-key`, `heroku.api-key`, `twilio.auth`, `base64.pem-blob`, `ci.workflow-echo`, `docker.auth-config`, `terraform.tfvars`, `age-or-sops.unencrypted`
- **LLM-only (ship last):** `generic.high-entropy-assignment` — keep behind the mandatory LLM gate and a strict identifier allowlist; this rule is where secrets scanners go to die on precision.
- **Cut:** none — this is the strongest catalog.

## Issue catalog
Each issue is a candidate rule or LLM probe. After approval, each gets fixtures under `fixtures/` (vulnerable + clean) and regression tests.

---
### 1. `secrets.aws.access-key-id` — AWS access key ID in source

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** AKIA/ASIA-style AWS access key IDs committed in source or config.

**Static detection.** Regex for `AKIA[0-9A-Z]{16}` / `ASIA…` with entropy checks on adjacent secret key.

**LLM role.** Confirm not in docs/tests; assess if paired secret present; escalate severity if both.

**False-positive guards.** Allow known fake keys (AKIAIOSFODNN7EXAMPLE) and test fixtures marked as examples.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/OWASP/wrongsecrets — AWS key patterns in vulnerable challenges
  - https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors/aws
  - https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml — aws-access-key rule

---
### 2. `secrets.aws.secret-access-key` — AWS secret access key

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** 40-char base64-ish AWS secret access keys near aws config or env assignments.

**Static detection.** High-entropy string assignment to AWS_SECRET_* or secretAccessKey fields.

**LLM role.** Correlate with access key ID; suppress if clearly redacted (****, YOUR_SECRET).

**False-positive guards.** Redacted placeholders, CSS hashes, and intentional test doubles.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/OWASP/wrongsecrets
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/gitleaks/gitleaks

---
### 3. `secrets.github.pat` — GitHub personal access token

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** ghp_/gho_/ghu_/ghs_/ghr_ tokens in repo text.

**Static detection.** Prefix + length regex with entropy.

**LLM role.** Validate token-like context (Authorization headers, env GITHUB_TOKEN assignments outside CI).

**False-positive guards.** GHES examples in docs using placeholders; ghp_ followed by x's.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks — github-pat rules
  - https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors/github
  - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens — shape docs

---
### 4. `secrets.github.fine-grained` — GitHub fine-grained PAT

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** github_pat_… fine-grained tokens.

**Static detection.** Prefix regex github_pat_[A-Za-z0-9_]{20,}

**LLM role.** Same as classic PAT.

**False-positive guards.** Documentation placeholders.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/github/docs — auth token documentation examples

---
### 5. `secrets.ssh.private-key` — PEM private key material

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY blocks in repo.

**Static detection.** Block detector for PEM headers; ignore .pub files.

**LLM role.** Distinguish deploy-key examples in tutorials vs real keys (entropy of body).

**False-positive guards.** Test keys labeled EXAMPLE; encrypted keys still report as medium.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/OWASP/wrongsecrets
  - https://github.com/gitleaks/gitleaks — private-key rule
  - https://github.com/trufflesecurity/trufflehog

---
### 6. `secrets.slack.token` — Slack API token

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** xoxb-/xoxp-/xoxa-/xoxs- tokens.

**Static detection.** Prefix + charset regex.

**LLM role.** Suppress slack example tokens from their docs samples when clearly fake.

**False-positive guards.** xoxb-0000 placeholders.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors/slack
  - https://api.slack.com/authentication/token-types — token prefixes

---
### 7. `secrets.stripe.live-key` — Stripe live secret key

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** sk_live_… Stripe secret keys.

**Static detection.** Prefix regex; treat sk_test_ as lower severity or info.

**LLM role.** Distinguish live vs test; only high on live.

**False-positive guards.** Stripe docs sample keys.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/stripe/stripe-python — test key usage in examples (clean: sk_test)
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog

---
### 8. `secrets.google.api-key` — Google API key

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** AIza… Google API keys in client code.

**Static detection.** AIza[0-9A-Za-z\-_]{35} with assignment context.

**LLM role.** Many browser-restricted keys are intentional; LLM should note restriction headers if present.

**False-positive guards.** Public Maps demo keys with referrer restrictions — downgrade severity.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/googlemaps/js-samples — client-side key patterns
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog

---
### 9. `secrets.jwt.hardcoded` — Hardcoded JWT signing secret

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** jwt.sign / HS256 secrets as string literals.

**Static detection.** AST/string patterns near jwt libraries; short static secrets.

**LLM role.** LLM: is this production code path vs unit test?

**False-positive guards.** Test secrets named 'test-secret' in *_test files.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/auth0/node-jsonwebtoken — README examples (clean baseline)
  - https://github.com/OWASP/wrongsecrets — JWT challenges
  - https://github.com/gitleaks/gitleaks — generic high-entropy

---
### 10. `secrets.db.connection-string` — Database URL with embedded password

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** postgres://user:pass@host, mongodb+srv://… with credentials.

**Static detection.** URL scheme + userinfo regex.

**LLM role.** Allow user:password placeholders and env var interpolation ${PASSWORD}.

**False-positive guards.** Documentation docker-compose examples using 'password'.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/docker/awesome-compose — compose DB password examples
  - https://github.com/OWASP/wrongsecrets
  - https://github.com/gitleaks/gitleaks — generic-api-key / uri rules

---
### 11. `secrets.dotenv.committed` — Committed .env with secrets

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** .env / .env.local / .env.production files containing KEY=value secrets.

**Static detection.** Path rules + value entropy; ignore .env.example with empty values.

**LLM role.** LLM: which keys look like real secrets vs empty/template.

**False-positive guards.** .env.example, .env.sample with placeholders.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/bkeepers/dotenv — docs warn against committing .env
  - https://github.com/motdotla/dotenv
  - https://github.com/github/gitignore — Node.gitignore .env entry

---
### 12. `secrets.npm.token` — npm automation token

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** npm_… tokens or _authToken in .npmrc.

**Static detection.** npm_ prefix and //registry.npmjs.org/:_authToken=

**LLM role.** Ignore CI examples that use ${NPM_TOKEN}.

**False-positive guards.** Placeholder tokens in docs.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
  - https://docs.npmjs.com/about-access-tokens

---
### 13. `secrets.pypi.token` — PyPI API token

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** pypi-AgEIcHlwaS5vcmc… tokens.

**Static detection.** pypi- prefix regex.

**LLM role.** Same as npm.

**False-positive guards.** Docs placeholders.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
  - https://pypi.org/help/#apitoken

---
### 14. `secrets.azure.storage-key` — Azure storage account key

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** AccountKey= base64 blobs in connection strings.

**Static detection.** Connection string parsers for DefaultEndpointsProtocol + AccountKey.

**LLM role.** Suppress Azurite/devstoreaccount1 well-known keys.

**False-positive guards.** Azure docs sample account keys.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/Azure/azure-sdk-for-go — samples
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog

---
### 15. `secrets.heroku.api-key` — Heroku API key

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** HEROKU_API_KEY= UUID-like values.

**Static detection.** Env assignment + UUID shape.

**LLM role.** Context-based.

**False-positive guards.** Test UUIDs.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
  - https://devcenter.heroku.com/articles/authentication

---
### 16. `secrets.twilio.auth` — Twilio account SID / auth token pair

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** AC… SIDs with nearby auth tokens.

**Static detection.** AC[a-f0-9]{32} + high-entropy neighbor.

**LLM role.** Twilio test credentials documented as safe — detect and downgrade.

**False-positive guards.** AC000000… test SIDs.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/twilio/twilio-python — test creds in tests
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog

---
### 17. `secrets.sendgrid.api-key` — SendGrid API key

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** SG.… API keys.

**Static detection.** SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}

**LLM role.** Suppress obvious fakes.

**False-positive guards.** SendGrid sample keys in docs.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/sendgrid/sendgrid-python

---
### 18. `secrets.private-key.openssh` — OpenSSH private key file

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** Files named id_rsa, id_ed25519 without .pub containing private key headers.

**Static detection.** Filename + PEM content.

**LLM role.** Ignore empty templates.

**False-positive guards.** Test fixtures under testdata/ with generate_test_keys scripts.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/OWASP/wrongsecrets
  - https://github.com/gitleaks/gitleaks
  - https://github.com/openssh/openssh-portable — key format docs

---
### 19. `secrets.generic.high-entropy-assignment` — High-entropy secret assignment

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |
| **Primary mode** | static + LLM |

**What it is.** const apiKey = '<high entropy>'; generic catch-all.

**Static detection.** Shannon entropy + assignment to secret-like identifiers.

**LLM role.** LLM mandatory to suppress hashes, UUIDs for non-secret ids, public keys.

**False-positive guards.** Strict allowlist of identifier names; never report without secret-like LHS.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/Yelp/detect-secrets
  - https://github.com/gitleaks/gitleaks — generic-api-key
  - https://github.com/trufflesecurity/trufflehog — entropy detectors

---
### 20. `secrets.base64.pem-blob` — Base64-encoded private key blob

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** Long base64 that decodes to PEM private key.

**Static detection.** Decode candidates and re-scan for PEM headers.

**LLM role.** Cap CPU; only on secret-like keys.

**False-positive guards.** Large base64 assets that are not keys (images).

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/gitleaks/gitleaks
  - https://github.com/OWASP/wrongsecrets

---
### 21. `secrets.ci.workflow-echo` — Secret echoed in CI logs

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** echo ${{ secrets.X }} or print(os.environ['SECRET']) in workflows/scripts.

**Static detection.** Workflow YAML + shell patterns.

**LLM role.** LLM: is secret masked by ::add-mask::?

**False-positive guards.** Debug steps that intentionally print lengths only.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/github/docs — security hardering for Actions
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://github.com/actions/runner — masking behavior

---
### 22. `secrets.docker.auth-config` — Docker config.json auth

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** auths: { registry: { auth: base64(user:pass) } } committed.

**Static detection.** Parse .docker/config.json / config.json auth fields.

**LLM role.** Ignore empty auth objects.

**False-positive guards.** CI examples using ${{ secrets }} injection only.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/docker/cli — config file format
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog

---
### 23. `secrets.terraform.tfvars` — Secrets in terraform.tfvars

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** Sensitive values in *.auto.tfvars / terraform.tfvars.

**Static detection.** Path + key names password/secret/token.

**LLM role.** Allow terraform.tfvars.example.

**False-positive guards.** Public module examples with dummy values.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/hashicorp/terraform — sensitive values docs
  - https://github.com/gitleaks/gitleaks
  - https://github.com/bridgecrewio/checkov — tf secrets patterns

---
### 24. `secrets.age-or-sops.unencrypted` — Unencrypted sibling of sops/age file

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |
| **Primary mode** | static + LLM |

**What it is.** secrets.yaml next to secrets.enc.yaml suggesting plaintext left behind.

**Static detection.** Path pairing heuristics.

**LLM role.** LLM: compare if values look encrypted.

**False-positive guards.** Intentional dual files in demos.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/getsops/sops — examples
  - https://github.com/FiloSottile/age
  - https://github.com/mozilla/sops (historical paths)

---
### 25. `secrets.ai.provider-key` — AI provider API keys (Anthropic/OpenAI/etc.)

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** `sk-ant-api03-…` (Anthropic), `sk-proj-…`/`sk-…` (OpenAI), `gsk_…` (Groq), `hf_…` (Hugging Face) keys committed to source. Among the most-leaked and most directly monetizable credentials since 2023 — table stakes for a secrets scanner in 2026.

**Static detection.** Per-provider prefix regexes with length/charset + entropy checks; keep providers as separate rules for precision and reporting.

**LLM role.** Suppress obvious placeholders (sk-ant-xxx…, YOUR_API_KEY, truncated doc examples); note proximity to client constructors to raise confidence.

**False-positive guards.** Documentation placeholders; strings shorter than the provider's real key length; test doubles clearly labeled fake.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/gitleaks/gitleaks — anthropic/openai rules
  - https://github.com/trufflesecurity/trufflehog — provider detectors
  - https://docs.anthropic.com/en/api/getting-started — key shape documentation

---
### 26. `secrets.k8s.secret-manifest` — Populated Kubernetes Secret manifests committed

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |
| **Primary mode** | static + LLM |

**What it is.** `kind: Secret` manifests with real values in `data:`/`stringData:` committed to the repo. Base64 is not encryption; this is a plaintext secret with extra steps.

**Static detection.** YAML parse for kind: Secret; base64-decode data values; entropy + non-placeholder checks on decoded content.

**LLM role.** Distinguish templated values ({{ }}, ${VAR}), empty values, and 'changeme' examples from real material.

**False-positive guards.** SealedSecrets (kind: SealedSecret) and SOPS-encrypted manifests (sops metadata present); Helm templates; example manifests with obvious dummies.

**Public examples of the bad pattern** (inspiration for fixtures — do not scrape secrets; recreate sanitized fixtures):
  - https://github.com/bitnami-labs/sealed-secrets — the correct pattern
  - https://github.com/getsops/sops
  - https://kubernetes.io/docs/concepts/configuration/secret/ — explicit warning about committing Secrets

---

## Implementation roadmap (after approval)
1. Prioritize **P0** high-severity / high-confidence static rules first.
2. Add **vulnerable + clean** fixtures per issue (public examples as inspiration only).
3. Wire LLM review to receive static signals as structured evidence (never raw repo dump).
4. Measure precision on a held-out corpus of popular public repos; gate release on FP budget.
5. Document known limitations in adversary description.

**P0 focus:** AWS, GitHub tokens, private keys, Stripe live keys, committed .env, AI provider keys, DB connection strings, k8s Secret manifests.
