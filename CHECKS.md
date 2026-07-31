# Checks — what security/secrets detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).
Regression entry: [`test/`](test/) including false-positive cases.

**Scope:** repository text files (binary and well-known generated paths filtered).

---

## Critical

### `secrets.aws.access-key-id`

| | |
| --- | --- |
| **What** | AWS access key ID in source |
| **Why** | Account takeover / data exfil |
| **Looks for** | `AKIA[0-9A-Z]{16}` shapes |
| **Stays quiet when** | Examples/placeholders only |
| **Remediation** | Disable key; rotate; use IAM roles / workload identity |

### `secrets.aws.secret-access-key`

| | |
| --- | --- |
| **What** | AWS secret access key |
| **Why** | Pairs with access key ID for full API access |
| **Looks for** | aws_secret_access_key / secretAccessKey assignments |
| **Stays quiet when** | No raw secret material |
| **Remediation** | Rotate immediately; secret manager only |

### `secrets.github.pat`

| | |
| --- | --- |
| **What** | GitHub classic personal access token |
| **Why** | Repo and org access with user privileges |
| **Looks for** | `ghp_` tokens |
| **Stays quiet when** | Revoked/example tokens |
| **Remediation** | Revoke in GitHub; prefer fine-grained or apps |

### `secrets.github.fine-grained`

| | |
| --- | --- |
| **What** | GitHub fine-grained PAT |
| **Why** | Scoped but still privileged git access |
| **Looks for** | github_pat_… shapes |
| **Stays quiet when** | Examples only |
| **Remediation** | Revoke and reissue from GitHub settings |

### `secrets.ssh.private-key`

| | |
| --- | --- |
| **What** | SSH private key block |
| **Why** | Host and git auth material |
| **Looks for** | BEGIN OPENSSH/RSA/EC PRIVATE KEY blocks |
| **Stays quiet when** | Public keys only; keys outside repo |
| **Remediation** | Revoke key; generate new; never commit private keys |

### `secrets.private-key.openssh`

| | |
| --- | --- |
| **What** | OpenSSH private key material |
| **Why** | Same class as SSH private keys |
| **Looks for** | OpenSSH private key armor |
| **Stays quiet when** | Public keys / certificates only |
| **Remediation** | Rotate and remove from history if pushed |

### `secrets.stripe.live-key`

| | |
| --- | --- |
| **What** | Stripe live secret key |
| **Why** | Payment API access |
| **Looks for** | `sk_live_` keys |
| **Stays quiet when** | test keys in non-prod with care; never live in git |
| **Remediation** | Roll key in Stripe dashboard |

### `secrets.slack.token`

| | |
| --- | --- |
| **What** | Slack token |
| **Why** | Workspace API access |
| **Looks for** | xox*-shaped tokens |
| **Stays quiet when** | Placeholders |
| **Remediation** | Revoke in Slack; use env injection |

### `secrets.sendgrid.api-key`

| | |
| --- | --- |
| **What** | SendGrid API key |
| **Why** | Email send abuse |
| **Looks for** | SG. API key shapes |
| **Stays quiet when** | Examples |
| **Remediation** | Rotate in SendGrid |

### `secrets.npm.token`

| | |
| --- | --- |
| **What** | npm access token |
| **Why** | Package publish / download abuse |
| **Looks for** | npm_ tokens |
| **Stays quiet when** | CI secrets store |
| **Remediation** | Revoke on npmjs.com |

### `secrets.ai.provider-key`

| | |
| --- | --- |
| **What** | AI provider API key |
| **Why** | Billable model API access |
| **Looks for** | Provider-specific live key shapes |
| **Stays quiet when** | Placeholders |
| **Remediation** | Rotate at the provider |

### `secrets.db.connection-string`

| | |
| --- | --- |
| **What** | Database connection string with credentials |
| **Why** | Direct DB access |
| **Looks for** | URL DSNs with embedded passwords |
| **Stays quiet when** | Passwordless local sockets / secret managers |
| **Remediation** | Move credentials to a secret store |

## High

### `secrets.dotenv.committed`

| | |
| --- | --- |
| **What** | Committed dotenv with real secret material |
| **Why** | Env files often hold production secrets |
| **Looks for** | .env* with high-entropy assignments |
| **Stays quiet when** | Example `.env.example` without real secrets |
| **Remediation** | Untrack; rotate; use secret manager |

### `secrets.k8s.secret-manifest`

| | |
| --- | --- |
| **What** | Kubernetes Secret manifest with data |
| **Why** | Base64 is not encryption |
| **Looks for** | Secret manifests containing data/stringData |
| **Stays quiet when** | External secrets / sealed secrets |
| **Remediation** | Do not commit raw Secret data |
