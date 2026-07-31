# security/secrets

**security/secrets** scans repository text for **high-confidence committed credentials and private keys**: AWS keys, GitHub PATs, cloud provider tokens, private key blocks, Stripe live keys, and similar material that should never land in git.

It is a **secrets scanner**, not a general security review. It prefers silence on placeholders, examples, and false-positive-prone shapes. When it reports, rotate immediately.

## What it does

1. **Scans** repository files with high-precision patterns (with false-positive filters).
2. **Emits stable rule ids** with file:line evidence and credential class labels.
3. **Synthesizes a review** focused on revoke/rotate guidance.
4. Optionally **enhances** with a model when provided — prioritization only, not freestyle secret invention.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Cloud | AWS access key IDs and secret access keys |
| Git forges | GitHub classic and fine-grained PATs |
| Keys | OpenSSH / PEM private key blocks |
| SaaS | Stripe live keys, Slack tokens, SendGrid, npm tokens |
| Config | DB connection strings; committed dotenv with real secrets; K8s Secret manifests with data |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Secret *logging* / argv / URL patterns in Go source | [`go/security`](https://github.com/adversarylabs/go-security-adversary) |
| Dockerfile ARG/ENV secret material | [`container/dockerfile`](https://github.com/adversarylabs/dockerfile-adversary) |
| CI secret scope and script injection | [`ci/github-actions`](https://github.com/adversarylabs/githubactions-adversary) |

## Precision stance

- **High confidence** pattern matches only; known false-positive shapes are filtered.
- Placeholders like `YOUR_API_KEY` / `xxx` should stay quiet.
- Any true positive should trigger credential rotation, not a style debate.
