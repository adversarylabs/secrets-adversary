# Secrets adversary

Scans repository text for high-confidence committed credentials and private keys.

## Checks

- **Repository contains a private key block:** Revoke, purge, and replace the key through a secret manager.
- **Repository contains an AWS access key identifier:** Disable and rotate the credential, then use workload identity.
- **Configuration contains a hard-coded credential:** Move the value to a managed secret and rotate it.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the Secrets adversary for any changed repository file because committed credentials can appear anywhere.

## Issue catalog

What this adversary targets (P0 / P1 / LLM-only priorities, detection notes, and public pattern references) is documented in [docs/issue-catalog.md](docs/issue-catalog.md).
