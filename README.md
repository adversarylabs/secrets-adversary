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
