# Initial checks

## secrets.private-key

- Severity: critical
- Category: secrets
- Recommendation: Revoke, purge, and replace the key through a secret manager.

## secrets.aws-key

- Severity: critical
- Category: secrets
- Recommendation: Disable and rotate the credential, then use workload identity.

## secrets.generic-token

- Severity: high
- Category: secrets
- Recommendation: Move the value to a managed secret and rotate it.

