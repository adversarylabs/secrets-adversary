# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `secrets.ai.provider-key` | Critical | AI provider API key |
| `secrets.aws-key` | Critical | Repository contains an AWS access key identifier |
| `secrets.aws.access-key-id` | Critical | AWS access key ID in source |
| `secrets.aws.secret-access-key` | Critical | AWS secret access key |
| `secrets.db.connection-string` | Critical | Database connection string with credentials |
| `secrets.dotenv.committed` | High | Committed dotenv with real secret material |
| `secrets.github.fine-grained` | Critical | GitHub fine-grained PAT |
| `secrets.github.pat` | Critical | GitHub classic personal access token |
| `secrets.k8s.secret-manifest` | High | Kubernetes Secret manifest with data |
| `secrets.npm.token` | Critical | npm access token |
| `secrets.private-key.openssh` | Critical | OpenSSH private key material |
| `secrets.query-credential-http-error` | Medium | Python Requests code puts a credential-bearing value in `params=` and lets `raise_for_status()` expose the prepared URL through an escaping HTTP error |
| `secrets.sendgrid.api-key` | Critical | SendGrid API key |
| `secrets.slack.token` | Critical | Slack token |
| `secrets.ssh.private-key` | Critical | SSH private key block |
| `secrets.stripe.live-key` | Critical | Stripe live secret key |
| `secrets.symfony.default-secret` | High | Known Symfony or eZ Platform default application secret |
