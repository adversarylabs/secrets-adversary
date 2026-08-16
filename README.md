# Secrets adversary

Scans repository text for committed credentials and narrow credential exposure paths.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates repository text and narrow code paths for committed credentials, private keys, tokens, connection strings, secret manifests, and credential exposure through errors.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It stays within this domain, does not execute target code, and leaves unrelated concerns to the corresponding specialist adversaries.
