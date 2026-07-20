export const spec = {
    "id": "secrets",
    "displayName": "Secrets",
    "description": "Scans repository text for high-confidence committed credentials and private keys.",
    "files": [
        "**/*"
    ],
    "rules": [
        {
            "id": "secrets.private-key",
            "title": "Repository contains a private key block",
            "summary": "Repository contains a private key block",
            "category": "secrets",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Repository contains a private key block weakens an important secrets boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Revoke, purge, and replace the key through a secret manager.",
            "complexity": "small",
            "tags": [
                "secrets",
                "private-key"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*"
                ],
                "pattern": {
                    "pattern": "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "secrets.aws-key",
            "title": "Repository contains an AWS access key identifier",
            "summary": "Repository contains an AWS access key identifier",
            "category": "secrets",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Repository contains an AWS access key identifier weakens an important secrets boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Disable and rotate the credential, then use workload identity.",
            "complexity": "small",
            "tags": [
                "secrets",
                "aws-key"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*"
                ],
                "pattern": {
                    "pattern": "\\bAKIA[0-9A-Z]{16}\\b",
                    "flags": "im"
                },
                "requires": []
            }
        },
        {
            "id": "secrets.generic-token",
            "title": "Configuration contains a hard-coded credential",
            "summary": "Configuration contains a hard-coded credential",
            "category": "secrets",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Configuration contains a hard-coded credential weakens an important secrets boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Move the value to a managed secret and rotate it.",
            "complexity": "small",
            "tags": [
                "secrets",
                "generic-token"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "**/*.env",
                    "**/*.properties",
                    "**/*.yaml",
                    "**/*.yml",
                    "**/*.json"
                ],
                "pattern": {
                    "pattern": "(?:api[_-]?(?:key|token)|access[_-]?token|client[_-]?secret|password)\\s*[:=]\\s*[\"']?[\\w/+.-]{20,}",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
