import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "secrets",
  "displayName": "Secrets",
  "description": "Scans repository text for high-confidence committed credentials and private keys.",
  "files": [
    "**/*"
  ],
  "rules": [
    {
      "id": "secrets.aws.access-key-id",
      "title": "AWS access key ID in source",
      "summary": "AWS access key ID in source",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "AWS access key ID in source weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "aws",
        "access-key-id"
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
      "id": "secrets.aws.secret-access-key",
      "title": "AWS secret access key",
      "summary": "AWS secret access key",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "AWS secret access key weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "aws",
        "secret-access-key"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "(aws_secret_access_key|secretAccessKey)\\s*[=:]\\s*['\\\"]?[A-Za-z0-9/+=]{40}",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.github.pat",
      "title": "GitHub personal access token",
      "summary": "GitHub personal access token",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "GitHub personal access token weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "github",
        "pat"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bghp_[A-Za-z0-9]{36}\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.github.fine-grained",
      "title": "GitHub fine-grained PAT",
      "summary": "GitHub fine-grained PAT",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "GitHub fine-grained PAT weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "github",
        "fine-grained"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bgithub_pat_[A-Za-z0-9_]{20,}\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.ssh.private-key",
      "title": "PEM private key material",
      "summary": "PEM private key material",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "PEM private key material weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "ssh",
        "private-key"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.private-key.openssh",
      "title": "OpenSSH private key file",
      "summary": "OpenSSH private key file",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "OpenSSH private key file weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "private-key",
        "openssh"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "-----BEGIN OPENSSH PRIVATE KEY-----",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.stripe.live-key",
      "title": "Stripe live secret key",
      "summary": "Stripe live secret key",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Stripe live secret key weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "stripe",
        "live-key"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bsk_live_[A-Za-z0-9]{20,}\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.dotenv.committed",
      "title": "Committed .env with secrets",
      "summary": "Committed .env with secrets",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Committed .env with secrets weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "dotenv",
        "committed"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\\s*=\\s*\\S+",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.db.connection-string",
      "title": "Database URL with embedded password",
      "summary": "Database URL with embedded password",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Database URL with embedded password weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "db",
        "connection-string"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "(?:postgres|mysql|mongodb(?:\\+srv)?)://[^/\\s:$]+:[^/\\s@${}]{4,}@",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.ai.provider-key",
      "title": "AI provider API keys",
      "summary": "AI provider API keys",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "AI provider API keys weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "ai",
        "provider-key"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\b(?:sk-ant-api03-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,})\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.k8s.secret-manifest",
      "title": "Populated Kubernetes Secret manifests",
      "summary": "Populated Kubernetes Secret manifests",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Populated Kubernetes Secret manifests weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "k8s",
        "secret-manifest"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "kind:\\s*Secret[\\s\\S]{0,200}(?:stringData|data):\\s*\\n\\s+\\w+:\\s*[A-Za-z0-9+/=]{8,}",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.symfony.default-secret",
      "title": "Known Symfony default application secret",
      "summary": "Known Symfony default application secret",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Older Symfony and eZ Platform projects shipped public default signing secrets. Deployments that retain them let attackers forge values protected by the application secret.",
      "impact": "Attackers can use the known signing material to forge trusted application data and, on affected legacy stacks, reach remote code execution.",
      "recommendation": "Replace the default with a freshly generated high-entropy secret supplied outside version control, then invalidate artifacts signed with the old value.",
      "complexity": "small",
      "tags": [
        "secrets",
        "symfony",
        "default-secret"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bThis(?:TokenIsNotSoSecretChangeIt|EzPlatformTokenIsNotSoSecret_PleaseChangeIt)\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.slack.token",
      "title": "Slack API token",
      "summary": "Slack API token",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Slack API token weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "slack",
        "token"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.npm.token",
      "title": "npm automation token",
      "summary": "npm automation token",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "npm automation token weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "npm",
        "token"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "(?:npm_[A-Za-z0-9]{20,}|//registry\\.npmjs\\.org/:_authToken\\s*=\\s*(?!\\$\\{)[A-Za-z0-9._-]+)",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.sendgrid.api-key",
      "title": "SendGrid API key",
      "summary": "SendGrid API key",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "SendGrid API key weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "sendgrid",
        "api-key"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*"
        ],
        "pattern": {
          "pattern": "\\bSG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}\\b",
          "flags": "im"
        },
        "requires": []
      }
    },
    {
      "id": "secrets.aws-key",
      "title": "Repository contains an AWS access key identifier",
      "summary": "AWS access key ID in source",
      "category": "secrets",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "AWS access key ID in source weakens the secrets boundary and can lead to account takeover.",
      "impact": "Exposed credentials can be used to access production systems or exfiltrate data.",
      "recommendation": "Revoke and rotate the credential immediately; store replacements in a secret manager.",
      "complexity": "small",
      "tags": [
        "secrets",
        "aws",
        "access-key-id"
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
    }
  ]
} as const satisfies AdversarySpec;
