import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "secrets";
    readonly displayName: "Secrets";
    readonly description: "Scans repository text for high-confidence committed credentials and private keys.";
    readonly files: ["**/*"];
    readonly rules: [{
        readonly id: "secrets.private-key";
        readonly title: "Repository contains a private key block";
        readonly summary: "Repository contains a private key block";
        readonly category: "secrets";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Repository contains a private key block weakens an important secrets boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Revoke, purge, and replace the key through a secret manager.";
        readonly complexity: "small";
        readonly tags: ["secrets", "private-key"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*"];
            readonly pattern: {
                readonly pattern: "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "secrets.aws-key";
        readonly title: "Repository contains an AWS access key identifier";
        readonly summary: "Repository contains an AWS access key identifier";
        readonly category: "secrets";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Repository contains an AWS access key identifier weakens an important secrets boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Disable and rotate the credential, then use workload identity.";
        readonly complexity: "small";
        readonly tags: ["secrets", "aws-key"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*"];
            readonly pattern: {
                readonly pattern: "\\bAKIA[0-9A-Z]{16}\\b";
                readonly flags: "im";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "secrets.generic-token";
        readonly title: "Configuration contains a hard-coded credential";
        readonly summary: "Configuration contains a hard-coded credential";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Configuration contains a hard-coded credential weakens an important secrets boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Move the value to a managed secret and rotate it.";
        readonly complexity: "small";
        readonly tags: ["secrets", "generic-token"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.env", "**/*.properties", "**/*.yaml", "**/*.yml", "**/*.json"];
            readonly pattern: {
                readonly pattern: "(?:api[_-]?(?:key|token)|access[_-]?token|client[_-]?secret|password)\\s*[:=]\\s*[\"']?[\\w/+.-]{20,}";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
