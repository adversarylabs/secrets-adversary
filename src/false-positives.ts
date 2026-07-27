/**
 * Heuristics for committed-secret false positives: redaction placeholders,
 * AWS documentation examples, low-entropy masks, and explicit "not a real secret"
 * commentary around a match.
 */

// Explicit "this is not live credential material" commentary only — bare
// words like "example" alone are too broad (real secrets in example.env matter).
const FAKE_CONTEXT =
  /\b(?:fake\s+(?:secret|key|credential|token)|placeholder|dummy\s+(?:secret|key|credential|token|value)?|redact(?:ed|ion)?|saniti[sz]e|mask(?:ed|ing)?|not\s+(?:a\s+)?real|test\s+secret|for\s+testing\s+only|do\s+not\s+use|not\s+(?:a\s+)?live\s+(?:secret|key|credential))\b/i;

/** Classic AWS docs / tool samples that are not live credentials. */
const KNOWN_FAKE_AWS_KEYS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "AKIAXXXXXXXXXXXXXXXX",
  "AKIA0000000000000000",
  "AKIATESTTESTTESTTEST",
  "AKIAAAAAAAAAAAAAAAAA",
]);

/**
 * Returns true when the match should not be reported as a real secret.
 * `match` is the regex capture (or full match). `line` is the source line.
 * `nearby` is optional surrounding text (previous/next lines).
 */
export function isLikelyFalsePositiveSecret(match: string, line: string, nearby = ""): boolean {
  const value = match.trim();
  if (value === "") return true;

  if (isAwsAccessKeyId(value)) {
    if (KNOWN_FAKE_AWS_KEYS.has(value.toUpperCase())) return true;
    if (isPlaceholderLikeToken(value.slice(4))) return true;
  } else if (isPlaceholderLikeToken(value)) {
    return true;
  }

  const context = `${line}\n${nearby}`;
  if (FAKE_CONTEXT.test(context)) return true;

  // Redaction / replacement assignments that only emit a mask.
  if (isRedactionReturnLine(line, value)) return true;

  return false;
}

function isAwsAccessKeyId(value: string): boolean {
  return /^AKIA[0-9A-Z]{16}$/i.test(value);
}

/**
 * Low-entropy masks: all identical chars, mostly X/0, or long runs of the same
 * character. Real cloud keys and tokens are high-entropy alphanumeric.
 */
export function isPlaceholderLikeToken(value: string): boolean {
  const body = value.replace(/[^0-9A-Za-z]/g, "");
  if (body.length < 8) return false;

  const upper = body.toUpperCase();
  const unique = new Set(upper).size;
  if (unique <= 2) return true;

  const placeholder = (upper.match(/[X0]/g) ?? []).length;
  if (placeholder / upper.length >= 0.7) return true;

  // Long run of the same character (XXXXXXXX, 00000000, AAAAAAAA).
  if (/(.)\1{7,}/i.test(upper)) return true;

  // Explicit placeholder words embedded in the token body.
  if (/(?:EXAMPLE|SAMPLE|TESTKEY|FAKEKEY|PLACEHOLDER|REDACTED|YOURKEYHERE)/i.test(upper)) return true;

  return false;
}

function isRedactionReturnLine(line: string, match: string): boolean {
  // e.g. return "AKIAXXXXXXXXXXXXXXXX" or => 'AKIA...'
  const quoted = match.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(
    `(?:return|=>|=)\\s*["'\`]${quoted}["'\`]`,
    "i",
  );
  return re.test(line);
}
