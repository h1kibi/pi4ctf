/**
 * Secret redaction for free-form environment notes.
 *
 * Notes live in a user-level store that outlives a case and is injected into
 * the prompt, so credentials and flags must not reach it. Redaction is
 * deliberately conservative: it targets unambiguous shapes and leaves version
 * strings, paths and hashes alone.
 */
const PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    '[redacted-private-key]',
  ],
  // CTF flag shape: any common prefix followed by a braced body.
  [/[A-Za-z][A-Za-z0-9_-]{0,31}\{[^}\r\n]{1,512}\}/g, '[redacted-flag]'],
  // Named secrets keep the key so the note still says what was removed.
  [
    /\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|authorization)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/gi,
    '$1=[redacted]',
  ],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/g, 'Bearer [redacted]'],
  [/\b(?:sk|rk)-[A-Za-z0-9_-]{16,}/g, '[redacted-token]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, '[redacted-token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, '[redacted-token]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[redacted-token]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, '[redacted-token]'],
];

export interface RedactionResult {
  text: string;
  redacted: boolean;
}

export function redactSecrets(text: string): RedactionResult {
  let out = text;
  for (const [pattern, replacement] of PATTERNS) out = out.replace(pattern, replacement);
  return { text: out, redacted: out !== text };
}
