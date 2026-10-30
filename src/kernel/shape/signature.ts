/**
 * signature@1 — argv normalization with <v:n> payload slots (ADR 0002 §3).
 * Frozen contract; changes require signature@2 + new fixtures.
 *
 * v1 spec (deterministic):
 *   - argv[0] stays literal (program).
 *   - tokens starting with "-" stay literal (flags/switches).
 *   - a value token stays literal iff it is "simple": matches
 *     /^[A-Za-z0-9_@:.+~-]{1,24}$/ and contains no "=" payload longer than
 *     16 chars (key=short-value is literal; key=long-value is payload).
 *   - URLs keep scheme://host[:port]/[first path segment] literal; the rest
 *     of the URL (query, long paths) becomes a payload slot.
 *   - every other value token becomes <v:n>; slots are numbered in order of
 *     first appearance; the same value always maps to the same slot number
 *     (dedupe by value).
 */
import * as crypto from 'node:crypto';

const URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#\s]+(?:\/[A-Za-z0-9_.-]{0,24})?)([/?#].*)?$/;
// Simple charset includes '=' so key=short-value stays literal (spec §v1);
// key=long-value is demoted to payload by the length check below.
const SIMPLE_RE = /^[A-Za-z0-9_@:.+~=-]{1,24}$/;

function isSimpleToken(token: string): boolean {
  if (!SIMPLE_RE.test(token)) return false;
  const eq = token.indexOf('=');
  if (eq >= 0) {
    const value = token.slice(eq + 1);
    if (value.length > 16) return false;
  }
  return true;
}

export interface SignatureResult {
  /** argv with payload slots applied, e.g. ["curl","-s","http://host/<v:1>"] */
  argvTemplate: string[];
  /** space-joined template, e.g. "curl -s http://host/<v:1>" */
  signature: string;
  /** number of distinct payload slots */
  slots: number;
}

/** Canonical key for the negative ledger. */
export function routeSignature(intentClass: string, signatureText: string): string {
  return `${intentClass}|signature@1:${signatureText}`;
}

export function signature(argv: string[]): SignatureResult {
  const slotByValue = new Map<string, number>();
  let nextSlot = 0;
  const template: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (i === 0 || token.startsWith('-')) {
      template.push(token);
      continue;
    }
    const urlMatch = URL_RE.exec(token);
    if (urlMatch) {
      const stable = urlMatch[1];
      const rest = urlMatch[2] ?? '';
      if (rest === '') {
        template.push(stable);
      } else {
        const slot = slotFor(slotByValue, rest, () => nextSlot++);
        template.push(`${stable}${renderSlot(slot)}`);
      }
      continue;
    }
    if (isSimpleToken(token)) {
      template.push(token);
      continue;
    }
    const slot = slotFor(slotByValue, token, () => nextSlot++);
    template.push(renderSlot(slot));
  }
  return { argvTemplate: template, signature: template.join(' '), slots: nextSlot };
}

function slotFor(map: Map<string, number>, value: string, alloc: () => number): number {
  let slot = map.get(value);
  if (slot === undefined) {
    slot = alloc();
    map.set(value, slot);
  }
  return slot;
}

function renderSlot(slot: number): string {
  return `<v:${slot + 1}>`;
}

/** canonicalKey = intentClass | signature@1 | shaped hash (docs/design.md §4.1) */
export function canonicalKey(intentClass: string, sig: string, shapedSha256: string): string {
  return `${intentClass}|signature@1:${sig}|shaped:sha256:${shapedSha256}`;
}

export function stableHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}
