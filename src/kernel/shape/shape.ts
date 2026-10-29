/**
 * shape@1 — deterministic output shaping. Frozen contract (ADR 0002 §3):
 * any behavior change requires shape@2 plus new golden fixtures.
 * Order of operations (fixed):
 *   1. binary detection (NUL byte) -> hex preview
 *   2. UTF-8 lossy decode (invalid -> U+FFFD)
 *   3. strip ANSI/OSC escape sequences
 *   4. CRLF / CR -> LF
 *   5. collapse runs of >3 identical consecutive lines (keep 3 + marker)
 *   6. large-output windowing: head 3 MiB + tail 1 MiB with [TRUNCATED] marker
 * Idempotence: shape(shape(x)) === shape(x) must hold for all inputs
 * (docs/design.md §5.4 acceptance).
 */
import { Buffer } from 'node:buffer';

const HEAD_LIMIT = 3 * 1024 * 1024;
const TAIL_LIMIT = 1 * 1024 * 1024;
const HEX_PREVIEW_BYTES = 4096;

export interface ShapeResult {
  shaped: string;
  encoding: 'utf8' | 'hex';
  truncated: boolean;
  bytes: number;
  /** Characters dropped by windowing (0 when not windowed); recorded in meta. */
  omittedChars: number;
}

// CSI: ESC [ params(0x30-0x3F)* intermediates(0x20-0x2F)* final(0x40-0x7E)
// OSC: ESC ] ... terminated by BEL or ESC \
// DCS/PM/APC: ESC P/X/^/_ ... ESC \  ; plus two-char ESC sequences.
const ANSI_RE =
  /\x1B\[[0-9;:<=>?]*[ -/]*[@-~]|\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B[PX^_][\s\S]*?\x1B\\|\x1B[@-Z\\-_]/g;

function stripAnsi(text: string): string {
  return text.replace(ANSI_RE, '');
}

function isBinary(buf: Buffer): boolean {
  // NUL byte in the first 8 KiB is a strong binary signal.
  const probe = buf.subarray(0, 8192);
  return probe.includes(0);
}

function toHexPreview(buf: Buffer): string {
  const slice = buf.subarray(0, HEX_PREVIEW_BYTES);
  const lines: string[] = [];
  for (let off = 0; off < slice.length; off += 32) {
    const chunk = slice.subarray(off, off + 32);
    const hex = chunk.toString('hex').replace(/(..)/g, '$1 ').trim();
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}`);
  }
  const note = buf.length > HEX_PREVIEW_BYTES
    ? `\n[BINARY ${buf.length} bytes; hex preview of first ${HEX_PREVIEW_BYTES} bytes]`
    : `\n[BINARY ${buf.length} bytes; full hex]`;
  return lines.join('\n') + note;
}

/** Collapse runs of >3 identical consecutive lines: keep 3 + count marker. */
export function collapseRepeats(text: string): string {
  const lines = text.split('\n');
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let j = i;
    while (j < lines.length && lines[j] === line) j++;
    const run = j - i;
    if (run > 3) {
      out.push(line, line, line, `[REPEATED ${run - 3} identical line${run - 3 === 1 ? '' : 's'} OMITTED]`);
    } else {
      for (let k = 0; k < run; k++) out.push(line);
    }
    i = j;
  }
  return out.join('\n');
}

/** shape@1 entry point. */
export function shape(raw: Buffer | string): ShapeResult {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
  if (isBinary(buf)) {
    return {
      shaped: toHexPreview(buf),
      encoding: 'hex',
      truncated: buf.length > HEX_PREVIEW_BYTES,
      bytes: buf.length,
      omittedChars: 0,
    };
  }
  // UTF-8 lossy: invalid sequences become U+FFFD.
  let text = buf.toString('utf8');
  text = stripAnsi(text);
  text = text.replace(/\r\n?/g, '\n');
  text = collapseRepeats(text);
  let omittedChars = 0;
  if (text.length > HEAD_LIMIT + TAIL_LIMIT) {
    omittedChars = text.length - HEAD_LIMIT - TAIL_LIMIT;
    const head = text.slice(0, HEAD_LIMIT);
    const tail = text.slice(text.length - TAIL_LIMIT);
    // Fixed marker (no counts) so windowing is idempotent: shape(shape(x)).
    // The omitted size lands in the artifact meta.json instead.
    text = `${head}\n[TRUNCATED]\n${tail}`;
  }
  return { shaped: text, encoding: 'utf8', truncated: omittedChars > 0, bytes: buf.length, omittedChars };
}
