/**
 * Stream shaping and artifact writes for execution results.
 *
 * Owns the raw/shaped/meta artifact layout and capture-level flags. Process
 * spawning lives in ./process.ts; classification stays in exec.
 */
import { Buffer } from 'node:buffer';
import * as path from 'node:path';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { shape } from '../shape/shape.js';
import type { Project } from '../project.js';
import type { StreamInfo } from '../types.js';

const EXCERPT_CHARS = 1536;

export function streamInfo(
  id: string,
  which: 'stdout' | 'stderr',
  raw: Buffer,
  rawTruncated: boolean,
  project: Project,
): { info: StreamInfo; shaped: string } {
  const shapedResult = shape(raw);
  const base = `artifacts/${id}.${which}`;
  const rawRef = `${base}.raw.log`;
  const shapedRef = `${base}.shaped.log`;
  atomicWriteFile(path.join(project.ctfDir, rawRef), raw);
  atomicWriteFile(path.join(project.ctfDir, shapedRef), shapedResult.shaped);
  atomicWriteFile(path.join(project.ctfDir, `${base}.meta.json`), JSON.stringify({
    bytes: raw.length,
    shapedBytes: Buffer.byteLength(shapedResult.shaped),
    lines: shapedResult.shaped.split('\n').length - 1,
    sha256: sha256(raw),
    encoding: shapedResult.encoding,
    truncated: shapedResult.truncated,
    omittedChars: shapedResult.omittedChars,
    // capture-level cap hit (distinct from shape windowing) — review R4
    outputTruncated: rawTruncated,
  }, null, 2));
  return {
    info: {
      sha256: sha256(raw),
      bytes: raw.length,
      rawRef,
      shapedRef,
      excerpt: shapedResult.shaped.slice(0, EXCERPT_CHARS),
      encoding: shapedResult.encoding,
      truncated: shapedResult.truncated,
      outputTruncated: rawTruncated,
    },
    shaped: shapedResult.shaped,
  };
}

/** A filter stage makes empty stdout a legitimate result (`grep` no match),
 *  not a broken probe. Only command-mode shell pipelines need this. */
export function hasFilterStage(command: string | undefined): boolean {
  return !!command && /\|\s*(?:grep|egrep|fgrep|rg|sed|awk|head|tail|jq|cut|sort|uniq|wc|tr)\b/.test(command);
}

/** WSL's bash.exe prints a UTF-16 localhost-proxy warning to stderr before the
 *  command runs. It is host noise, not challenge evidence. */
export function stripHostNoise(buf: Buffer): Buffer {
  if (buf.length === 0) return buf;
  const text = buf.toString('utf16le');
  if (!/^wsl:/im.test(text)) return buf;
  return Buffer.from(
    text
      .split(/\r?\n/)
      .filter((line) => !/^wsl:/i.test(line))
      .join('\n'),
    'utf16le',
  );
}

export function safeProbeLabel(value: string | undefined): string {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '?').slice(0, 64);
}

export function emptyStream(id: string, which: 'stdout' | 'stderr', project: Project): StreamInfo {
  const base = `artifacts/${id}.${which}`;
  const rawRef = `${base}.raw.log`;
  const shapedRef = `${base}.shaped.log`;
  atomicWriteFile(path.join(project.ctfDir, rawRef), Buffer.alloc(0));
  atomicWriteFile(path.join(project.ctfDir, shapedRef), '');
  return {
    sha256: sha256(Buffer.alloc(0)),
    bytes: 0,
    rawRef,
    shapedRef,
    excerpt: '',
    encoding: 'utf8',
    truncated: false,
    outputTruncated: false,
  };
}
