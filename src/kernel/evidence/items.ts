/**
 * evidence/1 parser. Items are child evidence of one ProcessOutcome; they are
 * script-declared unless a future kernel-probe mode sets provenance=kernel.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import { shape } from '../shape/shape.js';
import type { EvidenceItem, ItemIndex, StreamInfo } from '../types.js';

export const EVIDENCE_PROTOCOL = 'evidence/1' as const;
export const MAX_ITEMS = 16;
export const MAX_ITEM_BYTES = 256 * 1024;
export const MAX_TOTAL_ITEM_BYTES = 4 * 1024 * 1024;
export const MAX_LINE_BYTES = 512 * 1024;
export const MAX_SCANNED_BYTES = 16 * 1024 * 1024;
const EXCERPT_CHARS = 256;

export interface ItemSummary {
  id: string;
  label: string;
  kind: 'http' | 'binary' | 'text' | 'unknown';
  bytes: number;
  excerpt: string;
}

export interface ParsedItems {
  index: ItemIndex;
  items: EvidenceItem[];
  summaries: ItemSummary[];
}

interface RawItem {
  index: number;
  label: string;
  declaredKind: string;
  kind: 'http' | 'binary' | 'text' | 'unknown';
  status: string | number | boolean | null;
  encoding: 'utf8' | 'base64';
  stdout: Buffer;
  stderr: Buffer;
  meta: Record<string, string | number | boolean | null>;
  truncated: boolean;
}

function asScalar(v: unknown): string | number | boolean | null {
  if (v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return v;
  return null;
}

function safeLabel(v: unknown): string {
  return String(v ?? '').replace(/[^\x20-\x7E]/g, '?').slice(0, 64);
}

function safeKind(v: unknown): string {
  return String(v ?? '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
}

function safeMeta(v: unknown): Record<string, string | number | boolean | null> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return {};
  const out: Record<string, string | number | boolean | null> = {};
  let n = 0;
  for (const [key, value] of Object.entries(v as Record<string, unknown>)) {
    if (n >= 32) break;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (Array.isArray(value)) {
      if (value.length > 16) continue;
      const scalar = value.map(asScalar);
      if (scalar.some((x) => x === null && !value.includes(null))) continue;
      out[key] = scalar.join(',');
    } else {
      const scalar = asScalar(value);
      if (scalar === null && value !== null) continue;
      out[key] = scalar;
    }
    n++;
  }
  return out;
}

function decodeBody(obj: Record<string, unknown>, which: 'stdout' | 'stderr'): { buf: Buffer; encoding: 'utf8' | 'base64' } | { error: string } {
  const text = obj[which];
  const b64 = obj[`${which}_b64`];
  if (text !== undefined && b64 !== undefined) return { error: `${which} and ${which}_b64 are mutually exclusive` };
  if (b64 !== undefined) {
    if (typeof b64 !== 'string' || b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return { error: `invalid ${which}_b64` };
    return { buf: Buffer.from(b64, 'base64'), encoding: 'base64' };
  }
  if (text !== undefined && typeof text !== 'string') return { error: `${which} must be a string` };
  return { buf: Buffer.from(typeof text === 'string' ? text : '', 'utf8'), encoding: 'utf8' };
}

function emptyStream(base: string): { info: StreamInfo; shaped: string } {
  const info: StreamInfo = {
    sha256: sha256(Buffer.alloc(0)),
    bytes: 0,
    rawRef: `${base}.raw.log`,
    shapedRef: `${base}.shaped.log`,
    excerpt: '',
    encoding: 'utf8',
    truncated: false,
    outputTruncated: false,
  };
  return { info, shaped: '' };
}

function writeItemArtifacts(
  project: Project,
  parentId: string,
  raw: RawItem,
): { item: EvidenceItem; summary: ItemSummary } {
  const stem = `${parentId}.item-${String(raw.index).padStart(4, '0')}`;
  const base = `artifacts/${stem}`;
  const stdoutRaw = `${base}.stdout.raw.log`;
  const stdoutShaped = `${base}.stdout.shaped.log`;
  const stdoutInfo = shape(raw.stdout);
  atomicWriteFile(path.join(project.ctfDir, stdoutRaw), raw.stdout);
  atomicWriteFile(path.join(project.ctfDir, stdoutShaped), stdoutInfo.shaped);
  atomicWriteFile(path.join(project.ctfDir, `${base}.stdout.meta.json`), JSON.stringify({
    bytes: raw.stdout.length,
    shapedBytes: Buffer.byteLength(stdoutInfo.shaped),
    encoding: stdoutInfo.encoding,
    truncated: stdoutInfo.truncated,
    sha256: sha256(raw.stdout),
  }, null, 2));

  let stderrRaw: string;
  let stderrShaped: string;
  let stderrInfo: StreamInfo;
  if (raw.stderr.length > 0) {
    const s = shape(raw.stderr);
    stderrRaw = `${base}.stderr.raw.log`;
    stderrShaped = `${base}.stderr.shaped.log`;
    atomicWriteFile(path.join(project.ctfDir, stderrRaw), raw.stderr);
    atomicWriteFile(path.join(project.ctfDir, stderrShaped), s.shaped);
    stderrInfo = {
      sha256: sha256(raw.stderr),
      bytes: raw.stderr.length,
      rawRef: stderrRaw,
      shapedRef: stderrShaped,
      excerpt: s.shaped.slice(0, EXCERPT_CHARS),
      encoding: s.encoding,
      truncated: s.truncated,
      outputTruncated: false,
    };
  } else {
    const empty = emptyStream(`${base}.stderr`);
    stderrRaw = empty.info.rawRef;
    stderrShaped = empty.info.shapedRef;
    atomicWriteFile(path.join(project.ctfDir, stderrRaw), Buffer.alloc(0));
    atomicWriteFile(path.join(project.ctfDir, stderrShaped), '');
    stderrInfo = empty.info;
  }

  const item: EvidenceItem = {
    id: `${parentId}.${String(raw.index).padStart(4, '0')}`,
    parentOutcomeId: parentId,
    index: raw.index,
    label: raw.label,
    provenance: 'script-declared',
    declaredKind: raw.declaredKind,
    kind: raw.kind,
    status: raw.status,
    encoding: raw.encoding,
    stdout: {
      sha256: sha256(raw.stdout),
      bytes: raw.stdout.length,
      rawRef: stdoutRaw,
      shapedRef: stdoutShaped,
      excerpt: stdoutInfo.shaped.slice(0, EXCERPT_CHARS),
      encoding: stdoutInfo.encoding,
      truncated: stdoutInfo.truncated,
      outputTruncated: false,
    },
    stderr: stderrInfo,
    meta: raw.meta,
    semanticFailure: null,
    truncated: raw.truncated || stdoutInfo.truncated,
  };
  atomicWriteFile(path.join(project.ctfDir, `items/${item.id}.json`), JSON.stringify(item, null, 2));
  return {
    item,
    summary: {
      id: item.id,
      label: item.label,
      kind: item.kind,
      bytes: item.stdout.bytes,
      excerpt: item.stdout.excerpt.slice(0, 256),
    },
  };
}

export function parseEvidenceItems(
  project: Project,
  parentId: string,
  rawStdout: Buffer,
  opts: { timedOut: boolean; outputTruncated: boolean },
): ParsedItems | null {
  const decoded = rawStdout.toString('utf8').replace(/^\uFEFF/, '');
  // Fast path: no exact protocol line at all -> legacy single artifact.
  if (!decoded.split('\n').some((line) => /"pi4ctf"\s*:\s*"evidence\/1"/.test(line))) return null;

  let planned: number | null = null;
  let ended = false;
  let protocolError: string | null = null;
  let truncated = Boolean(opts.timedOut || opts.outputTruncated);
  let scanned = 0;
  let emitted = 0;
  let totalBody = 0;
  const raws: RawItem[] = [];
  const lines = decoded.split('\n');

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    scanned += Buffer.byteLength(line) + 1;
    if (scanned > MAX_SCANNED_BYTES) {
      truncated = true;
      protocolError = protocolError ?? 'scanned bytes exceeded';
      break;
    }
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
      truncated = true;
      protocolError = protocolError ?? 'line bytes exceeded';
      continue;
    }
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue; // noise
    }
    if (!obj || obj.pi4ctf !== EVIDENCE_PROTOCOL) continue;
    const type = obj.type;
    if (type === 'begin') {
      if (planned !== null || raws.length > 0) {
        protocolError = protocolError ?? 'duplicate begin';
        continue;
      }
      const n = Number(obj.count);
      planned = Number.isInteger(n) && n >= 0 ? n : null;
      continue;
    }
    if (type === 'end') {
      if (ended) {
        protocolError = protocolError ?? 'duplicate end';
        continue;
      }
      const n = Number(obj.count);
      if (planned !== null && Number.isInteger(n) && n !== raws.length) {
        truncated = true;
        protocolError = protocolError ?? 'end count mismatch';
      }
      ended = true;
      continue;
    }
    if (type === 'bail') {
      protocolError = `bail: ${safeLabel(obj.reason)}`;
      ended = true;
      continue;
    }
    if (type !== 'item') {
      protocolError = protocolError ?? `unknown record type ${String(type)}`;
      continue;
    }
    emitted++;
    if (ended) {
      protocolError = protocolError ?? 'item after end';
      continue;
    }
    if (raws.length >= MAX_ITEMS) {
      truncated = true;
      protocolError = protocolError ?? 'item cap';
      continue;
    }
    if (planned !== null && raws.length >= planned) {
      truncated = true;
      protocolError = protocolError ?? 'item beyond planned count';
      continue;
    }
    const stdout = decodeBody(obj, 'stdout');
    if ('error' in stdout) {
      protocolError = protocolError ?? stdout.error;
      continue;
    }
    const stderr = decodeBody(obj, 'stderr');
    if ('error' in stderr) {
      protocolError = protocolError ?? stderr.error;
      continue;
    }
    totalBody += stdout.buf.length + stderr.buf.length;
    if (totalBody > MAX_TOTAL_ITEM_BYTES) {
      truncated = true;
      protocolError = protocolError ?? 'total item bytes exceeded';
      break;
    }
    let itemTruncated = false;
    if (stdout.buf.length > MAX_ITEM_BYTES || stderr.buf.length > MAX_ITEM_BYTES) {
      itemTruncated = true;
      truncated = true;
    }
    const encoding = stdout.encoding;
    raws.push({
      index: raws.length + 1,
      label: safeLabel(obj.label),
      declaredKind: safeKind(obj.kind),
      kind: encoding === 'base64' ? 'binary' : 'text',
      status: asScalar(obj.status),
      encoding,
      stdout: stdout.buf.subarray(0, MAX_ITEM_BYTES),
      stderr: stderr.buf.subarray(0, MAX_ITEM_BYTES),
      meta: safeMeta(obj.meta),
      truncated: itemTruncated,
    });
  }

  if (planned !== null && !ended) {
    truncated = true;
    protocolError = protocolError ?? 'missing end';
  }
  if (planned !== null && raws.length !== planned) {
    truncated = true;
  }
  // We do not return "no items" for a malformed header; parent still exists.
  fs.mkdirSync(path.join(project.ctfDir, 'items'), { recursive: true });
  const items: EvidenceItem[] = [];
  const summaries: ItemSummary[] = [];
  for (const raw of raws) {
    const written = writeItemArtifacts(project, parentId, raw);
    items.push(written.item);
    summaries.push(written.summary);
  }
  return {
    index: {
      protocol: EVIDENCE_PROTOCOL,
      provenance: 'script-declared',
      planned,
      parsed: raws.length,
      emitted,
      truncated,
      protocolError,
      ids: items.map((item) => item.id),
    },
    items,
    summaries,
  };
}
