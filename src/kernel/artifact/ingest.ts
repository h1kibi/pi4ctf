/**
 * Ingest an external file as a first-class artifact + synthetic outcome.
 *
 * Why: webhook captures, browser downloads, and other tools write evidence
 * outside the challenge workspace. claim quotes and flag provenance only read
 * `.ctf/artifacts`, so without an explicit ingest those bytes cannot enter the
 * evidence chain. This copies the file into the case and records the same
 * outcome/observation shape as a real run.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { KernelError } from '../error.js';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import { classify } from '../classify/classify.js';
import { shape } from '../shape/shape.js';
import type { ProcessOutcome, StreamInfo, TargetSpec } from '../types.js';
import { targetRef } from '../target.js';
import { assertIngestSource } from './source.js';

const MAX_INGEST_BYTES = 64 * 1024 * 1024;
const EXCERPT_CHARS = 1536;

export interface IngestInput {
  path: string;
  name?: string;
  target?: TargetSpec | null;
  synthetic?: boolean;
  transform?: 'hex' | 'base64';
}

export interface IngestResult {
  id: string;
  artifact: string;
  raw: string;
  bytes: number;
  sourceSha256: string;
  transform?: string;
}

function decodeTransform(raw: Buffer, transform: 'hex' | 'base64'): Buffer {
  const text = raw.toString('utf8').trim();
  if (transform === 'hex') {
    if (text.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(text)) {
      throw new KernelError('INVALID_REQUEST', 'artifact transform=hex requires an even-length hex file');
    }
    return Buffer.from(text, 'hex');
  }
  if (!/^[A-Za-z0-9+/=\s]+$/.test(text)) {
    throw new KernelError('INVALID_REQUEST', 'artifact transform=base64 requires a base64 file');
  }
  return Buffer.from(text, 'base64');
}

function safeName(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
  return cleaned.length > 0 ? cleaned : `ingest-${randomUUID()}`;
}

function emptyStream(id: string, which: string, project: Project): StreamInfo {
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

export function ingestArtifact(project: Project, input: IngestInput): IngestResult {
  const src = assertIngestSource(project, input.path);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(src);
  } catch {
    throw new KernelError('NOT_FOUND', `artifact source not found: ${input.path}`);
  }
  if (!stat.isFile()) throw new KernelError('INVALID_REQUEST', `artifact source is not a file: ${input.path}`);
  if (stat.size > MAX_INGEST_BYTES) {
    throw new KernelError('LIMIT', `artifact source exceeds ${MAX_INGEST_BYTES} bytes: ${input.path}`);
  }
  const source = fs.readFileSync(src);
  const raw = input.transform ? decodeTransform(source, input.transform) : source;
  const sourceSha256 = sha256(source);
  const { id } = project.reserveCommand();
  const stem = safeName(input.name ?? `ingest-${randomUUID()}`);
  const base = `artifacts/${id}-${stem}`;
  const rawRef = `${base}.raw.log`;
  const shapedRef = `${base}.shaped.log`;
  atomicWriteFile(path.join(project.ctfDir, rawRef), raw);
  const shaped = shape(raw);
  atomicWriteFile(path.join(project.ctfDir, shapedRef), shaped.shaped);
  atomicWriteFile(
    path.join(project.ctfDir, `${base}.meta.json`),
    JSON.stringify({
      source: src,
      sourceSha256,
      transform: input.transform ?? null,
      bytes: raw.length,
      shapedBytes: Buffer.byteLength(shaped.shaped),
      encoding: shaped.encoding,
      truncated: shaped.truncated,
      omittedChars: shaped.omittedChars,
      sha256: sha256(raw),
    }, null, 2),
  );
  const stdout: StreamInfo = {
    sha256: sha256(raw),
    bytes: raw.length,
    rawRef,
    shapedRef,
    excerpt: shaped.shaped.slice(0, EXCERPT_CHARS),
    encoding: shaped.encoding,
    truncated: shaped.truncated,
    outputTruncated: false,
  };
  const stderr = emptyStream(id, 'stderr', project);
  const target = input.target === undefined ? (project.file().target ?? null) : input.target;
  const outcome: ProcessOutcome = {
    id,
    argvTemplate: ['artifact.ingest', input.path, ...(input.transform ? [input.transform] : [])],
    argvRaw: ['artifact.ingest', input.path, ...(input.transform ? [input.transform] : [])],
    target: targetRef(target),
    instanceId: target?.instanceId ?? null,
    synthetic: input.synthetic === true,
    intentClass: 'ingest',
    canonicalKey: `ingest|artifact.ingest|${stdout.sha256}`,
    ...(input.transform ? { derivedFrom: { sha256: sourceSha256, transform: input.transform } } : {}),
    exit: 0,
    signal: null,
    durationMs: 0,
    shell: null,
    stdout,
    stderr,
    processFailure: null,
    ts: Date.now(),
  };
  atomicWriteFile(path.join(project.ctfDir, `outcomes/${id}.json`), JSON.stringify(outcome, null, 2));
  const observation = classify(outcome, shaped.shaped);
  atomicWriteFile(
    path.join(project.ctfDir, `observations/${id}.json`),
    JSON.stringify(observation, null, 2),
  );
  project.appendEvent('artifact.ingest', 'model', {
    id,
    source: src,
    artifact: shapedRef,
    bytes: raw.length,
  });
  return { id, artifact: shapedRef, raw: rawRef, bytes: raw.length, sourceSha256, ...(input.transform ? { transform: input.transform } : {}) };
}
