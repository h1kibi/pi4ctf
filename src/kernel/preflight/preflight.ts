/**
 * Challenge preflight recorder.
 *
 * The provider scans the challenge root and returns kernel-owned metadata.
 * This module validates that shape, computes root/generated views, writes
 * chal.json, audits the event, and provides packet digest helpers.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWriteFile } from '../fsutil.js';
import { KernelError } from '../error.js';
import { Project } from '../project.js';
import type { TargetSpec } from '../types.js';
import type {
  ChallengeMetadata,
  ChallengeScan,
  PreflightResult,
} from './types.js';

function isRelativePath(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && !path.isAbsolute(value)
    && !value.split('/').includes('..');
}

/** Provider output is untrusted at the boundary: reject rows that would make
 *  packet/digest code throw after the scan is cached. */
function validateScan(scan: ChallengeScan): void {
  if (!scan
    || typeof scan !== 'object'
    || !Array.isArray(scan.files)
    || !Array.isArray(scan.libc)
    || !Array.isArray(scan.otherFiles)
    || !Array.isArray(scan.notes)
    || !Number.isInteger(scan.otherFilesTotal)
    || scan.otherFilesTotal < scan.otherFiles.length) {
    throw new KernelError('INTERNAL', 'invalid preflight scan: expected arrays and otherFilesTotal');
  }
  for (const note of scan.notes) {
    if (typeof note !== 'string') throw new KernelError('INTERNAL', 'invalid preflight scan: note must be a string');
  }
  for (const file of scan.files) {
    if (!file
      || typeof file !== 'object'
      || Array.isArray(file)
      || !isRelativePath(file.path)
      || typeof file.bytes !== 'number'
      || typeof file.sha256 !== 'string'
      || !file.elf
      || typeof file.elf !== 'object'
      || Array.isArray(file.elf)
      || typeof file.elf.bits !== 'number'
      || typeof file.elf.type !== 'string'
      || !Array.isArray(file.elf.needed)
      || (file.elf.interpreter !== null && typeof file.elf.interpreter !== 'string')
      || (file.elf.buildId !== null && typeof file.elf.buildId !== 'string')) {
      throw new KernelError('INTERNAL', `invalid preflight scan: malformed ELF row ${String(file?.path ?? '?')}`);
    }
  }
  for (const libc of scan.libc) {
    if (!libc
      || typeof libc !== 'object'
      || Array.isArray(libc)
      || !isRelativePath(libc.path)
      || typeof libc.bytes !== 'number'
      || typeof libc.sha256 !== 'string'
      || (libc.buildId !== null && typeof libc.buildId !== 'string')
      || (libc.version !== null && typeof libc.version !== 'string')
      || (libc.soname !== null && typeof libc.soname !== 'string')
      || typeof libc.interpreter !== 'boolean') {
      throw new KernelError('INTERNAL', 'invalid preflight scan: malformed libc row');
    }
  }
  for (const file of scan.otherFiles) {
    if (!file
      || typeof file !== 'object'
      || Array.isArray(file)
      || !isRelativePath(file.path)
      || typeof file.bytes !== 'number'
      || typeof file.sha256 !== 'string'
      || typeof file.format !== 'string') {
      throw new KernelError('INTERNAL', 'invalid preflight scan: malformed other-file row');
    }
  }
}

export function recordPreflight(project: Project, scan: ChallengeScan): PreflightResult {
  validateScan(scan);
  const endpoint = project.file().target ?? null;
  const { files, libc, otherFiles, otherFilesTotal, notes } = scan;
  if (!Array.isArray(files) || !Array.isArray(libc) || !Array.isArray(otherFiles) || !Array.isArray(notes)) {
    throw new KernelError('INTERNAL', 'invalid preflight scan: expected arrays');
  }
  const otherFilesTruncated = otherFilesTotal > otherFiles.length;
  const allFiles = [...files, ...otherFiles];
  const rootFiles = allFiles
    .filter((f) => !f.generated)
    .sort((a, b) => (a.mtimeMs ?? 0) - (b.mtimeMs ?? 0) || a.path.localeCompare(b.path))
    .map((f) => f.path);
  const generated = allFiles.filter((f) => f.generated).map((f) => f.path);
  const outPath = path.join(project.ctfDir, 'chal.json');

  try {
    const previous = JSON.parse(fs.readFileSync(outPath, 'utf8')) as ChallengeMetadata;
    const previousRoot = new Set(
      [...(previous.files ?? []), ...(previous.otherFiles ?? [])]
        .filter((f) => !f.generated)
        .map((f) => f.path),
    );
    const added = rootFiles.filter((f) => !previousRoot.has(f));
    if (previousRoot.size > 0 && added.length > 0) {
      notes.push(`new root file(s) since last preflight: ${added.slice(0, 8).join(', ')}${added.length > 8 ? ', ...' : ''}; move generated outputs to workspace/`);
    }
  } catch {
    // First preflight (or an unreadable old file): no baseline to compare.
  }

  const metadata: ChallengeMetadata = {
    endpoint,
    files,
    libc,
    otherFiles,
    otherFilesTotal,
    otherFilesTruncated,
    notes,
  };
  atomicWriteFile(outPath, JSON.stringify(metadata, null, 2));
  project.appendEvent('case.preflight', 'adapter', {
    files: files.length,
    libc: libc.length,
    notes: notes.length,
  });
  return {
    path: outPath,
    endpoint,
    files,
    libc,
    otherFiles,
    otherFilesTotal,
    otherFilesTruncated,
    rootFiles,
    generated,
    notes,
  };
}

function isChallengeMetadata(value: unknown): value is ChallengeMetadata {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const m = value as Record<string, unknown>;
  if (!Array.isArray(m.files)
    || !Array.isArray(m.libc)
    || !Array.isArray(m.otherFiles)
    || !Array.isArray(m.notes)
    || (m.endpoint !== null && (typeof m.endpoint !== 'object' || Array.isArray(m.endpoint)))
    || (m.otherFilesTotal !== undefined && typeof m.otherFilesTotal !== 'number')) return false;
  for (const note of m.notes) if (typeof note !== 'string') return false;
  for (const file of m.files) {
    if (!file || typeof file !== 'object' || Array.isArray(file)) return false;
    const row = file as Record<string, unknown>;
    const elf = row.elf;
    if (typeof row.path !== 'string'
      || !elf || typeof elf !== 'object' || Array.isArray(elf)
      || !Array.isArray((elf as Record<string, unknown>).needed)
      || ((elf as Record<string, unknown>).buildId !== undefined
        && (elf as Record<string, unknown>).buildId !== null
        && typeof (elf as Record<string, unknown>).buildId !== 'string')) return false;
  }
  for (const libc of m.libc) {
    if (!libc || typeof libc !== 'object' || Array.isArray(libc)
      || typeof (libc as Record<string, unknown>).path !== 'string') return false;
  }
  for (const file of m.otherFiles) {
    if (!file || typeof file !== 'object' || Array.isArray(file)
      || typeof (file as Record<string, unknown>).path !== 'string') return false;
  }
  return true;
}

export function readChallenge(project: Project): ChallengeMetadata | null {
  const p = path.join(project.ctfDir, 'chal.json');
  if (!fs.existsSync(p)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as unknown;
    return isChallengeMetadata(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Compact packet lines; never dump the whole chal.json into the prompt. */
export function challengeDigest(metadata: ChallengeMetadata, currentTarget: TargetSpec | null = null): string {
  const lines = ['## Challenge metadata'];
  if (metadata.endpoint) {
    const ep = metadata.endpoint;
    const line = `${ep.protocol ?? 'tcp'}://${ep.host}${ep.port ? `:${ep.port}` : ''}${ep.instanceId ? ` instance=${ep.instanceId}` : ''}`;
    const same = currentTarget
      && ep.host === currentTarget.host
      && ep.port === currentTarget.port
      && (ep.instanceId ?? '') === (currentTarget.instanceId ?? '');
    lines.push(same ? `- endpoint: ${line}` : `- preflight endpoint (stale): ${line}`);
    if (currentTarget && !same) {
      lines.push(`- current target: ${currentTarget.protocol ?? 'tcp'}://${currentTarget.host}${currentTarget.port ? `:${currentTarget.port}` : ''}${currentTarget.instanceId ? ` instance=${currentTarget.instanceId}` : ''}`);
    }
  }
  const digestFiles = [...metadata.files].sort((a, b) => Number(a.generated === true) - Number(b.generated === true) || a.path.localeCompare(b.path));
  for (const f of digestFiles.slice(0, 4)) {
    const e = f.elf;
    const flags = [
      e.bits === 64 ? '64-bit' : '32-bit',
      e.type,
      e.pie === true ? 'PIE' : e.pie === false ? 'no-PIE' : null,
      e.canary === true ? 'canary' : e.canary === false ? 'no-canary' : null,
      e.nx === true ? 'NX' : e.nx === false ? 'exec-stack' : null,
      e.relro ? `RELRO:${e.relro}` : null,
      e.buildId ? `build-id:${e.buildId.slice(0, 16)}` : null,
    ].filter(Boolean).join(' ');
    lines.push(`- ${f.path}${f.generated ? ' [generated]' : ''}: ${flags}`);
    if (e.needed.length) lines.push(`  needed: ${e.needed.slice(0, 8).join(', ')}`);
    if (e.interpreter) lines.push(`  interp: ${e.interpreter}`);
  }
  for (const l of metadata.libc.slice(0, 3)) {
    lines.push(`- libc ${l.path}: version=${l.version ?? '?'} build-id=${l.buildId ?? '?'}${l.interpreter ? ' (loader)' : ''}`);
  }
  const other = metadata.otherFiles ?? [];
  if (other.length > 0) {
    const total = metadata.otherFilesTotal ?? other.length;
    lines.push(`- other files (non-ELF): ${total} found, ${other.length} indexed; full list in .ctf/chal.json`);
  }
  const all = [...metadata.files, ...other];
  const rootFiles = all
    .filter((f) => !f.generated)
    .sort((a, b) => (a.mtimeMs ?? 0) - (b.mtimeMs ?? 0) || a.path.localeCompare(b.path))
    .map((f) => f.path);
  const generated = all.filter((f) => f.generated).map((f) => f.path);
  if (rootFiles.length) lines.push(`- root files (ELF+non-ELF, unclassified): ${rootFiles.length} (${rootFiles.slice(0, 4).join(', ')}${rootFiles.length > 4 ? ', ...' : ''})`);
  if (generated.length) lines.push(`- generated (workspace/build): ${generated.length} (${generated.slice(0, 4).join(', ')}${generated.length > 4 ? ', ...' : ''})`);
  if (metadata.notes.length > 0) lines.push(`- notes: ${metadata.notes.slice(0, 4).join('; ')}`);
  lines.push('- source: .ctf/chal.json (static preflight; verify runtime libc separately)');
  return lines.join('\n');
}
