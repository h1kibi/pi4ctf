/**
 * Challenge preflight: static ELF/libc metadata, no model strategy.
 *
 * The kernel owns this scan because the same bytes must produce the same
 * chal.json regardless of which model is driving the case. It intentionally
 * does not run readelf/checksec: those tools are absent on Windows hosts and
 * differ between images. File discovery and format classification live in
 * ./files.ts; the pure ELF parser lives in ./elf.ts; this module owns libc
 * classification and chal.json writes.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import type { TargetSpec } from '../types.js';
import { elfMagic, isLibcName, libcVersion, looksLikeInterpreter, parseElf, type ElfInfo } from './elf.js';
import {
  analyzeOther,
  detectFormat,
  generatedPath,
  readIgnore,
  relPosix,
  safeReadFile,
  walk,
  type OtherFile,
} from './files.js';

const MAX_OTHER_FILES = 256;

export interface ChallengeFile {
  path: string;
  bytes: number;
  sha256: string;
  generated?: boolean;
  mtimeMs?: number;
  elf: ElfInfo;
}

export interface LibcInfo {
  path: string;
  bytes: number;
  sha256: string;
  buildId: string | null;
  version: string | null;
  soname: string | null;
  interpreter: boolean;
}

export interface ChallengeMetadata {
  endpoint: TargetSpec | null;
  files: ChallengeFile[];
  libc: LibcInfo[];
  otherFiles: OtherFile[];
  otherFilesTotal?: number;
  otherFilesTruncated?: boolean;
  notes: string[];
}

export interface PreflightResult {
  path: string;
  endpoint: TargetSpec | null;
  files: ChallengeFile[];
  libc: LibcInfo[];
  otherFiles: OtherFile[];
  otherFilesTotal: number;
  otherFilesTruncated: boolean;
  rootFiles: string[];
  generated: string[];
  notes: string[];
}





























export function preflight(project: Project, opts: { includeWorkspace?: boolean; includeBuild?: boolean } = {}): PreflightResult {
  const includeWorkspace = opts.includeWorkspace === true;
  const includeBuild = opts.includeBuild === true;
  const { files: candidates, notes } = walk(project.root, readIgnore(project.root), includeWorkspace, includeBuild);
  const endpoint = project.file().target ?? null;
  const files: ChallengeFile[] = [];
  const libc: LibcInfo[] = [];
  const otherFiles: OtherFile[] = [];
  let otherFilesTotal = 0;
  for (const abs of candidates) {
    const rel = relPosix(project.root, abs);
    const buf = safeReadFile(abs);
    if (!buf) continue;
    const generated = generatedPath(rel);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(abs).mtimeMs; } catch { /* keep 0 */ }
    if (!elfMagic(buf)) {
      otherFilesTotal++;
      if (otherFiles.length < MAX_OTHER_FILES) {
        const detected = detectFormat(buf, path.basename(abs));
        otherFiles.push({
          path: rel,
          bytes: buf.length,
          sha256: sha256(buf),
          generated,
          mtimeMs,
          ...analyzeOther(buf, detected),
        });
      }
      continue;
    }
    const info = parseElf(buf);
    if (!info) {
      notes.push(`unparsable ELF: ${rel}`);
      continue;
    }
    const entry: ChallengeFile = {
      path: rel,
      bytes: buf.length,
      sha256: sha256(buf),
      generated,
      mtimeMs,
      elf: info,
    };
    files.push(entry);
    const name = path.basename(abs);
    if (isLibcName(name) || info.soname === 'libc.so.6') {
      libc.push({
        path: rel,
        bytes: buf.length,
        sha256: entry.sha256,
        buildId: info.buildId,
        version: libcVersion(buf),
        soname: info.soname,
        interpreter: looksLikeInterpreter(name),
      });
    }
  }
  if (files.length === 0) notes.push('no ELF files found');
  if (otherFilesTotal > otherFiles.length) {
    notes.push(`other file cap reached: indexed ${otherFiles.length}/${otherFilesTotal}; rootFiles reflects indexed files only`);
  }
  const allFiles = [...files, ...otherFiles];
  const rootFiles = allFiles.filter((f) => !f.generated).sort((a, b) => (a.mtimeMs ?? 0) - (b.mtimeMs ?? 0) || a.path.localeCompare(b.path)).map((f) => f.path);
  const generatedList = allFiles.filter((f) => f.generated).map((f) => f.path);
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
    otherFilesTruncated: otherFilesTotal > otherFiles.length,
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
    otherFilesTruncated: otherFilesTotal > otherFiles.length,
    rootFiles,
    generated: generatedList,
    notes,
  };
}

export function readChallenge(project: Project): ChallengeMetadata | null {
  const p = path.join(project.ctfDir, 'chal.json');
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')) as ChallengeMetadata;
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
