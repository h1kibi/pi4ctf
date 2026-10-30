/**
 * Preflight capability provider.
 *
 * Scans a challenge root and returns kernel-owned metadata types. This module
 * does not write .ctf state, append events, or decide target/oracle semantics.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { sha256 } from '../../kernel/fsutil.js';
import type {
  ChallengeFile,
  ChallengeScan,
  ChallengeScanOptions,
  LibcInfo,
  OtherFile,
} from '../../kernel/preflight/types.js';
import { analyzeOther, detectFormat, generatedPath, readIgnore, relPosix, safeReadFile, walk } from './files.js';
import { elfMagic, isLibcName, libcVersion, looksLikeInterpreter, parseElf } from './elf.js';

const MAX_OTHER_FILES = 256;

export function scanChallenge(root: string, opts: ChallengeScanOptions = {}): ChallengeScan {
  const includeWorkspace = opts.includeWorkspace === true;
  const includeBuild = opts.includeBuild === true;
  const { files: candidates, notes } = walk(root, readIgnore(root), includeWorkspace, includeBuild);
  const files: ChallengeFile[] = [];
  const libc: LibcInfo[] = [];
  const otherFiles: OtherFile[] = [];
  let otherFilesTotal = 0;

  for (const abs of candidates) {
    const rel = relPosix(root, abs);
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
  return { files, libc, otherFiles, otherFilesTotal, notes };
}
