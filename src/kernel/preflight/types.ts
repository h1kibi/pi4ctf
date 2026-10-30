/** Kernel-owned preflight metadata schema. Providers produce this data; the
 *  kernel validates, persists, and digests it. */
import type { TargetSpec } from '../types.js';

export type ElfClass = 'ELF32' | 'ELF64';
export type Relro = 'none' | 'partial' | 'full' | null;

export interface ElfInfo {
  class: ElfClass;
  endian: 'little' | 'big';
  type: 'relocatable' | 'executable' | 'shared' | 'core' | 'unknown';
  machine: string;
  arch: string;
  bits: number;
  pie: boolean | null;
  canary: boolean | null;
  nx: boolean | null;
  stackExec: boolean | null;
  relro: Relro;
  buildId: string | null;
  interpreter: string | null;
  needed: string[];
  rpath: string[];
  runpath: string[];
  soname: string | null;
}

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

export interface OtherFile {
  path: string;
  bytes: number;
  sha256: string;
  generated?: boolean;
  mtimeMs?: number;
  format: string;
  arch?: string;
  bits?: number;
  entry?: number;
  details?: string;
}

export interface ChallengeScanOptions {
  includeWorkspace?: boolean;
  includeBuild?: boolean;
}

export interface ChallengeScan {
  files: ChallengeFile[];
  libc: LibcInfo[];
  otherFiles: OtherFile[];
  otherFilesTotal: number;
  notes: string[];
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
