/**
 * Challenge preflight: static ELF/libc metadata, no model strategy.
 *
 * The kernel owns this scan because the same bytes must produce the same
 * chal.json regardless of which model is driving the case. It intentionally
 * does not run readelf/checksec: those tools are absent on Windows hosts and
 * differ between images. Reading the ELF headers/notes/dynamic section here
 * gives a deterministic subset (arch, PIE, NX, canary, RELRO, build-id,
 * NEEDED/RUNPATH, interpreter) on every backend.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { KernelError } from '../error.js';
import { Project } from '../project.js';
import type { TargetSpec } from '../types.js';

const MAX_FILES = 256;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_DEPTH = 2;
const MAX_OTHER_FILES = 256;
const OUTPUT_DIRS = new Set(['build', 'out', 'dist', 'target', 'obj', '__pycache__', '.cache', 'screenshots', 'shots']);
const MAX_STRING_SCAN = 2 * 1024 * 1024;

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

class Reader {
  constructor(
    private readonly buf: Buffer,
    private readonly little: boolean,
  ) {}

  u16(off: number): number {
    return this.little ? this.buf.readUInt16LE(off) : this.buf.readUInt16BE(off);
  }

  u32(off: number): number {
    return this.little ? this.buf.readUInt32LE(off) : this.buf.readUInt32BE(off);
  }

  u64(off: number): number {
    const v = this.little ? this.buf.readBigUInt64LE(off) : this.buf.readBigUInt64BE(off);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new KernelError('LIMIT', 'ELF offset exceeds safe integer range');
    }
    return Number(v);
  }

  bytes(off: number, len: number): Buffer {
    if (off < 0 || len < 0 || off + len > this.buf.length) {
      throw new KernelError('INVALID_REQUEST', 'ELF field out of bounds');
    }
    return this.buf.subarray(off, off + len);
  }

  get length(): number {
    return this.buf.length;
  }

  cstr(off: number, limit = 4096): string {
    if (off < 0 || off >= this.buf.length) return '';
    const end = Math.min(this.buf.length, off + limit);
    let i = off;
    while (i < end && this.buf[i] !== 0) i++;
    return this.buf.subarray(off, i).toString('utf8');
  }
}

interface Section {
  name: string;
  type: number;
  offset: number;
  size: number;
  link: number;
  entsize: number;
}

interface Phdr {
  type: number;
  flags: number;
  offset: number;
  vaddr: number;
  filesz: number;
  memsz: number;
}

const ET: Record<number, ElfInfo['type']> = {
  0: 'unknown',
  1: 'relocatable',
  2: 'executable',
  3: 'shared',
  4: 'core',
};

const MACHINE: Record<number, string> = {
  3: 'x86',
  8: 'mips',
  20: 'ppc',
  21: 'ppc64',
  40: 'arm',
  62: 'x86-64',
  183: 'aarch64',
  243: 'riscv',
};

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const PT_NOTE = 4;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

const SHT_SYMTAB = 2;
const SHT_DYNSYM = 11;

const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_STRSZ = 10;
const DT_SONAME = 14;
const DT_RPATH = 15;
const DT_BIND_NOW = 24;
const DT_RUNPATH = 29;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;
const NT_GNU_BUILD_ID = 3;

function safeReadFile(file: string): Buffer | null {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file);
  } catch {
    return null;
  }
}

function elfMagic(buf: Buffer): boolean {
  return buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
}

function vaddrToOffset(phdrs: Phdr[], vaddr: number): number | null {
  for (const p of phdrs) {
    if (p.type !== PT_LOAD) continue;
    if (vaddr >= p.vaddr && vaddr < p.vaddr + p.filesz) return p.offset + (vaddr - p.vaddr);
  }
  return null;
}

function noteBuildId(r: Reader, notes: { offset: number; size: number }[]): string | null {
  for (const n of notes) {
    const end = Math.min(r.length, n.offset + n.size);
    let off = n.offset;
    while (off + 12 <= end) {
      const namesz = r.u32(off);
      const descsz = r.u32(off + 4);
      const type = r.u32(off + 8);
      off += 12;
      if (namesz > 4096 || descsz > 1024 * 1024 || off + namesz + descsz > end) break;
      const name = r.bytes(off, namesz).toString('utf8').replace(/\0+$/, '');
      off += namesz;
      off = (off + 3) & ~3;
      const desc = r.bytes(off, descsz);
      off += descsz;
      off = (off + 3) & ~3;
      if (type === NT_GNU_BUILD_ID && name === 'GNU' && desc.length > 0) {
        return desc.toString('hex');
      }
    }
  }
  return null;
}

function parseElf(buf: Buffer): ElfInfo | null {
  if (!elfMagic(buf) || buf.length < 52) return null;
  const cls = buf[4];
  if (cls !== 1 && cls !== 2) return null;
  const data = buf[5];
  if (data !== 1 && data !== 2) return null;
  const is64 = cls === 2;
  const little = data === 1;
  const r = new Reader(buf, little);
  const bits = is64 ? 64 : 32;
  const typeNum = r.u16(16);
  const machineNum = r.u16(18);
  const phoff = is64 ? r.u64(32) : r.u32(28);
  const shoff = is64 ? r.u64(40) : r.u32(32);
  const phentsize = is64 ? r.u16(54) : r.u16(42);
  const phnum = is64 ? r.u16(56) : r.u16(44);
  const shentsize = is64 ? r.u16(58) : r.u16(46);
  const shnum = is64 ? r.u16(60) : r.u16(48);
  const shstrndx = is64 ? r.u16(62) : r.u16(50);

  const phdrs: Phdr[] = [];
  for (let i = 0; i < phnum; i++) {
    const off = phoff + i * phentsize;
    if (off + phentsize > buf.length) break;
    if (is64) {
      phdrs.push({
        type: r.u32(off),
        flags: r.u32(off + 4),
        offset: r.u64(off + 8),
        vaddr: r.u64(off + 16),
        filesz: r.u64(off + 32),
        memsz: r.u64(off + 40),
      });
    } else {
      phdrs.push({
        type: r.u32(off),
        flags: r.u32(off + 24),
        offset: r.u32(off + 4),
        vaddr: r.u32(off + 8),
        filesz: r.u32(off + 16),
        memsz: r.u32(off + 20),
      });
    }
  }

  const sections: Section[] = [];
  for (let i = 0; i < shnum; i++) {
    const off = shoff + i * shentsize;
    if (off + shentsize > buf.length) break;
    if (is64) {
      sections.push({
        name: '',
        type: r.u32(off + 4),
        offset: r.u64(off + 24),
        size: r.u64(off + 32),
        link: r.u32(off + 40),
        entsize: r.u64(off + 56),
      });
    } else {
      sections.push({
        name: '',
        type: r.u32(off + 4),
        offset: r.u32(off + 16),
        size: r.u32(off + 20),
        link: r.u32(off + 24),
        entsize: r.u32(off + 36),
      });
    }
  }
  // Section-name string table.
  if (shstrndx < sections.length) {
    const str = sections[shstrndx];
    if (str && str.offset < buf.length) {
      const end = Math.min(buf.length, str.offset + str.size);
      let off = str.offset;
      const names: string[] = [];
      while (off < end) {
        let i = off;
        while (i < end && buf[i] !== 0) i++;
        names.push(buf.subarray(off, i).toString('utf8'));
        off = i + 1;
      }
      // sh_name is not stored in Section above; read it again per section.
      for (let i = 0; i < sections.length; i++) {
        const shOff = shoff + i * shentsize;
        const nameOff = r.u32(shOff);
        sections[i].name = names[nameOff] ?? '';
      }
    }
  }

  const gnuStack = phdrs.find((p) => p.type === PT_GNU_STACK);
  const gnuRelro = phdrs.find((p) => p.type === PT_GNU_RELRO);
  const interpSeg = phdrs.find((p) => p.type === PT_INTERP);
  const interpSection = sections.find((s) => s.name === '.interp');
  let interpreter: string | null = null;
  if (interpSeg && interpSeg.filesz > 0) {
    interpreter = r.cstr(interpSeg.offset, Math.min(interpSeg.filesz, 4096)).replace(/\0+$/, '');
  } else if (interpSection) {
    interpreter = r.cstr(interpSection.offset, Math.min(interpSection.size, 4096)).replace(/\0+$/, '');
  }

  // Dynamic entries: strings are resolved through the load segment mapping.
  const neededOffsets: number[] = [];
  const rpathOffsets: number[] = [];
  const runpathOffsets: number[] = [];
  let sonameOffset: number | null = null;
  let strtabVaddr: number | null = null;
  let strsz: number | null = null;
  let flags = 0;
  let flags1 = 0;
  let bindNow = false;
  const dyn = phdrs.find((p) => p.type === PT_DYNAMIC);
  if (dyn && dyn.filesz > 0) {
    const ent = is64 ? 16 : 8;
    const end = Math.min(buf.length, dyn.offset + dyn.filesz);
    for (let off = dyn.offset; off + ent <= end; off += ent) {
      const tag = is64 ? r.u64(off) : r.u32(off);
      const val = is64 ? r.u64(off + 8) : r.u32(off + 4);
      if (tag === DT_NULL) break;
      switch (tag) {
        case DT_NEEDED: neededOffsets.push(val); break;
        case DT_RPATH: rpathOffsets.push(val); break;
        case DT_RUNPATH: runpathOffsets.push(val); break;
        case DT_SONAME: sonameOffset = val; break;
        case DT_STRTAB: strtabVaddr = val; break;
        case DT_STRSZ: strsz = val; break;
        case DT_FLAGS: flags = val; break;
        case DT_FLAGS_1: flags1 = val; break;
        case DT_BIND_NOW: bindNow = true; break;
      }
    }
  }
  let dynstr: Buffer | null = null;
  if (strtabVaddr !== null && strsz !== null) {
    const off = vaddrToOffset(phdrs, strtabVaddr);
    if (off !== null && off + strsz <= buf.length) dynstr = buf.subarray(off, off + strsz);
  }
  const dynString = (offset: number): string => {
    if (!dynstr || offset < 0 || offset >= dynstr.length) return '';
    const end = Math.min(dynstr.length, offset + 4096);
    let i = offset;
    while (i < end && dynstr[i] !== 0) i++;
    return dynstr.subarray(offset, i).toString('utf8');
  };
  const needed = neededOffsets.map(dynString).filter(Boolean).slice(0, 64);
  const rpath = rpathOffsets.map(dynString).filter(Boolean).slice(0, 16);
  const runpath = runpathOffsets.map(dynString).filter(Boolean).slice(0, 16);
  const soname = sonameOffset === null ? null : dynString(sonameOffset) || null;

  // Notes (build-id) from PT_NOTE segments.
  const notes = phdrs.filter((p) => p.type === PT_NOTE).map((p) => ({ offset: p.offset, size: p.filesz }));
  const buildId = noteBuildId(r, notes);

  // Canary: dynamic or regular symbol named __stack_chk_fail.
  let canary: boolean | null = null;
  for (const sec of sections) {
    if (sec.type !== SHT_SYMTAB && sec.type !== SHT_DYNSYM) continue;
    const strSec = sections[sec.link];
    if (!strSec || !sec.entsize) continue;
    const strOff = strSec.offset;
    const strEnd = Math.min(buf.length, strSec.offset + strSec.size);
    const end = Math.min(buf.length, sec.offset + sec.size);
    for (let off = sec.offset; off + sec.entsize <= end; off += sec.entsize) {
      const nameOff = r.u32(off);
      if (strOff + nameOff >= strEnd) continue;
      let i = strOff + nameOff;
      while (i < strEnd && buf[i] !== 0) i++;
      if (buf.subarray(strOff + nameOff, i).toString('utf8') === '__stack_chk_fail') {
        canary = true;
        break;
      }
    }
    if (canary === true) break;
  }
  if (canary === null && sections.some((s) => s.type === SHT_DYNSYM)) canary = false;

  const stackExec = gnuStack ? (gnuStack.flags & 1) !== 0 : null;
  const nx = stackExec === null ? null : !stackExec;
  const relro: Relro = gnuRelro
    ? ((bindNow || (flags & DF_BIND_NOW) !== 0 || (flags1 & DF_1_NOW) !== 0) ? 'full' : 'partial')
    : sections.some((s) => s.name === '.dynamic')
      ? 'none'
      : null;
  const isShared = typeNum === 3;
  const pie = typeNum === 2 ? false : isShared && interpreter !== null && soname === null ? true : null;
  const machine = MACHINE[machineNum] ?? `machine-${machineNum}`;

  return {
    class: is64 ? 'ELF64' : 'ELF32',
    endian: little ? 'little' : 'big',
    type: ET[typeNum] ?? 'unknown',
    machine,
    arch: `${machine}${bits === 64 ? '' : ` (${bits}-bit)`}`,
    bits,
    pie,
    canary,
    nx,
    stackExec,
    relro,
    buildId,
    interpreter,
    needed,
    rpath,
    runpath,
    soname,
  };
}

function libcVersion(buf: Buffer): string | null {
  const text = buf.subarray(0, Math.min(buf.length, MAX_STRING_SCAN)).toString('latin1');
  const patterns = [
    /GNU C Library[^\n]{0,120}?release version ([0-9][0-9A-Za-z.+-]*)/i,
    /glibc[^\n]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    /libc[- ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
  ];
  for (const re of patterns) {
    const m = re.exec(text);
    if (m?.[1]) return m[1].replace(/[.+-]+$/, '');
  }
  return null;
}

function isLibcName(name: string): boolean {
  return /^libc(?:[-.]|$)/i.test(name) || /^ld-(?:linux|musl)/i.test(name);
}

function looksLikeInterpreter(name: string): boolean {
  return /^ld-(?:linux|musl)/i.test(name);
}

function globToRegex(pattern: string): RegExp {
  const anchored = pattern.startsWith('/');
  const body = anchored ? pattern.slice(1) : pattern;
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '*') {
      if (body[i + 1] === '*') {
        out += '.*';
        i++;
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${anchored ? '' : '(?:.*/)?'}${out}$`);
}

function readIgnore(root: string): RegExp[] {
  const p = path.join(root, '.ctfignore');
  if (!fs.existsSync(p)) return [];
  const patterns: RegExp[] = [];
  for (const raw of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    // Negation is intentionally not supported: preflight has a safe default
    // and explicit exclusions; silent re-inclusion of core dumps is worse.
    if (line.startsWith('!')) continue;
    try {
      patterns.push(globToRegex(line));
    } catch {
      // ignore malformed user pattern
    }
  }
  return patterns;
}

function detectFormat(buf: Buffer, name = ''): string {
  if (elfMagic(buf)) return 'ELF';
  if (/\.class$/i.test(name) && buf.length >= 4 && buf.readUInt32BE(0) === 0xcafebabe) return 'Java class';
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return 'PE';
  if (buf.length >= 4) {
    const be = buf.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(be)) return 'Mach-O';
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return 'ZIP/JAR/APK';
  if (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === '%PDF') return 'PDF';
  if (buf.length >= 4) {
    const magic = buf.readUInt32LE(0);
    if ([0xa1b2c3d4, 0xd4c3b2a1, 0x0a0d0d0a].includes(magic)) return 'PCAP';
    if (magic === 0x00088b1f) return 'gzip';
  }
  return buf.includes(0) ? 'binary' : 'text';
}

function generatedPath(rel: string): boolean {
  const top = rel.split('/')[0]?.toLowerCase() ?? '';
  return top === 'workspace' || OUTPUT_DIRS.has(top);
}

function analyzeOther(buf: Buffer, format: string): Pick<OtherFile, 'format' | 'arch' | 'bits' | 'entry' | 'details'> {
  try {
    if (format === 'PE' && buf.length >= 0x40) {
      const pe = buf.readUInt32LE(0x3c);
      if (pe + 24 <= buf.length && buf.readUInt32LE(pe) === 0x00004550) {
        const machine = buf.readUInt16LE(pe + 4);
        const sections = buf.readUInt16LE(pe + 6);
        const opt = pe + 24;
        const magic = buf.readUInt16LE(opt);
        const bits = magic === 0x20b ? 64 : 32;
        const entry = bits === 64 ? Number(buf.readBigUInt64LE(opt + 16)) : buf.readUInt32LE(opt + 16);
        const arch = machine === 0x8664 ? 'x86-64' : machine === 0x14c ? 'x86' : machine === 0xaa64 ? 'arm64' : `pe-${machine}`;
        return { format: 'PE', arch, bits, entry, details: `sections=${sections}` };
      }
    }
    if (format === 'Mach-O' && buf.length >= 16) {
      const le = [0xfeedface, 0xfeedfacf].includes(buf.readUInt32LE(0));
      const cputype = le ? buf.readUInt32LE(4) : buf.readUInt32BE(4);
      const ncmds = le ? buf.readUInt32LE(16) : buf.readUInt32BE(16);
      const arch = cputype === 0x01000007 ? 'x86-64' : cputype === 0x00000007 ? 'x86' :
        cputype === 0x0100000c ? 'arm64' : cputype === 0x0000000c ? 'arm' : `macho-${cputype}`;
      return { format: 'Mach-O', arch, details: `ncmds=${ncmds}` };
    }
    if (format === 'Java class' && buf.length >= 8) {
      const major = buf.readUInt16BE(6);
      const jdk = major <= 52 ? 'JDK8-compatible' : major <= 55 ? 'JDK11-compatible' : 'newer than JDK11';
      return { format: 'Java class', arch: 'jvm', details: `major=${major} (${jdk})` };
    }
    if (format === 'ZIP/JAR/APK') {
      const text = buf.toString('latin1');
      const apk = text.includes('AndroidManifest.xml') || text.includes('classes.dex');
      let entries = 0;
      let idx = 0;
      while ((idx = text.indexOf('PK\x03\x04', idx)) >= 0 && entries < 10000) {
        entries++;
        idx += 4;
      }
      return { format: apk ? 'APK' : 'ZIP/JAR', details: `entries~${entries}` };
    }
    if (format === 'PCAP' && buf.length >= 24) {
      const linktype = buf.readUInt32LE(20);
      return { format: 'PCAP', details: `linktype=${linktype}` };
    }
  } catch {
    // keep the basic format on malformed headers
  }
  return { format };
}

function ignored(rel: string, name: string, isDir: boolean, user: RegExp[], includeWorkspace: boolean, includeBuild: boolean): boolean {
  const lower = name.toLowerCase();
  if (!isDir && lower === '.ctfignore') return true;
  if (isDir && (['.git', 'node_modules', '.ctf'].includes(lower) || (!includeWorkspace && lower === 'workspace') || (!includeBuild && OUTPUT_DIRS.has(lower)))) return true;
  if (!isDir) {
    if (/^core(?:\.\d+)?$/.test(lower) || /\.core$/.test(lower)) return true;
    if (/\.(?:zip|tar|tgz|7z|rar)$/.test(lower)) return true;
  }
  if (user.some((re) => re.test(rel))) return true;
  return false;
}

function walk(root: string, userIgnore: RegExp[] = readIgnore(root), includeWorkspace = false, includeBuild = false): { files: string[]; notes: string[] } {
  const files: string[] = [];
  const notes: string[] = [];
  let total = 0;
  let capNoted = false;
  const noteCap = () => {
    if (capNoted) return;
    capNoted = true;
    notes.push(`file cap reached: ${MAX_FILES}; use .ctfignore or narrow the challenge directory`);
  };
  const scannedTop = new Set<string>();
  const visit = (dir: string, depth: number) => {
    if (files.length >= MAX_FILES) {
      noteCap();
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (files.length >= MAX_FILES) {
        noteCap();
        break;
      }
      if (dir === root && scannedTop.has(ent.name)) continue;
      const rel = path.relative(root, path.join(dir, ent.name)).split(path.sep).join('/');
      if (ignored(rel, ent.name, ent.isDirectory(), userIgnore, includeWorkspace, includeBuild)) {
        notes.push(`ignored: ${rel}`);
        continue;
      }
      const abs = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) {
        notes.push(`skipped symlink: ${path.relative(root, abs)}`);
        continue;
      }
      if (ent.isDirectory()) {
        if (depth < MAX_DEPTH) visit(abs, depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      let st: fs.Stats;
      try {
        st = fs.lstatSync(abs);
      } catch {
        continue;
      }
      if (st.size > MAX_FILE_BYTES) {
        notes.push(`skipped large file: ${path.relative(root, abs)} (${st.size} bytes)`);
        continue;
      }
      if (total + st.size > MAX_TOTAL_BYTES) {
        notes.push('scan byte budget reached');
        return;
      }
      total += st.size;
      files.push(abs);
    }
  };
  // Explicit output roots are scanned first so a crowded challenge root
  // cannot consume the file cap before them.
  const priority: string[] = [];
  if (includeWorkspace) priority.push('workspace');
  if (includeBuild) priority.push(...OUTPUT_DIRS);
  for (const name of priority) {
    const dir = path.join(root, name);
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) continue;
    scannedTop.add(name);
    visit(dir, 0);
  }
  visit(root, 0);
  return { files, notes };
}

function relPosix(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join('/');
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
