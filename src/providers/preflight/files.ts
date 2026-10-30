/**
 * Bounded challenge file discovery and non-ELF format classification.
 *
 * This module owns .ctfignore, output-root ordering, size/count caps, and
 * basic format detection. ELF parsing lives in ./elf.ts; chal.json writes
 * stay in preflight.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { OtherFile } from '../../kernel/preflight/types.js';
import { elfMagic } from './elf.js';

const MAX_FILES = 256;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_DEPTH = 2;
const OUTPUT_DIRS = new Set(['build', 'out', 'dist', 'target', 'obj', '__pycache__', '.cache', 'screenshots', 'shots']);

export function safeReadFile(file: string): Buffer | null {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size <= 0 || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file);
  } catch {
    return null;
  }
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

export function readIgnore(root: string): RegExp[] {
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

export function detectFormat(buf: Buffer, name = ''): string {
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

export function generatedPath(rel: string): boolean {
  const top = rel.split('/')[0]?.toLowerCase() ?? '';
  return top === 'workspace' || OUTPUT_DIRS.has(top);
}

export function analyzeOther(buf: Buffer, format: string): Pick<OtherFile, 'format' | 'arch' | 'bits' | 'entry' | 'details'> {
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

export function walk(root: string, userIgnore: RegExp[] = readIgnore(root), includeWorkspace = false, includeBuild = false): { files: string[]; notes: string[] } {
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

export function relPosix(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join('/');
}
