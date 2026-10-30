/**
 * Deterministic ELF metadata parsing for preflight.
 *
 * No readelf/checksec dependency: the same bytes produce the same fields on
 * every host and backend. File discovery and chal.json remain in preflight.
 */
import { KernelError } from '../../kernel/error.js';
import type { ElfInfo, Relro } from '../../kernel/preflight/types.js';

const MAX_STRING_SCAN = 2 * 1024 * 1024;

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

export function elfMagic(buf: Buffer): boolean {
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

export function parseElf(buf: Buffer): ElfInfo | null {
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

export function libcVersion(buf: Buffer): string | null {
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

export function isLibcName(name: string): boolean {
  return /^libc(?:[-.]|$)/i.test(name) || /^ld-(?:linux|musl)/i.test(name);
}

export function looksLikeInterpreter(name: string): boolean {
  return /^ld-(?:linux|musl)/i.test(name);
}
