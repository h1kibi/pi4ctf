/** Generic tool probe table. No user paths or machine-specific names. */
export interface ProbeDefinition {
  id: string;
  binaries: string[];
  versionArgs: string[][];
  pythonModule?: string;
  versionRe: RegExp;
  provides: string[];
  major?: (version: string) => number | null;
}

function jdkMajor(version: string): number | null {
  const legacy = /^1\.(\d+)/.exec(version);
  if (legacy?.[1]) return Number(legacy[1]);
  const first = /^(\d+)/.exec(version);
  return first?.[1] ? Number(first[1]) : null;
}

export const PROBE_TABLE: ProbeDefinition[] = [
  {
    id: 'jdk',
    binaries: ['java'],
    versionArgs: [['-version']],
    versionRe: /(?:openjdk|java)\s+version\s+"?([^"\s]+)/i,
    provides: ['java', 'java-runtime', 'javac', 'jar'],
    major: jdkMajor,
  },
  {
    id: 'python',
    binaries: ['python3', 'python', 'py'],
    versionArgs: [['--version']],
    versionRe: /Python\s+(\S+)/i,
    provides: ['python', 'python3', 'pip'],
  },
  {
    id: 'gdb',
    binaries: ['gdb'],
    versionArgs: [['--version']],
    versionRe: /GNU gdb.*?(\d+\.\d+(?:\.\d+)*)/i,
    provides: ['debugger'],
  },
  {
    id: 'jadx',
    binaries: ['jadx'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['decompiler'],
  },
  {
    id: 'exiftool',
    binaries: ['exiftool'],
    versionArgs: [['-ver'], ['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['exiftool', 'metadata'],
  },
  {
    id: 'radare2',
    binaries: ['radare2'],
    versionArgs: [['-v'], ['-V']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['radare2', 'reverse'],
  },
  {
    id: 'rizin',
    binaries: ['rizin'],
    versionArgs: [['-v'], ['-V']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['rizin', 'reverse'],
  },
  {
    id: 'binwalk',
    binaries: ['binwalk'],
    versionArgs: [['--help'], ['-h'], ['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['binwalk', 'firmware'],
  },
  {
    id: 'sage',
    binaries: ['sage'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['sage', 'crypto'],
  },
  {
    id: 'foremost',
    binaries: ['foremost'],
    versionArgs: [['-V'], ['-h']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['foremost', 'forensics'],
  },
  {
    id: 'tshark',
    binaries: ['tshark'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['tshark', 'pcap'],
  },
  {
    id: 'apktool',
    binaries: ['apktool'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['apktool', 'android'],
  },
  {
    id: 'sqlmap',
    binaries: ['sqlmap'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['sqlmap', 'web'],
  },
  {
    id: '7z',
    binaries: ['7z'],
    versionArgs: [['-h'], ['--help']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['7z', 'archive'],
  },
  {
    id: 'ffuf',
    binaries: ['ffuf'],
    versionArgs: [['-V'], ['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9]+)?)/,
    provides: ['ffuf', 'web'],
  },
  {
    id: 'netcat',
    binaries: ['nc', 'netcat'],
    versionArgs: [['-h'], ['--help']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['netcat', 'nc'],
  },
  {
    id: 'qemu',
    binaries: ['qemu-i386', 'qemu-system-i386'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['qemu'],
  },
  {
    id: 'pwntools',
    binaries: ['python3', 'python'],
    versionArgs: [],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['pwntools', 'pwn'],
    pythonModule: 'pwn',
  },
  {
    id: 'ghidra',
    binaries: ['analyzeHeadless'],
    versionArgs: [['-help'], ['--help']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['decompiler'],
  },
  {
    id: 'aapt2',
    binaries: ['aapt2'],
    versionArgs: [['version'], ['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['aapt2', 'android'],
  },
  {
    id: 'go',
    binaries: ['go'],
    versionArgs: [['version']],
    versionRe: /go(\d+\.\d+(?:\.\d+)?)/i,
    provides: ['go'],
  },
  {
    id: 'semgrep',
    binaries: ['semgrep'],
    versionArgs: [['--version']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['semgrep'],
  },
  {
    id: 'hashcat',
    binaries: ['hashcat'],
    versionArgs: [['--version'], ['-V']],
    versionRe: /v?(\d+\.\d+(?:\.\d+)?)/,
    provides: ['hashcat'],
  },
  {
    id: 'ida',
    binaries: ['ida64', 'ida', 'idat64', 'idat'],
    versionArgs: [['-version'], ['--version'], ['-h']],
    versionRe: /(\d+\.\d+(?:\.\d+)?)/,
    provides: ['ida', 'reverse'],
  },
];


export const CAPABILITY_GROUPS: Record<string, string[]> = {
  pwn: ['pwntools', 'gdb', 'checksec', 'patchelf', 'one_gadget', 'ropper'],
  reverse: ['ghidra', 'jadx', 'radare2', 'rizin', 'objdump', 'ida', 'idat'],
  web: ['ffuf', 'sqlmap', 'curl'],
  net: ['nmap', 'ncat', 'nc', 'netcat'],
  crypto: ['sage', 'z3', 'gmpy2'],
  forensics: ['binwalk', 'tshark', 'exiftool', 'foremost', 'steghide', 'volatility'],
  java: ['jdk', 'jdk@21', 'jdk@17', 'jdk@11', 'jdk@8'],
  android: ['apktool', 'adb', 'aapt2'],
  misc: ['python', 'gcc', 'docker', 'angr', 'frida', 'node', 'git', '7z', 'openssl', 'file', 'strings', 'readelf', 'smali', 'patchelf', 'powershell'],
};

export function matchesCapability(id: string, capability: string): boolean {
  const base = id.split('@')[0] ?? id;
  return providesFor(id).includes(capability) || (CAPABILITY_GROUPS[capability] ?? []).some((name) => base === name || base.startsWith(`${name}-`) || base.startsWith(`${name}@`)) || id.startsWith(`${capability}@`);
}
export function probeFor(id: string): ProbeDefinition {
  const base = id.split('@')[0] ?? id;
  return PROBE_TABLE.find((entry) => entry.id === base || entry.provides.includes(id)) ?? {
    id: base,
    binaries: [base],
    versionArgs: [['--version'], ['-v'], ['-V'], ['-ver'], ['--help']],
    versionRe: /(\d+(?:\.\d+)+(?:-[A-Za-z0-9]+)?)/,
    provides: [base],
  };
}

export function providesFor(id: string): string[] {
  return probeFor(id).provides;
}
