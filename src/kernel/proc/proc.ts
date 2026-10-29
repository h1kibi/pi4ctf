/**
 * Bounded process-observation primitive for live pi4ctf sessions.
 *
 * It is intentionally session-scoped: the model cannot name an arbitrary host
 * PID. Host sessions read /proc/<pid>; docker sessions read PID 1 inside the
 * named container. Output is written to .ctf/artifacts and returned as a
 * bounded excerpt. This is an observation, not a claim or a budget action;
 * use artifact_ingest if it must enter the evidence chain.
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import { atomicWriteFile } from '../fsutil.js';
import { Project } from '../project.js';

export type ProcAction = 'maps' | 'mem' | 'libs';

export interface ProcInput {
  session: string;
  action: ProcAction;
  address?: string | number;
  length?: number;
}

export interface ProcResult {
  session: string;
  action: ProcAction;
  artifact: string;
  rawArtifact?: string;
  bytes: number;
  text: string;
  truncated: boolean;
  source: 'host' | 'docker';
  note: string;
}

const SESSION_RE = /^s\d{4}$/;
const CONTAINER_RE = /^pi4ctf-s\d{4}-[0-9a-f]{8}$/;
const MAX_MAPS_BYTES = 1024 * 1024;
const MAX_MEM_BYTES = 16 * 1024;
const MAX_DOCKER_BUFFER = 2 * 1024 * 1024;

interface SessionStateFile {
  id: string;
  pid?: number;
  container?: string;
  closed?: boolean;
}

function readState(project: Project, session: string): SessionStateFile {
  if (!SESSION_RE.test(session)) throw new KernelError('INVALID_REQUEST', 'session must look like s0001');
  const p = path.join(project.ctfDir, 'sessions', `${session}.json`);
  if (!fs.existsSync(p)) throw new KernelError('NOT_FOUND', `session ${session} not found`);
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')) as SessionStateFile;
  } catch {
    throw new KernelError('INTERNAL', `unreadable session state: ${session}`);
  }
}

function parseAddress(value: string | number | undefined): number {
  if (value === undefined) throw new KernelError('INVALID_REQUEST', 'mem requires address');
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new KernelError('INVALID_REQUEST', 'address must be a positive safe integer (decimal or 0x...)');
  }
  return n;
}

function uniqueLibs(maps: string): string[] {
  const out = new Set<string>();
  for (const line of maps.split(/\r?\n/)) {
    const m = /^[0-9a-f]+-[0-9a-f]+\s+\S+\s+\S+\s+\S+\s+\d+\s+(.+)$/i.exec(line);
    const file = m?.[1]?.trim().split(/\s+\(deleted\)$/)[0];
    if (!file || !file.startsWith('/') || file.startsWith('/dev/')) continue;
    out.add(file);
  }
  return [...out].sort();
}

function hexDump(buf: Buffer, base: number): string {
  const lines: string[] = [];
  for (let i = 0; i < buf.length; i += 16) {
    const chunk = buf.subarray(i, i + 16);
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...chunk].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(base + i).toString(16).padStart(12, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join('\n');
}

function hostRead(state: SessionStateFile, action: ProcAction, address: number, length: number): { buf: Buffer; raw?: Buffer; text: string } {
  if (process.platform !== 'linux') {
    throw new KernelError('UNSUPPORTED', 'proc reads require Linux host sessions (or a docker session)');
  }
  if (!state.pid || state.closed) throw new KernelError('CONFLICT', `session ${state.id} is not live`);
  if (action === 'maps' || action === 'libs') {
    let text: string;
    try {
      text = fs.readFileSync(`/proc/${state.pid}/maps`, 'utf8');
    } catch (err) {
      throw new KernelError('NOT_FOUND', `cannot read /proc/${state.pid}/maps: ${err instanceof Error ? err.message : String(err)}`);
    }
    return { buf: Buffer.from(text), text };
  }
  try {
    const fd = fs.openSync(`/proc/${state.pid}/mem`, 'r');
    try {
      const buf = Buffer.alloc(length);
      const n = fs.readSync(fd, buf, 0, length, address);
      const raw = buf.subarray(0, n);
      return { buf: raw, raw, text: hexDump(raw, address) };
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    throw new KernelError(
      'NOT_FOUND',
      `cannot read /proc/${state.pid}/mem at 0x${address.toString(16)}: ${err instanceof Error ? err.message : String(err)}; ` +
        'host reads may require kernel.yama.ptrace_scope=0 (or use the docker backend)',
    );
  }
}

function dockerRead(state: SessionStateFile, action: ProcAction, address: number, length: number): { buf: Buffer; raw?: Buffer; text: string } {
  if (!state.container || !CONTAINER_RE.test(state.container)) {
    throw new KernelError('UNSUPPORTED', 'docker session has no tracked container');
  }
  if (state.closed) throw new KernelError('CONFLICT', `session ${state.id} is not live`);
  if (action === 'maps' || action === 'libs') {
    const res = spawnSync('docker', ['exec', state.container, 'cat', '/proc/1/maps'], {
      encoding: null,
      maxBuffer: MAX_DOCKER_BUFFER,
      windowsHide: true,
    });
    if (res.status !== 0 || !res.stdout) {
      throw new KernelError('NOT_FOUND', `docker exec maps failed: ${res.stderr?.toString('utf8').slice(0, 800) || 'no output'}`);
    }
    const text = res.stdout.toString('utf8');
    return { buf: res.stdout, text };
  }
  const script = [
    'import sys',
    'f=open("/proc/1/mem","rb",buffering=0)',
    'f.seek(int(sys.argv[1]))',
    'sys.stdout.buffer.write(f.read(int(sys.argv[2])))',
  ].join(';');
  const res = spawnSync('docker', ['exec', state.container, 'python3', '-c', script, String(address), String(length)], {
    encoding: null,
    maxBuffer: MAX_DOCKER_BUFFER,
    windowsHide: true,
  });
  if (res.status !== 0 || !res.stdout) {
    throw new KernelError('NOT_FOUND', `docker exec mem failed: ${res.stderr?.toString('utf8').slice(0, 800) || 'no output'}`);
  }
  const raw = res.stdout;
  return { buf: raw, raw, text: hexDump(raw, address) };
}

export function readProcess(project: Project, input: ProcInput): ProcResult {
  const action = input.action;
  if (action !== 'maps' && action !== 'mem' && action !== 'libs') {
    throw new KernelError('INVALID_REQUEST', 'proc action must be maps | mem | libs');
  }
  const length = Math.min(MAX_MEM_BYTES, Math.max(1, Math.floor(input.length ?? 256)));
  const address = action === 'mem' ? parseAddress(input.address) : 0;
  const state = readState(project, input.session);
  const source: 'host' | 'docker' = state.container ? 'docker' : 'host';
  const read = source === 'docker' ? dockerRead(state, action, address, length) : hostRead(state, action, address, length);
  if (read.buf.length > MAX_MAPS_BYTES && action !== 'mem') {
    throw new KernelError('LIMIT', `proc ${action} output exceeds ${MAX_MAPS_BYTES} bytes`);
  }
  let text = read.text;
  if (action === 'libs') text = uniqueLibs(read.text).join('\n');
  const shaped = Buffer.from(text);
  const ref = `artifacts/proc-${state.id}-${action}.log`;
  atomicWriteFile(path.join(project.ctfDir, ref), shaped);
  let rawArtifact: string | undefined;
  if (read.raw) {
    rawArtifact = `artifacts/proc-${state.id}-${action}.raw.log`;
    atomicWriteFile(path.join(project.ctfDir, rawArtifact), read.raw);
  }
  project.appendEvent('proc.read', 'model', {
    session: state.id,
    action,
    source,
    bytes: read.raw?.length ?? read.buf.length,
    address: action === 'mem' ? address : null,
    length: action === 'mem' ? length : null,
  });
  const excerpt = text.length > 16 * 1024 ? text.slice(0, 16 * 1024) : text;
  return {
    session: state.id,
    action,
    artifact: ref,
    rawArtifact,
    bytes: read.raw?.length ?? read.buf.length,
    text: excerpt,
    truncated: excerpt.length < text.length,
    source,
    note: 'observation only; use artifact_ingest on the artifact path to put it into the claim/flag chain',
  };
}
