/**
 * Bounded child-process execution (docs/design.md §4.1, ADR 0002 §1).
 *
 * Owns process spawning, tree termination, stdin validation, and the
 * capture-level artifact cap. Classification and evidence writes stay in
 * exec.
 */
import { Buffer } from 'node:buffer';
import { spawn, type ChildProcess } from 'node:child_process';
import { KernelError } from '../error.js';
import { baseEnv } from '../sysutil.js';
import type { Prepared } from './prepare.js';

export const ARTIFACT_CAP = 64 * 1024 * 1024;
const STDIN_CAP = 1024 * 1024;
const GRACE_MS = 2_000;

/** Rejection before a child process exists; callers may release a reserved
 *  command slot. Once a child has a pid, the execution keeps its slot. */
export class PreSpawnError extends KernelError {
  constructor(code: 'NOT_FOUND' | 'LIMIT', message: string) {
    super(code, message);
    this.name = 'PreSpawnError';
  }
}

export function validateStdin(stdin: string | undefined): void {
  if (stdin !== undefined && Buffer.byteLength(stdin) > STDIN_CAP) {
    throw new PreSpawnError('LIMIT', `stdin exceeds ${STDIN_CAP} bytes`);
  }
}

export interface RawRun {
  exit: number | null;
  signal: string | null;
  timedOut: boolean;
  durationMs: number;
  stdout: Buffer;
  stderr: Buffer;
  outputTruncated: boolean;
}

// ---------------------------------------------------------------------------
// Tree kill: process group on POSIX, taskkill /T on Windows.
// ---------------------------------------------------------------------------

function killTree(pid: number, signal: 'SIGTERM' | 'SIGKILL'): void {
  if (process.platform === 'win32') {
    spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-pid, signal);
    } catch {
      try {
        process.kill(pid, signal);
      } catch {
        /* already gone */
      }
    }
  }
}

export function runRaw(prep: Prepared, timeoutMs: number, stdin: string | undefined): Promise<RawRun> {
  // Validate stdin BEFORE spawning so an oversized input never leaves an
  // orphan child (review R10).
  validateStdin(stdin);
  const { promise, resolve, reject } = Promise.withResolvers<RawRun>();
    const started = Date.now();
    let child: ChildProcess;
    try {
      child = spawn(prep.argv[0], prep.argv.slice(1), {
        cwd: prep.cwd,
        env: { ...baseEnv(), ...prep.env },
        detached: process.platform !== 'win32',
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (err) {
      reject(new PreSpawnError('NOT_FOUND', `spawn failed: ${err instanceof Error ? err.message : String(err)}`));
      return promise;
    }
    let timedOut = false;
    let settled = false;
    // Chunk arrays: concat once at the end (review R10).
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let total = 0;
    let outputTruncated = false;

    const capture = (buf: Buffer, which: 'out' | 'err') => {
      if (total >= ARTIFACT_CAP) {
        outputTruncated = true;
        return;
      }
      const room = ARTIFACT_CAP - total;
      const slice = buf.subarray(0, room);
      total += slice.length;
      if (which === 'out') outChunks.push(slice);
      else errChunks.push(slice);
    };

    child.stdout?.on('data', (d: Buffer) => capture(d, 'out'));
    child.stderr?.on('data', (d: Buffer) => capture(d, 'err'));
    // Pipe errors (EPIPE when the child exits early) must not crash the kernel.
    child.stdout?.on('error', () => {});
    child.stderr?.on('error', () => {});
    child.stdin?.on('error', () => {});

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      killTree(child.pid ?? 0, 'SIGTERM');
      setTimeout(() => {
        if (!settled && child.exitCode === null) killTree(child.pid ?? 0, 'SIGKILL');
      }, GRACE_MS).unref();
    }, timeoutMs);

    if (stdin !== undefined) {
      child.stdin?.write(stdin);
    }
    child.stdin?.end();

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(child.pid === undefined
        ? new PreSpawnError('NOT_FOUND', `spawn failed: ${err.message}`)
        : new KernelError('NOT_FOUND', `spawn failed: ${err.message}`));
    });

    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exit: code,
        signal: signal ?? null,
        timedOut,
        durationMs: Date.now() - started,
        stdout: Buffer.concat(outChunks),
        stderr: Buffer.concat(errChunks),
        outputTruncated,
      });
    });
  return promise;
}
