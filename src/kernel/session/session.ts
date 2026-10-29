/**
 * Session: persistent interactive process (docs/design.md §5.5).
 *
 * STATUS: pipe-only walking skeleton — true PTY (ConPTY/Unix PTY) is a W2/Rust
 * deliverable; resize is recorded but is a no-op on pipes. pwn/rev 题在 pipe
 * 模式下不算完成（review R3）。
 *
 * Hardened per review C3/C4/C5/R5/R9/R10:
 *   - spawn errors surface as NOT_FOUND instead of crashing the server;
 *   - env uses the shared allowlist (no host env leak);
 *   - buffers are chunk arrays (no O(n^2) concat per data event);
 *   - read() is async and never blocks the event loop;
 *   - state files are written atomically.
 */
import { Buffer } from 'node:buffer';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import { baseEnv, commandExists } from '../sysutil.js';
import { shape } from '../shape/shape.js';

const MAX_SESSIONS = 4;
const READ_CHUNK = 64 * 1024;
const READ_QUIET_MS = 150;

interface SessionState {
  id: string;
  argv: string[];
  startedAt: number;
  seq: number;
  closed: boolean;
  artifact: string;
  /** Host child PID (host backend); absent for docker/Windows. */
  pid?: number;
  /** Docker container name (docker backend); used by proc reads. */
  container?: string;
}

interface LiveSession {
  state: SessionState;
  child: ChildProcessWithoutNullStreams;
  chunks: Buffer[];
  total: number;
  /** Bytes already delivered by reads. */
  delivered: number;
  spawnError: string | null;
  lastGrow: number;
}

export interface SessionReadResult {
  seq: number;
  data: string;
  enc: 'utf8' | 'base64';
  exited: boolean;
}

export class SessionManager {
  private readonly live = new Map<string, LiveSession>();

  constructor(private readonly project: Project) {}

  open(input: { argv: string[]; cwd?: string }): SessionState {
    if (this.live.size >= MAX_SESSIONS) {
      throw new KernelError('LIMIT', `max ${MAX_SESSIONS} sessions`);
    }
    if (!input.argv || input.argv.length === 0) {
      throw new KernelError('INVALID_REQUEST', 'argv required');
    }
    const file = this.project.file();
    const { id } = this.project.allocId('session');
    const program = input.argv[0];
    let command = program;
    let commandArgs = input.argv.slice(1);
    let commandEnv: NodeJS.ProcessEnv = { ...baseEnv(), CTF_PROJECT: this.project.root };
    let container: string | undefined;
    if (file.backend === 'docker') {
      if (!file.dockerImage) {
        throw new KernelError('UNSUPPORTED', 'docker backend requires dockerImage in project.json');
      }
      const workspace = path.join(this.project.root, 'workspace');
      fs.mkdirSync(workspace, { recursive: true });
      command = 'docker';
      container = `pi4ctf-${id}-${sha256(this.project.root).slice(0, 8)}`;
      commandArgs = [
        'run', '--rm', '-i', '--name', container, '--network', 'bridge', '--cap-add', 'SYS_PTRACE',
        '-e', 'TERM=xterm', '-e', 'PYTHONUNBUFFERED=1',
        '-v', `${this.project.root}:/challenge:ro`,
        '-v', `${workspace}:/challenge/workspace:rw`,
        '-w', '/challenge/workspace',
        file.dockerImage,
        ...input.argv,
      ];
      commandEnv = baseEnv();
    } else if (!commandExists(program)) {
      // Fail fast on unknown host binaries (review C3).
      throw new KernelError('NOT_FOUND', `session program not found: ${program}`);
    }
    const artifact = `artifacts/session-${id}.log`;
    const child = spawn(command, commandArgs, {
      cwd: this.project.root,
      env: commandEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams;
    const state: SessionState = {
      id,
      argv: input.argv,
      startedAt: Date.now(),
      seq: 0,
      closed: false,
      artifact,
      pid: !container && child.pid ? child.pid : undefined,
      container,
    };
    const session: LiveSession = {
      state,
      child,
      chunks: [],
      total: 0,
      delivered: 0,
      spawnError: null,
      lastGrow: Date.now(),
    };
    const append = (chunk: Buffer) => {
      session.chunks.push(chunk);
      session.total += chunk.length;
      session.lastGrow = Date.now();
      try {
        fs.appendFileSync(path.join(this.project.ctfDir, artifact), chunk);
      } catch {
        /* project dir removed during shutdown; buffer keeps the data */
      }
    };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    // Pipe/spawn errors (EPIPE, ENOENT) must never crash the session server.
    child.stdout.on('error', () => {});
    child.stderr.on('error', () => {});
    child.stdin.on('error', () => {});
    child.on('error', (err) => {
      session.spawnError = err.message;
      session.state.closed = true;
      this.live.delete(id);
    });
    child.on('close', () => {
      state.closed = true;
    });
    this.live.set(id, session);
    this.persistState(state);
    this.project.appendEvent('session.open', 'model', { id, argv: input.argv });
    return state;
  }

  write(id: string, data: string): void {
    const s = this.get(id);
    if (s.state.closed) throw new KernelError('CONFLICT', `session ${id} exited`);
    s.child.stdin.write(data);
    this.project.appendEvent('session.write', 'model', { id, bytes: data.length });
  }

  /** Incremental read: only bytes after the last delivered offset. Async —
   *  never blocks the event loop (review R9). Resolves after a quiet window
   *  (150ms of no new data), on exit, or at the timeout. */
  read(id: string, timeoutMs = 1000): Promise<SessionReadResult> {
    const s = this.get(id);
    const deadline = Date.now() + Math.min(Math.max(timeoutMs, 0), 10_000);
    return new Promise((resolve) => {
      const poll = () => {
        const hasFresh = s.total > s.delivered;
        const quiet = Date.now() - s.lastGrow >= READ_QUIET_MS;
        const timedOut = Date.now() >= deadline;
        if ((hasFresh && quiet) || (s.state.closed && hasFresh) || timedOut) {
          const snapshot = Buffer.concat(s.chunks);
          const fresh = snapshot.subarray(s.delivered, s.delivered + READ_CHUNK);
          s.delivered += fresh.length;
          s.state.seq += 1;
          this.persistState(s.state);
          const isText = !fresh.includes(0);
          resolve({
            seq: s.state.seq,
            data: isText ? fresh.toString('utf8') : fresh.toString('base64'),
            enc: isText ? 'utf8' : 'base64',
            exited: s.state.closed,
          });
          return;
        }
        setTimeout(poll, 50);
      };
      poll();
    });
  }

  /** Accepted for contract compatibility; pipes cannot resize. */
  resize(id: string, cols: number, rows: number): void {
    this.get(id);
    this.project.appendEvent('session.resize', 'model', { id, cols, rows });
  }

  close(id: string): { exited: boolean } {
    const s = this.get(id);
    try {
      s.child.stdin.end();
      s.child.kill('SIGTERM');
      if (process.platform === 'win32') {
        spawn('taskkill', ['/PID', String(s.child.pid ?? 0), '/T', '/F'], { stdio: 'ignore' });
      } else if (s.child.pid) {
        try {
          process.kill(-s.child.pid, 'SIGTERM');
        } catch {
          /* already gone */
        }
      }
    } catch {
      /* already gone */
    }
    s.state.closed = true;
    this.persistState(s.state);
    this.live.delete(id);
    this.project.appendEvent('session.close', 'model', { id });
    return { exited: true };
  }

  /** Shape the session transcript for observation use. */
  shapeTranscript(id: string): string {
    const s = this.get(id);
    return shape(Buffer.concat(s.chunks)).shaped;
  }

  /** Kill all live sessions (stdin EOF / shutdown semantics). */
  closeAll(): void {
    for (const id of [...this.live.keys()]) this.close(id);
  }

  private persistState(state: SessionState): void {
    atomicWriteFile(
      path.join(this.project.ctfDir, `sessions/${state.id}.json`),
      JSON.stringify(state, null, 2),
    );
  }

  private get(id: string): LiveSession {
    const s = this.live.get(id);
    if (!s) throw new KernelError('NOT_FOUND', `session ${id} not open`);
    if (s.spawnError) {
      throw new KernelError('NOT_FOUND', `session ${id} failed to start: ${s.spawnError}`);
    }
    return s;
  }
}
