/**
 * Session: persistent interactive process (docs/design.md §5.5).
 *
 * STATUS: pipe by default; an opt-in POSIX PTY (`tty: true`) wraps the command
 * in a small python3 helper that allocates the PTY and disables echo before
 * exec, so the child sees a terminal without its input being duplicated.
 * Windows has no PTY path (pipe-only). Resize is forwarded to tty sessions;
 * pipe sessions only record it. pwn/rev 题在 pipe 模式下不算完成（review R3）。
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

/** Allocate the PTY and disable echo before the child can receive input.
 *  script(1) sets terminal modes only after exec, so early input can echo. */
const PTY_WRAP = [
  'import fcntl,os,pty,select,signal,struct,sys,termios',
  'm,s=pty.openpty()',
  'a=termios.tcgetattr(s)',
  'a[3]&=~termios.ECHO',
  'termios.tcsetattr(s,termios.TCSANOW,a)',
  'def setsize(cols,rows):',
  '    try:',
  '        fcntl.ioctl(m,termios.TIOCSWINSZ,struct.pack("HHHH",rows,cols,0,0))',
  '    except OSError:',
  '        pass',
  'setsize(80,24)',
  'def bye(*_):',
  '    raise SystemExit(0)',
  'signal.signal(signal.SIGTERM,bye)',
  'signal.signal(signal.SIGINT,bye)',
  'pid=os.fork()',
  'if pid==0:',
  '    os.setsid()',
  '    fcntl.ioctl(s,termios.TIOCSCTTY,0)',
  '    os.dup2(s,0)',
  '    os.dup2(s,1)',
  '    os.dup2(s,2)',
  '    os.close(m)',
  '    os.execvp(sys.argv[1],sys.argv[1:])',
  'os.close(s)',
  'def winch(*_):',
  '    p=os.environ.get("PI4CTF_TTY_RESIZE")',
  '    if not p:',
  '        return',
  '    try:',
  '        with open(p) as f:',
  '            c,r=f.read().split()',
  '        setsize(int(c),int(r))',
  '    except (OSError,ValueError):',
  '        pass',
  'signal.signal(signal.SIGWINCH,winch)',
  'def put(fd,data):',
  '    while data:',
  '        n=os.write(fd,data)',
  '        data=data[n:]',
  'try:',
  '    while True:',
  '        r,_,_=select.select([0,m],[],[])',
  '        if 0 in r:',
  '            d=os.read(0,65536)',
  '            if not d:',
  '                break',
  '            put(m,d)',
  '        if m in r:',
  '            try:',
  '                d=os.read(m,65536)',
  '            except OSError:',
  '                break',
  '            if not d:',
  '                break',
  '            put(1,d)',
  'finally:',
  '    try:',
  '        os.killpg(pid,signal.SIGTERM)',
  '    except OSError:',
  '        pass',
  '    try:',
  '        os.waitpid(pid,0)',
  '    except OSError:',
  '        pass',
].join('\n');

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
  /** True when the program runs under a pseudo-terminal wrapper. */
  tty?: boolean;
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

  open(input: { argv: string[]; cwd?: string; tty?: boolean }): SessionState {
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
        'run', '--rm', '-i', ...(input.tty ? ['-t'] : []), '--name', container, '--network', 'bridge', '--cap-add', 'SYS_PTRACE',
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
    const wantsTty = input.tty === true;
    if (wantsTty) {
      if (process.platform === 'win32') {
        throw new KernelError(
          'UNSUPPORTED',
          'tty sessions require a POSIX host; use a scripted approach (pwntools stdin=PTY) or a Docker image with a PTY helper',
        );
      }
      if (!commandExists('python3')) {
        throw new KernelError('UNSUPPORTED', 'tty sessions require python3 on the host to allocate the pseudo-terminal');
      }
      // Allocate the PTY and clear ECHO before exec; canonical mode is kept so
      // shell `read`, gdb and nc still work. Programs that need raw mode set it
      // themselves. Resize is still not forwarded.
      const wrapped = [command, ...commandArgs];
      command = 'python3';
      commandArgs = ['-c', PTY_WRAP, ...wrapped];
      fs.mkdirSync(path.join(this.project.ctfDir, 'sessions'), { recursive: true });
      commandEnv = { ...commandEnv, PI4CTF_TTY_RESIZE: this.resizePath(id) };
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
      pid: !container && !wantsTty && child.pid ? child.pid : undefined,
      container,
      ...(wantsTty ? { tty: true } : {}),
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
    this.project.appendEvent('session.open', 'model', { id, argv: input.argv, tty: wantsTty });
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

  private resizePath(id: string): string {
    return path.join(this.project.ctfDir, 'sessions', `${id}.resize`);
  }

  /** Resize is applied to tty sessions; pipe sessions only record the event. */
  resize(id: string, cols: number, rows: number): void {
    const s = this.get(id);
    const width = Math.min(1000, Math.max(1, Math.floor(cols)));
    const height = Math.min(1000, Math.max(1, Math.floor(rows)));
    let applied = false;
    if (s.state.tty) {
      try {
        fs.writeFileSync(this.resizePath(id), `${width} ${height}`);
        s.child.kill('SIGWINCH');
        applied = true;
      } catch {
        // The wrapper may have exited between the check and the write.
      }
    }
    this.project.appendEvent('session.resize', 'model', { id, cols: width, rows: height, applied });
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
    try {
      fs.rmSync(this.resizePath(id), { force: true });
    } catch {
      /* best effort */
    }
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
