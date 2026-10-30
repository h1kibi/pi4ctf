/**
 * Stateful GDB/MI controller for pwn debugging.
 *
 * One GDB process is kept per debugger session. Commands are serialized and
 * responses are parsed from MI records; prompt scraping is not used. The
 * controller is intentionally small: start/attach, breakpoints, execution
 * control, registers/backtrace/disassembly, memory reads, and a guarded raw
 * command escape hatch.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import * as readline from 'node:readline';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import { resolveInside } from '../fsutil.js';
import { Project } from '../project.js';
import { dockerHostArgs } from '../run/prepare.js';

const MAX_GDB_SESSIONS = 2;
const DEFAULT_TIMEOUT_MS = 30_000;
const GDB_BIN = process.env.PI4CTF_GDB ?? 'gdb';

export interface GdbStop {
  reason: string | null;
  signal: string | null;
  pc: string | null;
  func: string | null;
  file: string | null;
  line: string | null;
}

export interface GdbStartOptions {
  binary?: string;
  cwd?: string;
  args?: string[];
}

export interface GdbState {
  id: string;
  backend: 'host' | 'docker';
  binary: string | null;
  containerBinary: string | null;
  cwd: string;
  containerCwd: string;
  running: boolean;
  closed: boolean;
  lastStop: GdbStop | null;
}

interface GdbReply {
  raw: string[];
  console: string;
  target: string;
  stop: GdbStop | null;
}

interface Waiter {
  resolve: (line: string) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

function unescapeMi(value: string): string {
  const simple: Record<string, string> = {
    n: '\n', t: '\t', r: '\r', '\\': '\\', '"': '"', a: '\x07', b: '\b', f: '\f', v: '\v',
  };
  let out = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== '\\' || i + 1 >= value.length) {
      out += value[i];
      continue;
    }
    const c = value[++i]!;
    if (simple[c] !== undefined) out += simple[c];
    else if (c === 'x' && i + 2 < value.length && /^[0-9a-fA-F]{2}$/.test(value.slice(i + 1, i + 3))) {
      out += String.fromCharCode(parseInt(value.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (/^[0-7]$/.test(c)) {
      let j = i;
      while (j < Math.min(i + 3, value.length) && /^[0-7]$/.test(value[j]!)) j++;
      out += String.fromCharCode(parseInt(value.slice(i, j), 8));
      i = j - 1;
    } else {
      out += `\\${c}`;
    }
  }
  return out;
}

function parseStop(line: string): GdbStop {
  const field = (name: string) => {
    const m = new RegExp(`${name}="((?:[^"\\\\]|\\\\.)*)"`).exec(line);
    return m ? unescapeMi(m[1]!) : null;
  };
  return {
    reason: field('reason'),
    signal: field('signal-name'),
    pc: field('pc'),
    func: field('func'),
    file: field('file'),
    line: field('line'),
  };
}

function parseConsole(raw: string[]): { console: string; target: string; error: string | null } {
  const consoleParts: string[] = [];
  const targetParts: string[] = [];
  let error: string | null = null;
  for (const line of raw) {
    if (line.startsWith('~"') || line.startsWith('&"') || line.startsWith('@"')) {
      const body = line.endsWith('"') ? line.slice(2, -1) : line.slice(2);
      if (line.startsWith('@')) targetParts.push(unescapeMi(body));
      else consoleParts.push(unescapeMi(body));
    } else if (line.startsWith('^error')) {
      const m = /msg="((?:[^"\\]|\\.)*)"/.exec(line);
      error = m ? unescapeMi(m[1]!) : line;
    }
  }
  return {
    console: consoleParts.join(''),
    target: targetParts.join(''),
    error,
  };
}

function parseRegisters(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([a-z][a-z0-9]*)\s+(0x[0-9a-f]+|[0-9]+)\b/i.exec(line);
    if (m) out[m[1]!.toLowerCase()] = m[2]!;
  }
  return out;
}

function hexdump(hex: string, base: number): string {
  const lines: string[] = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const bytes = chunk.match(/../g) ?? [];
    const hexPart = bytes.join(' ').padEnd(47);
    const ascii = bytes.map((b) => {
      const n = parseInt(b, 16);
      return n >= 0x20 && n < 0x7f ? String.fromCharCode(n) : '.';
    }).join('');
    lines.push(`${(base + i / 2).toString(16).padStart(12, '0')}  ${hexPart}  ${ascii}`);
  }
  return lines.join('\n');
}

function quoteArg(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function safeConsole(command: string): void {
  if (command.length > 4096) throw new KernelError('LIMIT', 'gdb command is too long');
  const blocked = /^\s*(?:shell|!|python(?:-interactive)?|source|make|define|document|alias|pipe|dump|append|restore|add-auto-load|set\s+(?:logging|exec-wrapper|auto-load|startup-with-shell))\b/i;
  for (const line of command.split(/\r?\n/)) {
    if (blocked.test(line)) {
      throw new KernelError('SECURITY', 'gdb command can execute outside the debugger; use an allowed command');
    }
  }
}

function resolvePath(project: Project, value: string): { host: string; container: string } {
  const normalized = value.replace(/\\/g, '/');
  if (normalized === 'workspace' || normalized.startsWith('workspace/')) {
    const rest = normalized.slice('workspace'.length).replace(/^\/+/, '');
    const host = rest ? resolveInside(project.workspace, rest) : project.workspace;
    return { host, container: `/challenge/workspace${rest ? `/${rest}` : ''}` };
  }
  const host = resolveInside(project.root, value);
  const rel = path.relative(project.root, host).split(path.sep).join('/');
  return { host, container: `/challenge${rel ? `/${rel}` : ''}` };
}

function resolveCwd(project: Project, cwd: string | undefined, backend: 'host' | 'docker'): { host: string; container: string } {
  if (!cwd) {
    return {
      host: project.root,
      container: backend === 'docker' ? '/challenge/workspace' : project.root,
    };
  }
  const resolved = resolvePath(project, cwd);
  return { host: resolved.host, container: backend === 'docker' ? resolved.container : resolved.host };
}

export class GdbSession {
  readonly id: string;
  readonly backend: 'host' | 'docker';
  readonly binary: string | null;
  readonly containerBinary: string | null;
  readonly cwd: string;
  readonly containerCwd: string;
  lastStop: GdbStop | null = null;
  running = false;
  private closed = false;
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly rl: readline.Interface;
  private readonly queue: string[] = [];
  private readonly waiters: Waiter[] = [];
  private tail: Promise<unknown> = Promise.resolve();
  private stderr = '';
  private readonly timeoutMs: number;

  private constructor(
    project: Project,
    id: string,
    child: ChildProcessWithoutNullStreams,
    paths: { binary: string | null; containerBinary: string | null; cwd: string; containerCwd: string },
  ) {
    this.id = id;
    this.backend = project.file().backend;
    this.binary = paths.binary;
    this.containerBinary = paths.containerBinary;
    this.cwd = paths.cwd;
    this.containerCwd = paths.containerCwd;
    this.timeoutMs = DEFAULT_TIMEOUT_MS;
    this.child = child;
    this.rl = readline.createInterface({ input: child.stdout });
    this.rl.on('line', (line) => this.onLine(line));
    child.stderr.on('data', (chunk: Buffer) => {
      this.stderr += chunk.toString('utf8');
      if (this.stderr.length > 8000) this.stderr = this.stderr.slice(-8000);
    });
    child.stdin.on('error', () => {});
    child.stdout.on('error', () => {});
    child.stderr.on('error', () => {});
    child.on('error', (err) => this.fail(new Error(`gdb spawn failed: ${err.message}`)));
    child.on('close', () => this.fail(new Error(`gdb exited${this.stderr ? `: ${this.stderr}` : ''}`)));
  }

  static async start(
    project: Project,
    id: string,
    options: GdbStartOptions,
  ): Promise<GdbSession> {
    const file = project.file();
    const backend = file.backend;
    const cwd = resolveCwd(project, options.cwd, backend);
    const binary = options.binary ? resolvePath(project, options.binary) : null;
    const gdbArgs = [
      '--interpreter=mi2',
      '--quiet',
      // Do not execute arbitrary .gdbinit files from the challenge/workspace.
      '--nx',
      ...(binary ? [backend === 'docker' ? binary.container : binary.host] : []),
    ];
    let child: ChildProcessWithoutNullStreams;
    if (backend === 'docker') {
      if (!file.dockerImage) {
        throw new KernelError('UNSUPPORTED', 'docker backend requires dockerImage in project.json');
      }
      child = spawn('docker', [
        'run',
        '--rm',
        '-i',
        '--cap-add',
        'SYS_PTRACE',
        '--network',
        'bridge',
        ...dockerHostArgs(),
        '--entrypoint',
        GDB_BIN,
        '-e',
        'TERM=dumb',
        '-v',
        `${project.root}:/challenge:ro`,
        '-v',
        `${project.workspace}:/challenge/workspace:rw`,
        '-w',
        cwd.container,
        file.dockerImage,
        ...gdbArgs,
      ], {
        cwd: project.root,
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      }) as ChildProcessWithoutNullStreams;
    } else {
      child = spawn(GDB_BIN, gdbArgs, {
        cwd: cwd.host,
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      }) as ChildProcessWithoutNullStreams;
    }
    const session = new GdbSession(project, id, child, {
      binary: binary?.host ?? null,
      containerBinary: binary?.container ?? null,
      cwd: cwd.host,
      containerCwd: cwd.container,
    });
    try {
      await session.ready();
      if (options.args && options.args.length > 0) {
        await session.console(`set args ${options.args.map(quoteArg).join(' ')}`);
      }
      return session;
    } catch (err) {
      session.close();
      throw err;
    }
  }

  private onLine(line: string): void {
    const waiter = this.waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(line);
    } else {
      this.queue.push(line);
    }
  }

  private fail(err: Error): void {
    this.closed = true;
    const pending = this.waiters.splice(0);
    for (const waiter of pending) {
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
  }

  private nextLine(timeoutMs = this.timeoutMs): Promise<string> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.closed) return Promise.reject(new Error('gdb session is closed'));
    const { promise, resolve, reject } = Promise.withResolvers<string>();
    const timer = setTimeout(() => {
      const idx = this.waiters.findIndex((waiter) => waiter.timer === timer);
      if (idx >= 0) this.waiters.splice(idx, 1);
      reject(new KernelError('TIMEOUT', `gdb did not return within ${timeoutMs}ms${this.stderr ? `: ${this.stderr.slice(-800)}` : ''}`));
    }, timeoutMs);
    timer.unref?.();
    this.waiters.push({ resolve, reject, timer });
    return promise;
  }

  private async ready(): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const line = await this.nextLine(10_000);
      if (line === '(gdb)' || line.startsWith('(gdb)')) break;
    }
    await this.request('-gdb-set pagination off');
    await this.request('-gdb-set confirm off');
  }

  private request(command: string, timeoutMs = this.timeoutMs): Promise<GdbReply> {
    const next = this.tail.then(() => this.requestInner(command, timeoutMs));
    this.tail = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async requestInner(command: string, timeoutMs: number): Promise<GdbReply> {
    if (this.closed) throw new KernelError('CONFLICT', 'gdb session is closed');
    this.child.stdin.write(`${command}\n`);
    const raw: string[] = [];
    let sawRunning = false;
    let sawStop = false;
    let stop: GdbStop | null = null;
    for (;;) {
      const line = await this.nextLine(timeoutMs);
      raw.push(line);
      if (line.startsWith('^running') || line.startsWith('*running')) sawRunning = true;
      if (line.startsWith('*stopped')) {
        sawStop = true;
        stop = parseStop(line);
        this.lastStop = stop;
      }
      if (line === '(gdb)' || line.startsWith('(gdb)')) {
        if (sawRunning && !sawStop) continue;
        break;
      }
    }
    const parsed = parseConsole(raw);
    if (parsed.error) throw new KernelError('CONFLICT', `gdb: ${parsed.error}`);
    return { raw, console: parsed.console, target: parsed.target, stop };
  }

  private async console(command: string): Promise<string> {
    const reply = await this.request(`-interpreter-exec console ${JSON.stringify(command)}`);
    return reply.console;
  }

  private state(): GdbState {
    return {
      id: this.id,
      backend: this.backend,
      binary: this.binary,
      containerBinary: this.containerBinary,
      cwd: this.cwd,
      containerCwd: this.containerCwd,
      running: this.running,
      closed: this.closed,
      lastStop: this.lastStop,
    };
  }

  status(): GdbState {
    return this.state();
  }

  async break(location: string, condition?: string): Promise<Record<string, unknown>> {
    if (!location || /[\r\n]/.test(location) || location.length > 512) {
      throw new KernelError('INVALID_REQUEST', 'invalid breakpoint location');
    }
    const inserted = await this.request(`-break-insert ${location}`);
    if (condition) {
      if (/[\r\n]/.test(condition) || condition.length > 1024) {
        throw new KernelError('INVALID_REQUEST', 'invalid breakpoint condition');
      }
      const number = /bkpt=\{number="(\d+)"/.exec(inserted.raw.join('\n'))?.[1];
      if (!number) throw new KernelError('INTERNAL', 'gdb did not return a breakpoint number');
      await this.request(`-break-condition ${number} ${condition}`);
    }
    return { stop: inserted.stop, output: inserted.console, breakpoints: await this.listBreakpoints() };
  }

  async listBreakpoints(): Promise<string> {
    return this.console('info breakpoints');
  }

  async deleteBreakpoint(number?: number): Promise<Record<string, unknown>> {
    if (number !== undefined && (!Number.isInteger(number) || number < 1)) {
      throw new KernelError('INVALID_REQUEST', 'breakpoint number must be a positive integer');
    }
    const reply = await this.request(number ? `-break-delete ${number}` : '-break-delete');
    return { output: reply.console };
  }

  async attach(pid: number): Promise<Record<string, unknown>> {
    if (!Number.isInteger(pid) || pid < 1) throw new KernelError('INVALID_REQUEST', 'pid must be a positive integer');
    const reply = await this.request(`-target-attach ${pid}`);
    this.lastStop = reply.stop ?? this.lastStop;
    return { stop: reply.stop, output: reply.console, state: this.state() };
  }

  private async exec(command: string): Promise<Record<string, unknown>> {
    this.running = true;
    try {
      const reply = await this.request(command);
      return {
        stop: reply.stop,
        output: reply.console,
        target: reply.target,
        state: this.state(),
      };
    } finally {
      this.running = false;
    }
  }

  async run(): Promise<Record<string, unknown>> {
    return this.exec('-exec-run');
  }

  async continue(): Promise<Record<string, unknown>> {
    return this.exec('-exec-continue');
  }

  async step(kind: 'step' | 'next' | 'stepi' | 'nexti' | 'finish'): Promise<Record<string, unknown>> {
    const command: Record<typeof kind, string> = {
      step: '-exec-step',
      next: '-exec-next',
      stepi: '-exec-step-instruction',
      nexti: '-exec-next-instruction',
      finish: '-exec-finish',
    };
    return this.exec(command[kind]);
  }

  interrupt(): void {
    if (this.closed) return;
    this.child.stdin.write('-exec-interrupt\n');
  }

  async regs(): Promise<Record<string, unknown>> {
    const text = await this.console('info registers');
    return { registers: parseRegisters(text), text };
  }

  async backtrace(): Promise<Record<string, unknown>> {
    const text = await this.console('bt 12');
    return { text };
  }

  async stack(): Promise<Record<string, unknown>> {
    const text = await this.console('x/16gx $rsp');
    return { text };
  }

  async mem(address: string, length: number): Promise<Record<string, unknown>> {
    if (!address || /[\r\n]/.test(address)) throw new KernelError('INVALID_REQUEST', 'invalid gdb address');
    if (!Number.isInteger(length) || length < 1 || length > 16 * 1024) {
      throw new KernelError('LIMIT', 'memory length must be 1..16384');
    }
    const reply = await this.request(`-data-read-memory-bytes ${address} ${length}`);
    const contents = /contents="([0-9a-fA-F]*)"/.exec(reply.raw.join('\n'))?.[1] ?? '';
    return {
      address,
      bytes: contents.length / 2,
      hex: contents,
      text: hexdump(contents, Number.parseInt(address, 0) || 0),
    };
  }

  async raw(command: string): Promise<Record<string, unknown>> {
    safeConsole(command);
    const output = await this.console(command);
    return { output };
  }

  async context(): Promise<Record<string, unknown>> {
    const regs = await this.regs();
    const bt = await this.backtrace();
    const disasm = await this.console('x/8i $pc');
    return {
      stop: this.lastStop,
      registers: regs.registers,
      registerText: regs.text,
      backtrace: bt.text,
      disassembly: disasm,
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.child.stdin.write('-gdb-exit\n');
    } catch {
      /* already gone */
    }
    try {
      this.child.kill();
    } catch {
      /* already gone */
    }
    this.rl.close();
    this.fail(new Error('gdb session closed'));
  }
}

export class GdbManager {
  private readonly sessions = new Map<string, GdbSession>();
  private seq = 0;

  constructor(private readonly project: Project) {}

  async start(options: GdbStartOptions = {}): Promise<GdbSession> {
    if (this.sessions.size >= MAX_GDB_SESSIONS) {
      throw new KernelError('LIMIT', `max ${MAX_GDB_SESSIONS} gdb sessions`);
    }
    const id = `g${String(++this.seq).padStart(4, '0')}`;
    const session = await GdbSession.start(this.project, id, options);
    this.sessions.set(id, session);
    return session;
  }

  get(id: string): GdbSession {
    if (!/^g\d{4}$/.test(id)) throw new KernelError('INVALID_REQUEST', 'gdb session must look like g0001');
    const session = this.sessions.get(id);
    if (!session) throw new KernelError('NOT_FOUND', `gdb session ${id} not open`);
    return session;
  }

  list(): GdbState[] {
    return [...this.sessions.values()].map((session) => session.status());
  }

  close(id: string): Record<string, unknown> {
    const session = this.get(id);
    session.close();
    this.sessions.delete(id);
    return { id, closed: true };
  }

  closeAll(): void {
    for (const session of this.sessions.values()) session.close();
    this.sessions.clear();
  }
}
