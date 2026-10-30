#!/usr/bin/env node
/**
 * rt — pi4ctf kernel CLI (TS walking skeleton).
 *
 *   rt < input.json           one-shot JSON protocol (kernel-design §4.1)
 *   rt --op project.status --root /path/to/challenge
 *   rt --session              JSON-lines session server (4 verbs' session leg)
 *
 * stdout carries exactly one JSON object in one-shot mode; diagnostics go to
 * stderr. Exit codes follow the kernel error table.
 */
import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { assertCaseBudget, dispatch, type Request } from './adapter/protocol.js';
import { Project } from './kernel/project.js';
import { SessionManager } from './kernel/session/session.js';
import { GdbManager } from './kernel/gdb/gdb.js';
import { EXIT_CODES, KernelError } from './kernel/error.js';
import { checkRunScope } from './kernel/security.js';

async function main(): Promise<number> {
  const args = process.argv.slice(2);

  if (args.includes('--session')) {
    await runSessionServer();
    return 0;
  }

  let req: Request;
  const opIdx = args.indexOf('--op');
  if (opIdx >= 0) {
    const op = args[opIdx + 1];
    const rootIdx = args.indexOf('--root');
    const root = rootIdx >= 0 ? args[rootIdx + 1] : undefined;
    const inputFileIdx = args.indexOf('--input-file');
    const inputIdx = args.indexOf('--input');
    let input: Record<string, unknown> = {};
    if (inputFileIdx >= 0) {
      const file = args[inputFileIdx + 1];
      if (!file) {
        process.stderr.write('--input-file requires a path\n');
        return EXIT_CODES.INVALID_REQUEST;
      }
      input = file === '-'
        ? JSON.parse(fs.readFileSync(0, 'utf8'))
        : JSON.parse(fs.readFileSync(file, 'utf8'));
    } else if (inputIdx >= 0) {
      input = JSON.parse(args[inputIdx + 1]);
    }
    req = { op, root, input };
  } else {
    const raw = fs.readFileSync(0, 'utf8');
    req = JSON.parse(raw) as Request;
  }
  if (!req || typeof req.op !== 'string') {
    process.stderr.write('request must be {"op": "...", "root": "...", "input": {...}}\n');
    return EXIT_CODES.INVALID_REQUEST;
  }
  const response = await dispatch(req);
  process.stdout.write(JSON.stringify(response) + '\n');
  if (!response.ok) return EXIT_CODES[response.error.code];
  return 0;
}

/** JSON-lines session server: {"op":"open|write|read|resize|close",...}
 *
 * Session managers are cached per project root (review C4): the 4-session
 * cap is enforced per case across the whole server lifetime, not per open. */
async function runSessionServer(): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin });
  const byRoot = new Map<string, SessionManager>();
  const bySession = new Map<string, { mgr: SessionManager; root: string }>();
  const byGdbRoot = new Map<string, GdbManager>();

  rl.on('line', (line) => {
    void (async () => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line);
      } catch {
        process.stdout.write(JSON.stringify({ ok: false, error: { code: 'INVALID_REQUEST', message: 'bad JSON line' } }) + '\n');
        return;
      }
      try {
        const out = await handleSessionLine(byRoot, bySession, byGdbRoot, msg);
        process.stdout.write(JSON.stringify(out) + '\n');
      } catch (err) {
        const ker = err instanceof KernelError ? err : new KernelError('INTERNAL', String(err));
        process.stdout.write(JSON.stringify({ ok: false, id: msg.id ?? null, error: { code: ker.code, message: ker.message } }) + '\n');
      }
    })();
  });

  await new Promise<void>((resolve) => rl.on('close', resolve));
  for (const mgr of byRoot.values()) mgr.closeAll();
  for (const mgr of byGdbRoot.values()) mgr.closeAll();
}

async function handleSessionLine(
  byRoot: Map<string, SessionManager>,
  bySession: Map<string, { mgr: SessionManager; root: string }>,
  byGdbRoot: Map<string, GdbManager>,
  msg: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const op = String(msg.op ?? '');
  const root = String(msg.root ?? '');
  const id = msg.id ? String(msg.id) : null;
  if (op === 'gdb') return handleGdbLine(byGdbRoot, msg);
  if (op === 'open') {
    if (!root) throw new KernelError('INVALID_REQUEST', 'root is required');
    const project = Project.open(root);
    const argv = (msg.argv as string[]) ?? [];
    const cwd = typeof msg.cwd === 'string' ? msg.cwd : undefined;
    // Goal contract applies to session targets too (ADR 0003 §3).
    checkRunScope(project, argv);
    let mgr = byRoot.get(project.root);
    if (!mgr) {
      mgr = new SessionManager(project);
      byRoot.set(project.root, mgr);
    }
    assertCaseBudget(project);
    const state = mgr.open({ argv, tty: msg.tty === true, cwd });
    // A session is one long-running command; its I/O is not charged per
    // keystroke. Counting the open prevents a post-budget session bypass.
    try {
      project.reserveCommand();
    } catch (err) {
      mgr.close(state.id);
      throw err;
    }
    bySession.set(state.id, { mgr, root });
    return { ok: true, id: state.id, artifact: state.artifact, exited: false };
  }
  if (!id) throw new KernelError('INVALID_REQUEST', 'id is required');
  const entry = bySession.get(id);
  if (!entry) throw new KernelError('NOT_FOUND', `session ${id} not open`);
  const { mgr } = entry;
  switch (op) {
    case 'write':
      // write is data, not a command target; scope was checked at open.
      mgr.write(id, String(msg.data ?? ''));
      return { ok: true, id };
    case 'read': {
      const out = await mgr.read(id, typeof msg.timeoutMs === 'number' ? msg.timeoutMs : 1000);
      return { ok: true, id, ...out, artifact: `artifacts/session-${id}.log` };
    }
    case 'resize':
      mgr.resize(id, Number(msg.cols ?? 120), Number(msg.rows ?? 40));
      return { ok: true, id };
    case 'close':
      mgr.close(id);
      bySession.delete(id);
      return { ok: true, id, exited: true };
    default:
      throw new KernelError('INVALID_REQUEST', `unknown session op: ${op}`);
  }
}

async function handleGdbLine(
  byRoot: Map<string, GdbManager>,
  msg: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const root = String(msg.root ?? '');
  if (!root) throw new KernelError('INVALID_REQUEST', 'root is required');
  const project = Project.open(root);
  let mgr = byRoot.get(project.root);
  if (!mgr) {
    mgr = new GdbManager(project);
    byRoot.set(project.root, mgr);
  }
  const action = String(msg.action ?? '');
  const id = msg.id ? String(msg.id) : null;
  if (action === 'start') {
    const session = await mgr.start({
      ...(typeof msg.binary === 'string' && msg.binary.length > 0 ? { binary: msg.binary } : {}),
      ...(typeof msg.cwd === 'string' && msg.cwd.length > 0 ? { cwd: msg.cwd } : {}),
      ...(Array.isArray(msg.args) ? { args: (msg.args as unknown[]).map(String) } : {}),
    });
    return { ok: true, ...session.status() };
  }
  if (action === 'list') return { ok: true, sessions: mgr.list() };
  if (action === 'kill') {
    if (!id) throw new KernelError('INVALID_REQUEST', 'id is required');
    return { ok: true, ...mgr.close(id) };
  }
  if (!id) throw new KernelError('INVALID_REQUEST', 'id is required');
  const session = mgr.get(id);
  switch (action) {
    case 'attach':
      return { ok: true, ...(await session.attach(Number(msg.pid))) };
    case 'run':
      return { ok: true, ...(await session.run()) };
    case 'continue':
      return { ok: true, ...(await session.continue()) };
    case 'step':
      return { ok: true, ...(await session.step('step')) };
    case 'next':
      return { ok: true, ...(await session.step('next')) };
    case 'stepi':
      return { ok: true, ...(await session.step('stepi')) };
    case 'nexti':
      return { ok: true, ...(await session.step('nexti')) };
    case 'finish':
      return { ok: true, ...(await session.step('finish')) };
    case 'break':
      return { ok: true, ...(await session.break(String(msg.location ?? ''), typeof msg.condition === 'string' ? msg.condition : undefined)) };
    case 'delete':
      return { ok: true, ...(await session.deleteBreakpoint(msg.number === undefined ? undefined : Number(msg.number))) };
    case 'list-breakpoints':
      return { ok: true, output: await session.listBreakpoints() };
    case 'context':
      return { ok: true, ...(await session.context()) };
    case 'regs':
      return { ok: true, ...(await session.regs()) };
    case 'backtrace':
      return { ok: true, ...(await session.backtrace()) };
    case 'stack':
      return { ok: true, ...(await session.stack()) };
    case 'mem':
      return { ok: true, ...(await session.mem(String(msg.address ?? ''), Number(msg.length ?? 256))) };
    case 'raw':
      return { ok: true, ...(await session.raw(String(msg.command ?? ''))) };
    case 'interrupt':
      session.interrupt();
      return { ok: true, id, interrupted: true };
    default:
      throw new KernelError('INVALID_REQUEST', `unknown gdb action: ${action}`);
  }
}


main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(EXIT_CODES.INTERNAL);
  });
