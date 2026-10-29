/** Opt-in POSIX PTY sessions: script(1) wrapper, isatty, /dev/tty, no echo. */
import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { SessionManager } from '../kernel/session/session.js';
import { commandExists } from '../kernel/sysutil.js';
import { makeProject } from './helpers.js';

const SKIP = process.platform === 'win32' || !commandExists('python3')
  ? 'tty sessions require a POSIX host with python3'
  : false;

async function readUntil(mgr: SessionManager, id: string, needle: string, timeoutMs = 5000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let text = '';
  while (Date.now() < deadline) {
    const chunk = await mgr.read(id, 400);
    text += chunk.data;
    if (text.includes(needle)) return text;
    if (chunk.exited) break;
  }
  return text;
}

test('tty session exposes a terminal; the default session does not', { skip: SKIP }, async () => {
  const tp = makeProject();
  const tty = new SessionManager(tp.project);
  const pipe = new SessionManager(tp.project);
  const probe = ['sh', '-c', 'if [ -t 0 ] && [ -t 1 ]; then echo TTY_BOTH; else echo PIPE_MODE; fi'];
  try {
    const withTty = tty.open({ argv: probe, tty: true });
    assert.match(await readUntil(tty, withTty.id, 'TTY_BOTH'), /TTY_BOTH/);

    const withoutTty = pipe.open({ argv: probe });
    assert.match(await readUntil(pipe, withoutTty.id, 'PIPE_MODE'), /PIPE_MODE/);
  } finally {
    tty.closeAll();
    pipe.closeAll();
    tp.cleanup();
  }
});

test('tty session can write to /dev/tty', { skip: SKIP }, async () => {
  const tp = makeProject();
  const mgr = new SessionManager(tp.project);
  try {
    const state = mgr.open({
      argv: ['sh', '-c', 'if echo probe >/dev/tty 2>/dev/null; then echo TTY_WROTE; else echo NO_TTY; fi'],
      tty: true,
    });
    assert.match(await readUntil(mgr, state.id, 'TTY_WROTE'), /TTY_WROTE/);
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});

test('tty session disables terminal echo so input is not duplicated', { skip: SKIP }, async () => {
  const tp = makeProject();
  const mgr = new SessionManager(tp.project);
  try {
    const state = mgr.open({ argv: ['sh', '-c', 'read x; echo GOT:$x'], tty: true });
    mgr.write(state.id, 'hello\n');
    const text = await readUntil(mgr, state.id, 'GOT:hello');
    assert.match(text, /GOT:hello/);
    assert.equal(
      text.split('hello').length - 1,
      1,
      `echo must not duplicate the input: ${JSON.stringify(text)}`,
    );
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});
