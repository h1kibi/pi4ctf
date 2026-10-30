/** rt --session JSON-lines server E2E (spawns the real CLI process). */
import * as assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as readline from 'node:readline';
import * as path from 'node:path';
import { test } from 'node:test';
import { makeProject } from './helpers.js';

const RT = path.resolve(import.meta.dirname, '..', 'rt.js');
const NODE = process.execPath;

interface ServerHandle {
  send: (obj: Record<string, unknown>) => void;
  next: () => Promise<Record<string, unknown>>;
  close: () => Promise<void>;
}

async function startServer(): Promise<ServerHandle> {
  const child = spawn(NODE, [RT, '--session'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const rl = readline.createInterface({ input: child.stdout });
  const queue: Record<string, unknown>[] = [];
  const waiters: ((v: Record<string, unknown>) => void)[] = [];
  rl.on('line', (line) => {
    const obj = JSON.parse(line) as Record<string, unknown>;
    const waiter = waiters.shift();
    if (waiter) waiter(obj);
    else queue.push(obj);
  });
  return {
    send: (obj) => child.stdin.write(JSON.stringify(obj) + '\n'),
    next: () =>
      queue.length > 0
        ? Promise.resolve(queue.shift() as Record<string, unknown>)
        : new Promise((resolve) => waiters.push(resolve)),
    close: () =>
      new Promise((resolve) => {
        child.stdin.end();
        child.on('close', () => resolve());
      }),
  };
}

function settle(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

test('rt --session: open/write/read/close over JSON lines', async () => {
  const tp = makeProject();
  try {
    const srv = await startServer();
    // open without root -> INVALID_REQUEST
    srv.send({ op: 'open', argv: [NODE, '-i'] });
    const bad = await srv.next();
    assert.equal(bad.ok, false);

    // open against a real project
    srv.send({ op: 'open', root: tp.root, argv: [NODE, '-i'] });
    const opened = await srv.next();
    assert.equal(opened.ok, true);
    const id = String(opened.id);
    assert.ok(String(opened.artifact).startsWith('artifacts/session-'));

    // write does not require root (fixed bug) and returns ok
    srv.send({ op: 'write', id, data: 'console.log("rt-session-e2e");\n' });
    const wrote = await srv.next();
    assert.equal(wrote.ok, true);

    await settle(700);
    srv.send({ op: 'read', id, timeoutMs: 600 });
    const read = await srv.next();
    assert.equal(read.ok, true);
    assert.match(String(read.data), /rt-session-e2e/);

    srv.send({ op: 'close', id });
    const closed = await srv.next();
    assert.equal(closed.ok, true);

    // closed session is gone
    srv.send({ op: 'read', id, timeoutMs: 100 });
    const gone = await srv.next();
    assert.equal(gone.ok, false);

    await srv.close();
  } finally {
    tp.cleanup();
  }
});

test('rt --session: open maps cwd=workspace', async () => {
  const tp = makeProject();
  try {
    const srv = await startServer();
    srv.send({
      op: 'open',
      root: tp.root,
      argv: [NODE, '-e', 'console.log(process.cwd())'],
      cwd: 'workspace',
    });
    const opened = await srv.next();
    assert.equal(opened.ok, true);
    const id = String(opened.id);
    await settle(500);
    srv.send({ op: 'read', id, timeoutMs: 600 });
    const read = await srv.next();
    assert.equal(read.ok, true);
    assert.equal(String(read.data).trim(), tp.project.workspace);
    srv.send({ op: 'close', id });
    await srv.next();
    await srv.close();
  } finally {
    tp.cleanup();
  }
});

test('rt --session: open to non-allowed host is blocked', async () => {
  const tp = makeProject({ allowedHosts: ['127.0.0.1'] });
  try {
    const srv = await startServer();
    srv.send({ op: 'open', root: tp.root, argv: ['curl', '-s', 'http://evil.example.com/'] });
    const res = await srv.next();
    assert.equal(res.ok, false);
    assert.equal((res.error as { code: string }).code, 'SECURITY');
    await srv.close();
    const events = await import('node:fs').then((fs) =>
      fs.readFileSync(path.join(tp.root, '.ctf', 'events.jsonl'), 'utf8'),
    );
    assert.match(events, /blocked\.run/);
  } finally {
    tp.cleanup();
  }
});

test('C3: open with nonexistent binary -> NOT_FOUND and the server survives', async () => {
  const tp = makeProject();
  try {
    const srv = await startServer();
    srv.send({ op: 'open', root: tp.root, argv: ['definitely-not-a-real-binary-xyz'] });
    const bad = await srv.next();
    assert.equal(bad.ok, false);
    assert.equal((bad.error as { code: string }).code, 'NOT_FOUND');
    // server is still alive: a valid open works
    srv.send({ op: 'open', root: tp.root, argv: [NODE, '-i'] });
    const good = await srv.next();
    assert.equal(good.ok, true);
    srv.send({ op: 'close', id: String(good.id) });
    await srv.next();
    await srv.close();
  } finally {
    tp.cleanup();
  }
});

test('C4: 5th concurrent session per project is rejected at the protocol level', async () => {
  const tp = makeProject();
  try {
    const srv = await startServer();
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) {
      srv.send({ op: 'open', root: tp.root, argv: [NODE, '-i'] });
      const res = await srv.next();
      assert.equal(res.ok, true, `open ${i} should succeed`);
      ids.push(String(res.id));
    }
    srv.send({ op: 'open', root: tp.root, argv: [NODE, '-i'] });
    const fifth = await srv.next();
    assert.equal(fifth.ok, false);
    assert.equal((fifth.error as { code: string }).code, 'LIMIT');
    for (const id of ids) {
      srv.send({ op: 'close', id });
      await srv.next();
    }
    await srv.close();
  } finally {
    tp.cleanup();
  }
});
