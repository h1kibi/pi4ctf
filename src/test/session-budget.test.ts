/** Session opens consume one command budget; no post-budget session bypass. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { makeProject } from './helpers.js';
import { spawn } from 'node:child_process';
import * as readline from 'node:readline';

const RT = path.resolve(import.meta.dirname, '..', 'rt.js');
const NODE = process.execPath;

async function startServer() {
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
    send: (obj: Record<string, unknown>) => child.stdin.write(JSON.stringify(obj) + '\n'),
    next: () => queue.length ? Promise.resolve(queue.shift() as Record<string, unknown>) : new Promise<Record<string, unknown>>((r) => waiters.push(r)),
    close: () => new Promise<void>((resolve) => { child.stdin.end(); child.on('close', () => resolve()); }),
  };
}

test('rt --session: open is rejected at turn budget', async () => {
  const tp = makeProject();
  try {
    const file = tp.project.file();
    fs.writeFileSync(
      path.join(tp.root, '.ctf', 'project.json'),
      JSON.stringify({ ...file, counters: { ...file.counters, command: 30 } }, null, 2),
    );
    const srv = await startServer();
    srv.send({ op: 'open', root: tp.root, argv: [NODE, '-i'] });
    const res = await srv.next();
    assert.equal(res.ok, false);
    assert.equal((res.error as { code: string }).code, 'LIMIT');
    await srv.close();
  } finally {
    tp.cleanup();
  }
});
