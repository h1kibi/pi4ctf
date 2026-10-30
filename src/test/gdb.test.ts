/** Optional Docker GDB/MI integration: compile a fixture, break at main,
 *  inspect stop context, read stack memory, and exercise the rt GDB route.
 *  Skipped without Docker/image. */
import * as assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { test } from 'node:test';
import { GdbManager } from '../kernel/gdb/gdb.js';
import { makeProject } from './helpers.js';

const IMAGE = process.env.PI4CTF_TEST_GDB_IMAGE ?? 'ctf-swarm-pi-pwn:0.3.0-rc.1';
const RT = path.resolve(import.meta.dirname, '..', 'rt.js');
const NODE = process.execPath;
const SKIP = (() => {
  const info = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 3000 });
  if (info.status !== 0) return 'docker is unavailable';
  const image = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore', timeout: 3000 });
  return image.status === 0 ? false : `docker image ${IMAGE} is unavailable`;
})();

function buildFixture(workspace: string): void {
  const source = [
    '#include <stdio.h>',
    'int main(void) { char buf[32]; puts("gdb-fixture"); fgets(buf, sizeof buf, stdin); return 0; }',
  ].join('\n');
  fs.writeFileSync(path.join(workspace, 'chal.c'), source);
  const built = spawnSync('docker', [
    'run', '--rm', '--entrypoint', 'sh',
    '-v', `${workspace}:/workspace`,
    '-w', '/workspace',
    IMAGE,
    '-c', 'gcc -g -O0 -o chal chal.c',
  ], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(built.status, 0, built.stderr || built.stdout);
}

interface ServerHandle {
  send: (obj: Record<string, unknown>) => void;
  next: () => Promise<Record<string, unknown>>;
  close: () => Promise<void>;
}

async function startServer(): Promise<ServerHandle> {
  const child = spawn(NODE, [RT, '--session'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const rl = readline.createInterface({ input: child.stdout });
  const queue: Record<string, unknown>[] = [];
  const waiters: ((value: Record<string, unknown>) => void)[] = [];
  rl.on('line', (line) => {
    const value = JSON.parse(line) as Record<string, unknown>;
    const waiter = waiters.shift();
    if (waiter) waiter(value);
    else queue.push(value);
  });
  return {
    send: (obj) => child.stdin.write(JSON.stringify(obj) + '\n'),
    next: () => queue.length > 0
      ? Promise.resolve(queue.shift() as Record<string, unknown>)
      : new Promise((resolve) => waiters.push(resolve)),
    close: () => new Promise((resolve) => {
      child.stdin.end();
      child.on('close', () => resolve());
    }),
  };
}

test('gdb: Docker MI breakpoint, stop context, and stack memory', { skip: SKIP, timeout: 90_000 }, async () => {
  const tp = makeProject({ backend: 'docker', dockerImage: IMAGE });
  const mgr = new GdbManager(tp.project);
  try {
    buildFixture(tp.project.workspace);
    const session = await mgr.start({ binary: 'workspace/chal' });
    const bp = await session.break('main');
    assert.match(JSON.stringify(bp), /Breakpoint 1|breakpoint/);
    const run = await session.run();
    assert.match(JSON.stringify(run), /main|breakpoint/i);
    const context = await session.context();
    assert.match(String(context.backtrace), /main/);
    assert.ok(Object.keys(context.registers as Record<string, string>).length > 0);
    const mem = await session.mem('$rsp', 32);
    assert.equal(mem.bytes, 32);
    assert.match(String(mem.text), /[0-9a-f]{12}/);
    await assert.rejects(() => session.raw('shell id'), /outside the debugger/);
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});

test('rt --session: gdb start/break/run/context route', { skip: SKIP, timeout: 90_000 }, async () => {
  const tp = makeProject({ backend: 'docker', dockerImage: IMAGE });
  const srv = await startServer();
  try {
    buildFixture(tp.project.workspace);
    srv.send({ op: 'gdb', root: tp.root, action: 'start', binary: 'workspace/chal' });
    const opened = await srv.next();
    assert.equal(opened.ok, true, JSON.stringify(opened));
    const id = String(opened.id);
    srv.send({ op: 'gdb', root: tp.root, action: 'break', id, location: 'main' });
    const bp = await srv.next();
    assert.equal(bp.ok, true, JSON.stringify(bp));
    srv.send({ op: 'gdb', root: tp.root, action: 'run', id });
    const run = await srv.next();
    assert.equal(run.ok, true, JSON.stringify(run));
    srv.send({ op: 'gdb', root: tp.root, action: 'context', id });
    const context = await srv.next();
    assert.equal(context.ok, true, JSON.stringify(context));
    assert.match(JSON.stringify(context), /main/);
    srv.send({ op: 'gdb', root: tp.root, action: 'kill', id });
    const killed = await srv.next();
    assert.equal(killed.ok, true, JSON.stringify(killed));
  } finally {
    await srv.close();
    tp.cleanup();
  }
});
