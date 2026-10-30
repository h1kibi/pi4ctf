/** Optional Docker pwn smoke: pwntools reaches a host target, and proc reads
 *  the live container PID 1. Skipped when Docker or the image is unavailable. */
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as net from 'node:net';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { SessionManager } from '../kernel/session/session.js';
import { makeProject } from './helpers.js';

const IMAGE = process.env.PI4CTF_TEST_PWN_IMAGE ?? 'cyberarena/agent-base:latest';
const SKIP = (() => {
  const info = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 3000 });
  if (info.status !== 0) return 'docker is unavailable';
  const image = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore', timeout: 3000 });
  return image.status === 0 ? false : `docker image ${IMAGE} is unavailable`;
})();

async function hostTarget(): Promise<{ server: net.Server; port: number; close: () => void }> {
  const server = net.createServer((socket) => {
    socket.once('data', (data) => {
      socket.end(data.toString().includes('PWN') ? 'PWNED: docker-pwn\n' : 'NO\n');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '0.0.0.0', resolve));
  const address = server.address() as net.AddressInfo;
  return {
    server,
    port: address.port,
    close: () => server.close(),
  };
}

test('docker pwn: pwntools reaches a host target', { skip: SKIP, timeout: 60_000 }, async () => {
  const target = await hostTarget();
  const tp = makeProject({
    backend: 'docker',
    dockerImage: IMAGE,
    target: { host: 'host.docker.internal', port: target.port },
    allowedHosts: ['*'],
  });
  try {
    const code = [
      'from pwn import remote',
      'import os',
      "r=remote(os.environ['HOST'], int(os.environ['PORT']), timeout=5)",
      "r.sendline(b'PWN')",
      "print(r.recvline().decode().strip())",
      'r.close()',
    ].join(';');
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: ['python3', '-c', code], timeoutMs: 30_000, targetTimeoutMs: 5000 },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(res.ok ? String(res.data.stdout) : '', /PWNED: docker-pwn/);
  } finally {
    target.close();
    tp.cleanup();
  }
});

test('docker pwn: session cwd and proc read container PID 1', { skip: SKIP, timeout: 60_000 }, async () => {
  const tp = makeProject({ backend: 'docker', dockerImage: IMAGE });
  const mgr = new SessionManager(tp.project);
  try {
    const session = mgr.open({
      argv: ['python3', '-c', 'import os,time; print(os.getcwd(), flush=True); time.sleep(10)'],
      cwd: 'workspace/sub',
    });
    const out = await mgr.read(session.id, 2000);
    assert.match(out.data, /\/challenge\/workspace\/sub/);
    const proc = await dispatch({
      op: 'proc',
      root: tp.root,
      input: { session: session.id, action: 'maps' },
    });
    assert.equal(proc.ok, true, JSON.stringify(proc));
    assert.equal(proc.ok ? proc.data.source : '', 'docker');
    assert.match(proc.ok ? String(proc.data.text) : '', /\/usr\/|python|libc/);
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});

test('docker tty allocates a container TTY on POSIX', {
  skip: SKIP || process.platform === 'win32' ? 'docker tty requires a POSIX host' : false,
  timeout: 60_000,
}, async () => {
  const tp = makeProject({ backend: 'docker', dockerImage: IMAGE });
  const mgr = new SessionManager(tp.project);
  try {
    const session = mgr.open({
      argv: ['python3', '-c', 'import sys,time; print(sys.stdin.isatty(), flush=True); time.sleep(10)'],
      tty: true,
    });
    const out = await mgr.read(session.id, 2000);
    assert.match(out.data, /True/);
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});
