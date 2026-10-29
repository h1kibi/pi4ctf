/** Target metadata, env injection, reachability and target-unreachable semantics. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import { after, before, test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { recoverTarget } from '../kernel/target-recovery.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;
let server: http.Server;
let port = 0;

before(async () => {
  server = http.createServer((_req, res) => res.end('ok'));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr && typeof addr === 'object') port = addr.port;
});

after(() => server.close());

test('target injects HOST/PORT/TARGET and is attributed to the outcome', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        argv: [NODE, '-e', 'console.log(`${process.env.HOST}|${process.env.PORT}|${process.env.TARGET}|${process.env.EXTRA}`)'],
        env: { EXTRA: 'ok' },
      },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.target, `127.0.0.1:${port}`);
    assert.equal(res.ok && res.data.instanceId, null);
    assert.equal(res.ok && res.data.targetReachable, null);
    assert.match(res.ok ? String(res.data.stdout) : '', new RegExp(`127\\.0\\.0\\.1\\|${port}\\|127\\.0\\.0\\.1:${port}\\|ok`));
  } finally {
    tp.cleanup();
  }
});

test('loopback targets skip the run precheck and are not budgeted before execution', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port: 1 }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({ op: 'run', root: tp.root, input: { argv: [NODE, '-e', 'console.log(1)'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.targetReachable, null);
    assert.equal(tp.project.file().counters.command, 1);
  } finally {
    tp.cleanup();
  }
});

test('skipTargetCheck allows a target started inside the run', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port: 1 }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log(process.env.TARGET)'], skipTargetCheck: true },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(res.ok ? String(res.data.stdout) : '', /127\.0\.0\.1:1/);
    assert.equal(res.ok && res.data.targetReachable, null);
  } finally {
    tp.cleanup();
  }
});

test('target host is scope-checked even without a URL in argv', async () => {
  const tp = makeProject({ target: { host: 'evil.example', port: 31337 }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({ op: 'run', root: tp.root, input: { argv: [NODE, '-e', 'console.log(1)'] } });
    assert.equal(res.ok, false);
    assert.equal(!res.ok && res.error.code, 'SECURITY');
  } finally {
    tp.cleanup();
  }
});

test('network error is target-unreachable and does not condemn the route', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        argv: [NODE, '-e', 'console.error("connect ECONNREFUSED 127.0.0.1:1"); process.exit(1)'],
        skipTargetCheck: true,
      },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.semanticFailure, 'target-unreachable');
    const negatives = (await import('node:fs')).readdirSync(`${tp.root}/.ctf/negatives`).filter((n) => n.endsWith('.json'));
    assert.equal(negatives.length, 0);
  } finally {
    tp.cleanup();
  }
});


test('case.configure validates target reachability before pinning', async () => {
  const tp = makeProject();
  const fs = await import('node:fs');
  try {
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flagSha256: (await import('node:crypto')).createHash('sha256').update(tp.flag).digest('hex'), target: { host: '127.0.0.1', port }, expiresAt: Date.now() + 60_000 }, null, 2));
    const ok = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { target: { host: '127.0.0.1', port } },
    });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(tp.project.file().target?.port, port);
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flagSha256: (await import('node:crypto')).createHash('sha256').update(tp.flag).digest('hex'), target: { host: '127.0.0.1', port: 1 }, expiresAt: Date.now() + 60_000 }, null, 2));
    const bad = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { target: { host: '127.0.0.1', port: 1 } },
    });
    assert.equal(bad.ok, false);
    assert.equal(!bad.ok && bad.error.code, 'TARGET_UNREACHABLE');
    assert.equal(tp.project.file().target?.port, port);
  } finally {
    tp.cleanup();
  }
});


test('env HOST/PORT supplies an effective target when project target is absent', async () => {
  const tp = makeProject({ allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        argv: [NODE, '-e', 'console.log(process.env.TARGET)'],
        env: { HOST: '127.0.0.1', PORT: String(port) },
      },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.target, `127.0.0.1:${port}`);
    assert.equal(res.ok ? String(res.data.stdout) : '', `127.0.0.1:${port}\n`);
  } finally {
    tp.cleanup();
  }
});


test('leading env assignments do not change the route signature', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port }, allowedHosts: ['127.0.0.1'] });
  try {
    const argv = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("same")'] },
    });
    const command = await dispatch({
      op: 'run',
      root: tp.root,
      input: { command: 'HOST=127.0.0.1 PORT=' + port + ' ' + NODE + ' -e "console.log(\'same\')"' },
    });
    assert.equal(argv.ok, true);
    assert.equal(command.ok, true);
    const route = (v: unknown) => String(v).split('|shaped:')[0];
    assert.equal(argv.ok && command.ok && route(argv.data.canonicalKey), route(command.ok ? command.data.canonicalKey : ''));
  } finally {
    tp.cleanup();
  }
});


test('case.configure fails fast on oracle target mismatch', async () => {
  const tp = makeProject();
  const fs = await import('node:fs');
  try {
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flagSha256: (await import('node:crypto')).createHash('sha256').update(tp.flag).digest('hex'), target: { host: '127.0.0.1', port: 1 }, expiresAt: Date.now() + 60_000 }, null, 2));
    const res = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { target: { host: '127.0.0.1', port } },
    });
    assert.equal(res.ok, false);
    assert.equal(!res.ok && res.error.code, 'ORACLE');
    assert.match(!res.ok ? res.error.message : '', /does not match/);
  } finally {
    tp.cleanup();
  }
});


test('target without a port is reported as unchecked, not reachable', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1' }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log(process.env.TARGET)'] },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.targetReachable, null);
    assert.equal(res.ok && res.data.targetCheckMs, null);
  } finally {
    tp.cleanup();
  }
});


test('case.configure validates the current target when only the oracle changes', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port: 1 }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { oracleRef: tp.oraclePath, targetTimeoutMs: 100 },
    });
    assert.equal(res.ok, false);
    assert.equal(!res.ok && res.error.code, 'TARGET_UNREACHABLE');
  } finally {
    tp.cleanup();
  }
});


test('docker backend downgrades an unreachable host-side target to a warning', async () => {
  const tp = makeProject({ backend: 'docker', target: { host: '127.0.0.1', port: 1 }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { backend: 'docker', dockerImage: 'alpine:3', target: { host: '127.0.0.1', port: 1 }, targetTimeoutMs: 100 },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(JSON.stringify(res), /backend=docker may still reach it/);
  } finally {
    tp.cleanup();
  }
});


test('oracle reset hook recovers a crashed target before failing the run', async () => {
  const probe = net.createServer();
  const freePort = Promise.withResolvers<number>();
  probe.listen(0, '127.0.0.1', () => {
    const addr = probe.address();
    const p = addr && typeof addr === 'object' ? addr.port : 0;
    probe.close(() => freePort.resolve(p));
  });
  probe.once('error', freePort.reject);
  const targetPort = await freePort.promise;
  let target: net.Server | null = null;
  const reset = http.createServer((_req, res) => {
    target ??= net.createServer((socket) => {
      socket.on('error', () => { /* reachability probe may close early */ });
      socket.end('ok\n');
    });
    target.listen(targetPort, '127.0.0.1', () => res.end('reset'));
  });
  const resetUp = Promise.withResolvers<void>();
  reset.listen(0, '127.0.0.1', resetUp.resolve);
  reset.once('error', resetUp.reject);
  await resetUp.promise;
  const addr = reset.address();
  const resetPort = addr && typeof addr === 'object' ? addr.port : 0;
  const tp = makeProject({ target: { host: '127.0.0.1', port: targetPort }, allowedHosts: ['127.0.0.1'] });
  try {
    const oracle = JSON.parse(fs.readFileSync(tp.oraclePath, 'utf8')) as Record<string, unknown>;
    oracle.reset = { url: `http://127.0.0.1:${resetPort}/reset` };
    fs.writeFileSync(tp.oraclePath, JSON.stringify(oracle));
    const target = tp.project.file().target;
    assert.ok(target);
    const recovery = await recoverTarget(tp.project, target, 500, 5_000);
    assert.equal(recovery.attempted, true);
    assert.equal(recovery.recovered, true);
  } finally {
    tp.cleanup();
    const resetClosed = Promise.withResolvers<void>();
    reset.close(() => resetClosed.resolve());
    await resetClosed.promise;
    if (target) {
      const targetClosed = Promise.withResolvers<void>();
      (target as net.Server).close(() => targetClosed.resolve());
      await targetClosed.promise;
    }
  }
});


test('connection reset from a crashed target is classified as environment failure', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port }, allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        argv: [NODE, '-e', 'console.error("read ECONNRESET"); process.exit(1)'],
        skipTargetCheck: true,
      },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.semanticFailure, 'target-unreachable');
    const negatives = fs.readdirSync(`${tp.root}/.ctf/negatives`).filter((n) => n.endsWith('.json'));
    assert.deepEqual(negatives, []);
  } finally {
    tp.cleanup();
  }
});


test('loopback is allowed even when allowedHosts lists only a remote host', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1' }, allowedHosts: ['example.com'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log(process.env.TARGET)'] },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(res.ok ? String(res.data.stdout) : '', /127\.0\.0\.1/);
  } finally {
    tp.cleanup();
  }
});

test('case.configure can replace allowedHosts', async () => {
  const tp = makeProject({ allowedHosts: ['example.com'] });
  try {
    const res = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { allowedHosts: ['127.0.0.1', '*.example.com'] },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.deepEqual(tp.project.file().allowedHosts, ['127.0.0.1', '*.example.com']);
  } finally {
    tp.cleanup();
  }
});
