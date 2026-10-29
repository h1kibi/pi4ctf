/**
 * Regression tests for the review findings (C1–C6, R2, R4, R7, R8).
 * One test per finding so a re-introduced defect fails by name.
 */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { after, before, test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { extractUrlHosts } from '../kernel/classify/classify.js';
import { Ledger } from '../kernel/ledger/store.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { runExec, ARTIFACT_CAP } from '../kernel/run/exec.js';
import { FileLock } from '../kernel/fsutil.js';
import { SessionManager } from '../kernel/session/session.js';
import { signature } from '../kernel/shape/signature.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

// ---------------------------------------------------------------------------
// C1: goal-contract scope bypass
// ---------------------------------------------------------------------------

test('C1: userinfo trick http://allowed:80@evil resolves to evil', () => {
  assert.deepEqual(extractUrlHosts('http://127.0.0.1:80@evil.example.com/'), ['evil.example.com']);
});

test('C1: quoted URL inside argv is still detected', () => {
  assert.deepEqual(extractUrlHosts('"http://evil.example.com/x"'), ['evil.example.com']);
});

test('C1: URL inside a script body (node -e fetch) is detected', () => {
  assert.deepEqual(extractUrlHosts("fetch('http://127.0.0.1:9090/')"), ['127.0.0.1']);
});

test('C1: unparsable :// token fails closed at the run verb', async () => {
  const tp = makeProject({ allowedHosts: ['10.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("see http:// glitch")'] },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'SECURITY');
  } finally {
    tp.cleanup();
  }
});

test('C1: script-embedded URL to non-allowed host is blocked end-to-end', async () => {
  const tp = makeProject({ allowedHosts: ['10.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', "fetch('http://192.0.2.1:9/').catch(()=>{})"] },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'SECURITY');
    const events = fs.readFileSync(path.join(tp.root, '.ctf', 'events.jsonl'), 'utf8');
    assert.match(events, /blocked\.run/);
  } finally {
    tp.cleanup();
  }
});

test('C1: allowed host inside script body passes', async () => {
  const tp = makeProject({ allowedHosts: ['10.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', "console.log('http://10.0.0.1/x (not fetched)')"] },
    });
    assert.equal(res.ok, true);
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// C2: artifact symlink escape
// ---------------------------------------------------------------------------

test('C2: symlink in artifacts cannot escape .ctf via readArtifact', () => {
  const tp = makeProject();
  try {
    const secret = path.join(os.tmpdir(), `pi4ctf-secret-${Date.now()}.txt`);
    fs.writeFileSync(secret, 'SECRET-OUTSIDE');
    const link = path.join(tp.project.ctfDir, 'artifacts', 'leak.log');
    fs.symlinkSync(secret, link);
    const ledger = new Ledger(tp.project);
    assert.throws(() => ledger.readArtifact('artifacts/leak.log'), /symlink in artifact path/);
    fs.rmSync(secret, { force: true });
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// C4: session cap at the protocol level (5th open fails)
// handled in rt-session.test.ts (protocol server); manager-level cap here.
// ---------------------------------------------------------------------------

test('C4 (manager): MAX_SESSIONS enforced per manager', () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) ids.push(mgr.open({ argv: [NODE, '-i'] }).id);
    assert.throws(() => mgr.open({ argv: [NODE, '-i'] }), /max 4 sessions/);
    for (const id of ids) mgr.close(id);
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// C6: live lock is never broken
// ---------------------------------------------------------------------------

test('C6: lock held by a live pid is not broken, even if old', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-lock-'));
  try {
    const lockPath = path.join(dir, '.lock');
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, ts: Date.now() - 10 * 60_000 }));
    const lock = FileLock.at(lockPath);
    assert.throws(() => lock.withLock(() => 1), /lock busy/);
    // a dead-pid lock IS broken and acquirable
    const deadPath = path.join(dir, 'dead.lock');
    fs.writeFileSync(deadPath, JSON.stringify({ pid: 999_999_999, ts: Date.now() }));
    const val = FileLock.at(deadPath).withLock(() => 42);
    assert.equal(val, 42);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// R2: differential over different templates is fabricated evidence
// ---------------------------------------------------------------------------

test('R2: differential claim over two DIFFERENT commands is rejected', async () => {
  const tp = makeProject();
  try {
    // same behavior, different argvTemplate spelling (abs path vs bare name)
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'process.stdout.write("x".repeat(200))'] });
    const b = await runExec(tp.project, { argv: ['node', '-e', 'process.stdout.write("y".repeat(500))'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'differential',
      text: '伪造差分',
      quotes: [],
      refs: [a.outcome.id, b.outcome.id],
    });
    const verdict = verifier.verify(claim.id);
    assert.equal(verdict.state, 'rejected');
    assert.match(verdict.rejectedReason ?? '', /argvTemplate/);
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// R4: capture cap recorded, never silent
// ---------------------------------------------------------------------------

test('R4: hitting the artifact cap sets outputTruncated on outcome + meta', async () => {
  const tp = makeProject();
  try {
    // ~72MB of output > 64MB cap
    const { outcome } = await runExec(tp.project, {
      argv: [NODE, '-e', `process.stdout.write(Buffer.alloc(${ARTIFACT_CAP + 8 * 1024 * 1024}, 120))`],
      timeoutMs: 120_000,
    });
    assert.equal(outcome.stdout.outputTruncated, true);
    assert.ok(outcome.stdout.bytes <= ARTIFACT_CAP);
    const meta = JSON.parse(
      fs.readFileSync(path.join(tp.project.ctfDir, `artifacts/${outcome.id}.stdout.meta.json`), 'utf8'),
    ) as { outputTruncated: boolean };
    assert.equal(meta.outputTruncated, true);
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// R7: real no-output-when-expected (exit 0, empty body, contracted class)
// ---------------------------------------------------------------------------

let emptyServer: http.Server;
let emptyPort = 0;

before(async () => {
  emptyServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(''); // empty body, clean exit -> curl prints nothing, exit 0
  });
  await new Promise<void>((r) => emptyServer.listen(0, '127.0.0.1', r));
  emptyPort = (emptyServer.address() as import('node:net').AddressInfo).port;
});

after(() => {
  emptyServer.close();
});

test('R7: exit 0 + empty stdout on http-probe -> no-output-when-expected', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, {
      argv: ['curl', '-s', `http://127.0.0.1:${emptyPort}/`],
      timeoutMs: 15_000,
    });
    assert.equal(outcome.exit, 0);
    assert.equal(outcome.intentClass, 'http-probe');
    assert.equal(outcome.stdout.bytes, 0);
    assert.equal(outcome.processFailure, 'no-output-when-expected');
  } finally {
    tp.cleanup();
  }
});

test('R7b: filtered pipeline with empty stdout is not a no-output failure', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, {
      command: `curl -s http://127.0.0.1:${emptyPort}/ | sed -n '1p'`,
      timeoutMs: 15_000,
    });
    assert.equal(outcome.exit, 0);
    assert.equal(outcome.stdout.bytes, 0);
    assert.equal(outcome.processFailure, null, 'grep/sed-style empty result is legitimate');
  } finally {
    tp.cleanup();
  }
});

// ---------------------------------------------------------------------------
// R8: key=short-value stays literal in signature@1
// ---------------------------------------------------------------------------

test('R8: signature keeps key=short-value literal, long value becomes payload', () => {
  assert.deepEqual(signature(['curl', '-d', 'a=1']).argvTemplate, ['curl', '-d', 'a=1']);
  assert.deepEqual(
    signature(['curl', '-d', `key=${'v'.repeat(40)}`]).argvTemplate,
    ['curl', '-d', '<v:1>'],
  );
});
