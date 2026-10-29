/**
 * Protocol E2E: the full core loop over the real dispatch surface.
 * A local HTTP server plays the vulnerable challenge: /?id=1 returns a short
 * body, /?id=1'+AND+'1'='1 returns a long body (boolean blind SQLi shape).
 */
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { after, before, test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';

const FLAG = 'flag{bl1nd_l0ng_r00m}';

let server: http.Server;
let port = 0;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const id = url.searchParams.get('id') ?? '';
    const truthy = id.includes("' AND '1'='1");
    const body = truthy ? `<html>${'WELCOME ADMIN '.repeat(60)}</html>` : '<html>nope</html>';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr && typeof addr === 'object') port = addr.port;
});

after(() => {
  server.close();
});

function rootDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-e2e-'));
}

test('E2E: init -> run baseline/probe -> claim differential -> flag -> complete', async () => {
  const root = rootDir();
  const oraclePath = path.join(os.tmpdir(), `oracle-${path.basename(root)}.json`);
  fs.writeFileSync(
    oraclePath,
    JSON.stringify({ flagSha256: crypto.createHash('sha256').update(FLAG).digest('hex') }),
  );
  try {
    // -- case init (internal API)
    const init = await dispatch({
      op: 'project.init',
      root,
      input: {
        id: 'web-blind-sqli',
        title: 'blind sqli',
        goal: '拿到 flag 并验证',
        category: 'web',
        flagFormat: 'flag\\{[^}]+\\}',
        backend: 'host',
        oracleRef: path.relative(root, oraclePath),
        allowedHosts: ['127.0.0.1'],
      },
    });
    assert.equal(init.ok, true);

    // -- verb run: baseline leg
    const baseline = await dispatch({
      op: 'run',
      root,
      input: { argv: ['curl', '-s', `http://127.0.0.1:${port}/?id=1`], timeoutMs: 15000 },
    });
    assert.equal(baseline.ok, true, JSON.stringify(baseline));
    assert.equal(baseline.ok && baseline.data.semanticFailure, null);
    const baseId = baseline.ok ? String(baseline.data.id) : '';
    const baseShapedRef = baseline.ok ? String(baseline.data.artifact) : '';

    // -- verb run: probe leg (payload differs; signature template identical)
    const probe = await dispatch({
      op: 'run',
      root,
      input: { argv: ['curl', '-s', `http://127.0.0.1:${port}/?id=1'+AND+'1'='1`], timeoutMs: 15000 },
    });
    assert.equal(probe.ok, true);
    const probeId = probe.ok ? String(probe.data.id) : '';

    // the flag materializes in the oracle-only path; put it into an artifact
    // by "exploiting": run a command that prints it (simulating data exfil)
    const exfil = await dispatch({
      op: 'run',
      root,
      input: { argv: ['node', '-e', `console.log(${JSON.stringify('admin panel says ' + FLAG)})`] },
    });
    assert.equal(exfil.ok, true);

    // -- verb claim: differential with quotes from both legs
    const baseShaped = fs.readFileSync(path.join(root, '.ctf', baseShapedRef), 'utf8');
    const claim = await dispatch({
      op: 'claim',
      root,
      input: {
        claimType: 'differential',
        text: 'boolean blind：true/false 响应长度不同',
        quotes: [
          {
            shapedRef: baseShapedRef,
            span: { start: 0, end: Math.min(20, baseShaped.length) },
            text: baseShaped.slice(0, Math.min(20, baseShaped.length)),
          },
        ],
        refs: [baseId, probeId],
        probe: { purpose: '比较响应长度', expect: 'delta > 10%', falsifier: '长度一致或都 403' },
      },
    });
    assert.equal(claim.ok, true, JSON.stringify(claim));
    const claimRec = claim.ok ? (claim.data.claim as { id: string; state: string }) : null;
    assert.equal(claimRec?.state, 'accepted');
    const claimId = claimRec?.id ?? '';

    // -- case context: packet carries fact + untrusted observations
    const ctx = await dispatch({ op: 'case.context', root });
    assert.equal(ctx.ok, true);
    const packet = ctx.ok ? String(ctx.data.packet) : '';
    assert.match(packet, /## Verified Facts[\s\S]*http\.length_delta@1\.0\.0/);
    assert.match(packet, /<UNTRUSTED_DATA>/);

    // -- verb flag: four layers
    const flag = await dispatch({ op: 'flag', root, input: { value: FLAG, evidenceRefs: [claimId] } });
    assert.equal(flag.ok, true, JSON.stringify(flag));
    assert.ok(fs.existsSync(path.join(root, '.ctf', 'flag.txt')));

    // -- case complete: requires verified Fact
    const statsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-protocol-stats-'));
    process.env.PI4CTF_STATS_PATH = path.join(statsDir, 'solve-stats.jsonl');
    try {
      const complete = await dispatch({ op: 'case.complete', root });
      assert.equal(complete.ok, true);
      assert.ok(complete.ok && complete.data.flagAccepted === true);
    } finally {
      delete process.env.PI4CTF_STATS_PATH;
      fs.rmSync(statsDir, { recursive: true, force: true });
    }

    // -- doctor clean
    const doctor = await dispatch({ op: 'case.doctor', root });
    assert.equal(doctor.ok, true);
    assert.deepEqual(doctor.ok ? doctor.data.issues : ['x'], []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oraclePath, { force: true });
  }
});

test('E2E: 500-status run produces semanticFailure server-error + negative entry', async () => {
  const failing = http.createServer((_req, res) => {
    res.writeHead(500);
    res.end('oops');
  });
  await new Promise<void>((r) => failing.listen(0, '127.0.0.1', r));
  const fport = (failing.address() as import('node:net').AddressInfo).port;
  const root = rootDir();
  try {
    await dispatch({ op: 'project.init', root, input: { id: 'err', backend: 'host', allowedHosts: ['127.0.0.1'] } });
    const run = await dispatch({
      op: 'run',
      root,
      input: { argv: ['curl', '-si', `http://127.0.0.1:${fport}/x`], timeoutMs: 15000 },
    });
    assert.equal(run.ok, true);
    assert.equal(run.ok && run.data.semanticFailure, 'server-error');
    // negative ledger captured it with the kernel-owned class
    const negs = fs
      .readdirSync(path.join(root, '.ctf', 'negatives'))
      .map((n) => JSON.parse(fs.readFileSync(path.join(root, '.ctf', 'negatives', n), 'utf8')));
    assert.ok(negs.some((n) => n.failureClass === 'server-error' && n.transient === true));
  } finally {
    failing.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('E2E: project.status / case.handoff / project.close roundtrip', async () => {
  const root = rootDir();
  try {
    await dispatch({ op: 'project.init', root, input: { id: 'rt', backend: 'host' } });
    const status = await dispatch({ op: 'project.status', root });
    assert.equal(status.ok, true);
    assert.ok(status.ok && (status.data.counters as Record<string, number>).command === 0);
    const handoff = await dispatch({ op: 'case.handoff', root });
    assert.equal(handoff.ok, true);
    assert.ok(fs.existsSync(path.join(root, '.ctf', 'progress.md')));
    const close = await dispatch({ op: 'project.close', root, input: { status: 'stopped' } });
    assert.equal(close.ok, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
