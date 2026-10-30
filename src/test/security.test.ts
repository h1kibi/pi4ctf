/**
 * Security tests: goal contract, kernel-only ops, untrusted input handling,
 * root identity fail-closed, path escapes (docs/design.md §7, ADR 0003).
 */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { scanInjection, wrapUntrusted } from '../kernel/security.js';
import { Project } from '../kernel/project.js';
import { Ledger } from '../kernel/ledger/store.js';
import { commandClassOf } from '../kernel/classify/classify.js';
import { signature } from '../kernel/shape/signature.js';
import { commandExists } from '../kernel/sysutil.js';
import { execHostOf, prepareDocker, prepareHost } from '../kernel/run/prepare.js';
import { makeContainerCases, makeProject } from './helpers.js';

const NODE = process.execPath;

test('goal contract: run to non-allowed host is blocked and audited', async () => {
  const tp = makeProject({ allowedHosts: ['127.0.0.1'] });
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: ['curl', '-s', 'http://evil.example.com/x'], timeoutMs: 5000 },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'SECURITY');
    // audited as blocked.run
    const events = fs.readFileSync(path.join(tp.root, '.ctf', 'events.jsonl'), 'utf8');
    assert.match(events, /blocked\.run/);
    // allowed host passes the gate
    const okRun = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("fine")'] },
    });
    assert.equal(okRun.ok, true);
  } finally {
    tp.cleanup();
  }
});

test('kernel-only ops are blocked with audit, not INVALID_REQUEST', async () => {
  const tp = makeProject();
  try {
    for (const op of ['predicate.register', 'contract.override', 'guardrail.edit', 'budget.raise', 'allowedHosts.expand', 'memory.addGlobal', 'flag.write', 'flag.txt', 'registry.write']) {
      const res = await dispatch({ op, root: tp.root, input: {} });
      assert.equal(res.ok, false, `${op} should be blocked`);
      if (!res.ok) assert.equal(res.error.code, 'SECURITY', `${op} should be SECURITY`);
    }
    const events = fs.readFileSync(path.join(tp.root, '.ctf', 'events.jsonl'), 'utf8');
    assert.match(events, /blocked\.kernelOnly/);
  } finally {
    tp.cleanup();
  }
});

test('injection fixture: untrusted text is scanned, wrapped, never executed', async () => {
  const tp = makeProject();
  try {
    const inject = fs.readFileSync(
      path.resolve(import.meta.dirname, '..', '..', 'fixtures', 'injection', 'inject-01.txt'),
      'utf8',
    );
    // 1. the run output carrying injection payloads is just data
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', `console.log(${JSON.stringify(inject)})`] },
    });
    assert.equal(res.ok, true);
    const markers = res.ok ? (res.data.injectionMarkers as string[]) : [];
    assert.ok(markers.length >= 3, `expected injection markers, got ${markers}`);

    // 2. no flag was written from injected content
    assert.equal(fs.existsSync(path.join(tp.root, '.ctf', 'flag.txt')), false);

    // 3. the decoy flag in the artifact cannot pass the oracle
    const decoy = await dispatch({
      op: 'flag',
      root: tp.root,
      input: { value: 'flag{d3c0y_f4k3}', evidenceRefs: [] },
    });
    assert.equal(decoy.ok, false);
    assert.equal(fs.existsSync(path.join(tp.root, '.ctf', 'flag.txt')), false);

    // 4. wrapUntrusted keeps the boundary structural
    const wrapped = wrapUntrusted(inject);
    assert.ok(wrapped.startsWith('<UNTRUSTED_DATA>'));
    assert.ok(wrapped.endsWith('</UNTRUSTED_DATA>'));
    assert.deepEqual(scanInjection('totally clean output'), []);
  } finally {
    tp.cleanup();
  }
});

test('case.close cannot bypass the verified-Fact completion gate', async () => {
  const tp = makeProject();
  try {
    const completed = await dispatch({ op: 'case.close', root: tp.root, input: { status: 'completed' } });
    assert.equal(completed.ok, false);
    assert.equal(completed.ok ? '' : completed.error.code, 'CONFLICT');

    const implicit = await dispatch({ op: 'case.close', root: tp.root, input: {} });
    assert.equal(implicit.ok, true, JSON.stringify(implicit));
    assert.equal(implicit.ok ? implicit.data.status : '', 'failed');
  } finally {
    tp.cleanup();
  }
});

test('commandExists treats metacharacters as a literal name', () => {
  assert.equal(commandExists('node & echo PI4CTF_INJECTED'), false);
});

test('root identity: a foreign root identity fails closed', () => {
  const tp = makeProject();
  const replaced = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-replaced-'));
  try {
    // A fresh directory with a foreign identity must fail closed. Renaming the
    // live project is deliberately not asserted here: Windows can return EPERM
    // while an indexer holds a fresh temp dir, and name stability across a
    // rename is OS behavior rather than the security invariant.
    fs.mkdirSync(path.join(replaced, '.ctf'), { recursive: true });
    fs.writeFileSync(
      path.join(replaced, '.ctf', 'project.json'),
      JSON.stringify({
        version: 1, id: 'x', title: 'x', goal: '', origin: '', status: 'active',
        category: 'x', backend: 'host', root: replaced, rootIdentity: 'dev:dead:ino:beef',
        envHash: '', flagFormat: 'f', oracle: { type: 'local', ref: '../o.json' },
        deadlineMs: null, allowedHosts: ['*'], counters: {}, revisions: {},
      }),
    );
    assert.throws(() => Project.open(replaced), /root identity mismatch/);
  } finally {
    tp.cleanup();
    fs.rmSync(replaced, { recursive: true, force: true });
  }
});

test('cwd escape is rejected with SECURITY', async () => {
  const tp = makeProject();
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log(1)'], cwd: '../../etc' },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'SECURITY');
  } finally {
    tp.cleanup();
  }
});

test('unknown op is INVALID_REQUEST; request shape validated', async () => {
  const tp = makeProject();
  try {
    const res = await dispatch({ op: 'nonsense.op', root: tp.root });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'INVALID_REQUEST');
    const noRun = await dispatch({ op: 'run', root: tp.root, input: {} });
    assert.equal(noRun.ok, false);
  } finally {
    tp.cleanup();
  }
});

test('budget gate: turn budget exhausted -> LIMIT without executing', async () => {
  const tp = makeProject();
  try {
    // burn the 30-turn budget with a direct counter edit (kernel-owned file)
    const file = tp.project.file();
    const projectJson = JSON.parse(
      JSON.stringify({ ...file, counters: { ...file.counters, command: 30 } }),
    ) as typeof file;
    const fsx = await import('node:fs');
    const pjs = path.join(tp.root, '.ctf', 'project.json');
    fsx.writeFileSync(pjs, JSON.stringify(projectJson, null, 2));
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("should not run")'] },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'LIMIT');
    assert.throws(() => tp.project.reserveCommand(), /turn budget exhausted/);
  } finally {
    tp.cleanup();
  }
});

test('exec-local failures do not enter the negative ledger', async () => {
  const tp = makeProject();
  try {
    const first = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'process.exit(7)'] },
    });
    assert.equal(first.ok, true);
    assert.equal(first.ok ? (first.data as { processFailure?: string }).processFailure : '', 'nonzero-exit');
    const second = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("different script")'] },
    });
    assert.equal(second.ok, true);
    const negDir = path.join(tp.root, '.ctf', 'negatives');
    assert.equal(fs.readdirSync(negDir).length, 0);
  } finally {
    tp.cleanup();
  }
});

test('case.restart resets command budget; case.close blocks runs', async () => {
  const tp = makeProject();
  try {
    const file = tp.project.file();
    const projectJson = { ...file, counters: { ...file.counters, command: 30 } } as typeof file;
    const fsx = await import('node:fs');
    fsx.writeFileSync(path.join(tp.root, '.ctf', 'project.json'), JSON.stringify(projectJson, null, 2));

    const restart = await dispatch({ op: 'case.restart', root: tp.root });
    assert.equal(restart.ok, true);
    assert.equal(tp.project.file().counters.command, 0);
    assert.equal(tp.project.file().counters.restart, 1);

    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("after restart")'] },
    });
    assert.equal(run.ok, true);

    const close = await dispatch({ op: 'case.close', root: tp.root, input: { status: 'stopped' } });
    assert.equal(close.ok, true);
    const afterClose = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("must not run")'] },
    });
    assert.equal(afterClose.ok, false);
    assert.equal(afterClose.ok ? '' : afterClose.error.code, 'CONFLICT');
  } finally {
    tp.cleanup();
  }
});

test('restart resets budget but never reuses command ids', async () => {
  const tp = makeProject();
  try {
    const first = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("old")'] },
    });
    assert.equal(first.ok, true);
    const oldId = String((first.data as { id?: string }).id);
    const restarted = await dispatch({ op: 'case.restart', root: tp.root });
    assert.equal(restarted.ok, true);
    const second = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("new")'] },
    });
    assert.equal(second.ok, true);
    const newId = String((second.data as { id?: string }).id);
    assert.notEqual(newId, oldId);
    assert.ok(fs.existsSync(path.join(tp.root, '.ctf', 'outcomes', `${oldId}.json`)));
    const { Ledger } = await import('../kernel/ledger/store.js');
    assert.equal(new Ledger(tp.project).recentOutcomes(1)[0]?.id, newId);
  } finally {
    tp.cleanup();
  }
});

test('case.restart clears transient negative entries but keeps hard blocks', async () => {
  const tp = makeProject();
  try {
    const { Ledger } = await import('../kernel/ledger/store.js');
    const ledger = new Ledger(tp.project);
    ledger.addNegative({
      signature: 'generic|signature@1:soft',
      failureClass: 'timeout',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() + 600_000,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const restarted = await dispatch({ op: 'case.restart', root: tp.root });
    assert.equal(restarted.ok, true);
    assert.equal((restarted.ok ? (restarted.data as { clearedNegatives?: number }).clearedNegatives : 0), 1);
    const after = new Ledger(tp.project).listNegatives();
    assert.equal(after.length, 1);
    assert.ok(after[0]?.unblockedAt);
  } finally {
    tp.cleanup();
  }
});

test('case.init creates a timestamped case and points the container index at it', async () => {
  const container = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-initcase-'));
  const challenge = path.join(container, 'challenges', 'A');
  const oracle = path.join(container, 'challenges', 'oracle.json');
  try {
    fs.mkdirSync(challenge, { recursive: true });
    fs.writeFileSync(oracle, JSON.stringify({ flag: 'flag{init_case}' }, null, 2));
    const res = await dispatch({
      op: 'case.init',
      root: container,
      input: {
        challengeRoot: challenge,
        oracleRef: '../oracle.json',
        backend: 'host',
        flagFormat: 'flag\\{[^}]+\\}',
      },
    });
    assert.equal(res.ok, true);
    const data = res.ok ? res.data as Record<string, unknown> : {};
    const id = String(data.caseId);
    assert.match(id, /^\d{8}-\d{4}$/);
    assert.equal(Project.activeCaseId(container), id);
    assert.equal(Project.open(container).root, challenge);
    assert.equal(Project.open(container).workspace, path.join(container, 'workspace', id));
  } finally {
    fs.rmSync(container, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  }
});

test('case container stores timestamped cases, per-case workspaces, and an active index', async () => {
  const box = makeContainerCases();
  try {
    const [a, b] = box.cases;
    assert.ok(a && b);
    const index = JSON.parse(fs.readFileSync(path.join(box.container, '.ctf', 'index.json'), 'utf8')) as { active?: string };
    assert.equal(index.active, b.id);
    assert.ok(fs.existsSync(path.join(box.container, 'workspace', a.id)));
    assert.ok(fs.existsSync(path.join(box.container, 'workspace', b.id)));

    const opened = Project.open(box.container);
    assert.equal(opened.caseId, b.id);
    assert.equal(opened.root, b.root);
    assert.equal(opened.workspace, path.join(box.container, 'workspace', b.id));
    assert.equal(Project.openCase(box.container, a.id).root, a.root);

    const activated = await dispatch({
      op: 'case.activate',
      root: box.container,
      input: { challengeRoot: a.root },
    });
    assert.equal(activated.ok, true);
    assert.equal(Project.activeCaseId(box.container), a.id);
  } finally {
    box.cleanup();
  }
});

test('docker runs mount the case workspace, not a shared root workspace', () => {
  const box = makeContainerCases();
  try {
    const first = box.cases[0];
    assert.ok(first);
    first.project.reconfigure({ backend: 'docker', dockerImage: 'example:case' });
    const prepared = prepareDocker(execHostOf(first.project), { argv: ['true'] });
    assert.ok(prepared.argv.includes(`${first.project.workspace}:/challenge/workspace:rw`));
    assert.ok(!prepared.argv.includes(`${path.join(first.root, 'workspace')}:/challenge/workspace:rw`));
  } finally {
    box.cleanup();
  }
});

test('host runs map cwd=workspace to the case workspace', () => {
  const box = makeContainerCases();
  try {
    const first = box.cases[0];
    assert.ok(first);
    const prepared = prepareHost(execHostOf(first.project), { argv: ['true'], cwd: 'workspace' });
    assert.equal(prepared.cwd, first.project.workspace);
    assert.throws(
      () => prepareHost(execHostOf(first.project), { argv: ['true'], cwd: 'workspace/../escape' }),
      /path escapes/,
    );
  } finally {
    box.cleanup();
  }
});

test('case.restart selects a case id, reopens it, clears soft blocks, and has no cap', async () => {
  const box = makeContainerCases();
  try {
    const [a, b] = box.cases;
    assert.ok(a && b);
    await dispatch({ op: 'case.activate', root: box.container, input: { caseId: a.id } });
    b.project.close('stopped');
    const progress = path.join(b.project.ctfDir, 'progress.md');
    fs.writeFileSync(progress, 'resume from the second case');

    for (let i = 0; i < 5; i++) {
      const res = await dispatch({
        op: 'case.restart',
        root: box.container,
        input: { caseId: b.id },
      });
      assert.equal(res.ok, true);
    }
    const final = await dispatch({
      op: 'case.restart',
      root: box.container,
      input: { caseId: b.id },
    });
    assert.equal(final.ok, true);
    const data = final.ok ? final.data as Record<string, unknown> : {};
    assert.equal(data.caseId, b.id);
    assert.equal(data.workspace, path.join(box.container, 'workspace', b.id));
    assert.equal(data.handoff, 'resume from the second case');
    assert.equal(Project.activeCaseId(box.container), b.id);
    assert.equal(b.project.file().status, 'active');
    assert.ok((b.project.file().counters.restart ?? 0) >= 6);
    assert.equal(b.project.file().counters.command, 0);
  } finally {
    box.cleanup();
  }
});

test('case.clearNegatives clears soft entries without resetting the budget', async () => {
  const tp = makeProject();
  try {
    const { Ledger } = await import('../kernel/ledger/store.js');
    const ledger = new Ledger(tp.project);
    ledger.addNegative({
      signature: 'generic|signature@1:soft-clear',
      failureClass: 'timeout',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() + 600_000,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const before = tp.project.file().counters.command;
    const res = await dispatch({ op: 'case.clearNegatives', root: tp.root });
    assert.equal(res.ok, true);
    assert.equal((res.ok ? (res.data as { cleared?: number }).cleared : 0), 1);
    assert.equal(tp.project.file().counters.command, before);
    assert.ok(new Ledger(tp.project).listNegatives()[0]?.unblockedAt);
  } finally {
    tp.cleanup();
  }
});

test('case.time sets a hard checkpoint and continue clears it', async () => {
  const tp = makeProject();
  try {
    const set = await dispatch({ op: 'case.time', root: tp.root, input: { minutes: 10 } });
    assert.equal(set.ok, true);
    const at = set.ok && typeof set.data.timeLimitAtMs === 'number' ? set.data.timeLimitAtMs : 0;
    assert.ok(at > Date.now());

    const file = tp.project.file();
    fs.writeFileSync(
      path.join(tp.root, '.ctf', 'project.json'),
      JSON.stringify({ ...file, timeLimitAtMs: Date.now() - 1000 }, null, 2),
    );
    const blocked = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("blocked")'] },
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.ok ? '' : blocked.error.code, 'TIMEOUT');

    const cont = await dispatch({ op: 'case.continue', root: tp.root });
    assert.equal(cont.ok, true);
    assert.equal(tp.project.file().timeLimitAtMs, null);
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("after continue")'] },
    });
    assert.equal(run.ok, true);
  } finally {
    tp.cleanup();
  }
});

test('case.map exposes route state and clearNegatives accepts one id', async () => {
  const tp = makeProject();
  try {
    const ledger = new Ledger(tp.project);
    const a = ledger.addNegative({
      signature: 'generic|signature@1:map-a',
      failureClass: 'timeout',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() + 600_000,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    assert.ok(a.id);
    ledger.addNegative({
      signature: 'generic|signature@1:map-b',
      failureClass: 'server-error',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() + 600_000,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    tp.project.writePlan({ chain: ['recon', 'exploit'], next: 'find offset', preconditions: ['libc?'] });

    const map = await dispatch({ op: 'case.map', root: tp.root });
    assert.equal(map.ok, true);
    const mapData = map.ok ? map.data : undefined;
    const plan = mapData?.plan;
    const planNext = typeof plan === 'object' && plan !== null && 'next' in plan ? plan.next : undefined;
    const negatives = mapData?.negatives;
    assert.equal(planNext, 'find offset');
    assert.equal(Array.isArray(negatives) ? negatives.length : -1, 2);

    const cleared = await dispatch({ op: 'case.clearNegatives', root: tp.root, input: { id: a.id } });
    assert.equal(cleared.ok, true);
    const clearedCount = cleared.ok && typeof cleared.data.cleared === 'number' ? cleared.data.cleared : 0;
    assert.equal(clearedCount, 1);
    const after = new Ledger(tp.project).listNegatives();
    assert.ok(after.find((n) => n.id === a.id)?.unblockedAt);
    assert.equal(after.filter((n) => !n.unblockedAt).length, 1);
  } finally {
    tp.cleanup();
  }
});

test('budget gate: past-deadline project rejects run with TIMEOUT', async () => {
  const tp = makeProject();
  try {
    const file = tp.project.file();
    const projectJson = { ...file, deadlineMs: Date.now() - 1000 } as typeof file;
    const fsx = await import('node:fs');
    fsx.writeFileSync(path.join(tp.root, '.ctf', 'project.json'), JSON.stringify(projectJson, null, 2));
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log(1)'] },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'TIMEOUT');
  } finally {
    tp.cleanup();
  }
});

test('negative gate: hard-blocked route returns CONFLICT without executing', async () => {
  const tp = makeProject();
  try {
    // a deterministic schema-mismatch style hard block on this signature
    const ledger = new Ledger(tp.project);
    const argv = [NODE, '-e', 'console.log("will-be-blocked")'];
    ledger.addNegative({
      signature: `${commandClassOf(argv)}|signature@1:${signature(argv).signature}`,
      failureClass: 'schema-mismatch',
      transient: false,
      condemnedBy: 'test',
      unblockOn: 'env_change',
      expiresAt: null,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const before = (tp.project.file().counters.command) ?? 0;
    const res = await dispatch({ op: 'run', root: tp.root, input: { argv } });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'CONFLICT');
    assert.equal(tp.project.file().counters.command, before, 'blocked run must not execute');
  } finally {
    tp.cleanup();
  }
});

test('case.continue resets budget without consuming a restart', async () => {
  const tp = makeProject();
  try {
    const file = tp.project.file();
    fs.writeFileSync(
      path.join(tp.root, '.ctf', 'project.json'),
      JSON.stringify({ ...file, counters: { ...file.counters, command: 30, restart: 3 } }, null, 2),
    );
    const cont = await dispatch({ op: 'case.continue', root: tp.root });
    assert.equal(cont.ok, true);
    assert.equal(tp.project.file().counters.command, 0);
    assert.equal(tp.project.file().counters.restart, 3);
    assert.equal(tp.project.file().counters.continue, 1);

    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: { argv: [NODE, '-e', 'console.log("continued")'] },
    });
    assert.equal(run.ok, true);
    assert.equal(tp.project.file().counters.command, 1);
  } finally {
    tp.cleanup();
  }
});

test('packet degrades on invalid rows and unreadable state dirs', async () => {
  const tp = makeProject();
  try {
    fs.mkdirSync(path.join(tp.project.ctfDir, 'facts'), { recursive: true });
    fs.writeFileSync(path.join(tp.project.ctfDir, 'facts', 'f9998.json'), 'null');
    fs.writeFileSync(
      path.join(tp.project.ctfDir, 'facts', 'f9997.json'),
      JSON.stringify({ id: 'f9997', claimType: 'observed', predicate: 'p', observationRefs: [] }),
    );
    fs.writeFileSync(
      path.join(tp.project.ctfDir, 'claims', 'c9998.json'),
      JSON.stringify({ id: 'c9998', state: 'proposed', claimType: 'observed', text: 'x', refs: [123] }),
    );
    fs.writeFileSync(
      path.join(tp.project.ctfDir, 'outcomes', 'cmd-9998.json'),
      JSON.stringify({
        id: 'cmd-9998',
        ts: 1,
        canonicalKey: 'k',
        intentClass: 'exec-local',
        stdout: { excerpt: '', shapedRef: 'a' },
        stderr: { excerpt: '', shapedRef: 'b' },
        items: { ids: {} },
      }),
    );
    fs.rmSync(path.join(tp.project.ctfDir, 'negatives'), { recursive: true, force: true });
    fs.writeFileSync(path.join(tp.project.ctfDir, 'negatives'), 'not a directory');
    fs.writeFileSync(
      path.join(tp.project.ctfDir, 'chal.json'),
      JSON.stringify({ endpoint: null, files: [{ path: 'bad', elf: { needed: [], buildId: 123 } }], libc: [], otherFiles: [], notes: [] }),
    );

    const ctx = await dispatch({ op: 'case.context', root: tp.root });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.ok ? ctx.data.integrity : '', 'degraded');
    const packet = ctx.ok ? String(ctx.data.packet) : '';
    assert.match(packet, /invalid row: facts\/f9998\.json/);
    assert.match(packet, /invalid row: facts\/f9997\.json/);
    assert.match(packet, /invalid row: claims\/c9998\.json/);
    assert.match(packet, /invalid row: outcomes\/cmd-9998\.json/);
    assert.match(packet, /unreadable dir: negatives/);

    const handoff = await dispatch({ op: 'case.handoff', root: tp.root });
    assert.equal(handoff.ok, true);
  } finally {
    tp.cleanup();
  }
});

test('doctor reports corrupt state JSON; listFacts stops skipping it', async () => {
  const tp = makeProject();
  try {
    fs.mkdirSync(path.join(tp.project.ctfDir, 'facts'), { recursive: true });
    fs.writeFileSync(path.join(tp.project.ctfDir, 'facts', 'f9999.json'), '{broken');
    const res = await dispatch({ op: 'case.doctor', root: tp.root });
    assert.equal(res.ok, true);
    assert.match(JSON.stringify(res), /unreadable json: facts\/f9999\.json/);
    const ctx = await dispatch({ op: 'case.context', root: tp.root });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.ok ? ctx.data.integrity : '', 'degraded');
    const packet = ctx.ok ? String(ctx.data.packet) : '';
    assert.match(packet, /## Packet integrity/);
    assert.match(packet, /unreadable json: facts\/f9999\.json/);
    assert.throws(() => new Ledger(tp.project).listFacts(), /cannot read .*f9999\.json/);
  } finally {
    tp.cleanup();
  }
});
