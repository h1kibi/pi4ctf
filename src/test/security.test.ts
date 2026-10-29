/**
 * Security tests: goal contract, kernel-only ops, untrusted input handling,
 * root identity fail-closed, path escapes (docs/design.md §7, ADR 0003).
 */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { scanInjection, wrapUntrusted } from '../kernel/security.js';
import { Project } from '../kernel/project.js';
import { makeProject } from './helpers.js';

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
    for (const op of ['predicate.register', 'contract.override', 'guardrail.edit', 'budget.raise', 'allowedHosts.expand', 'memory.addGlobal', 'flag.write', 'flag.txt']) {
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

test('root identity: replacing the project root fails closed', () => {
  const tp = makeProject();
  try {
    const root = tp.root;
    // same-volume rename keeps the file id (same filesystem object) -> still opens
    const moved = `${root}-moved`;
    fs.renameSync(root, moved);
    Project.open(moved);
    fs.renameSync(moved, root);
    // replacing the root with a fresh directory at the same path is a
    // different filesystem object -> kernel must fail closed
    fs.rmSync(root, { recursive: true, force: true });
    fs.mkdirSync(path.join(root, '.ctf'), { recursive: true });
    fs.writeFileSync(
      path.join(root, '.ctf', 'project.json'),
      JSON.stringify({
        version: 1, id: 'x', title: 'x', goal: '', origin: '', status: 'active',
        category: 'x', backend: 'host', root, rootIdentity: 'dev:dead:ino:beef',
        envHash: '', flagFormat: 'f', oracle: { type: 'local', ref: '../o.json' },
        deadlineMs: null, allowedHosts: ['*'], counters: {}, revisions: {},
      }),
    );
    assert.throws(() => Project.open(root), /root identity mismatch/);
  } finally {
    tp.cleanup();
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
    const { Ledger } = await import('../kernel/ledger/store.js');
    const ledger = new Ledger(tp.project);
    const { commandClassOf } = await import('../kernel/classify/classify.js');
    const { signature } = await import('../kernel/shape/signature.js');
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
