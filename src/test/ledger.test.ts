/** Ledger tests: resubmission gate, negative TTL gate, recent dedupe. */
import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { Ledger } from '../kernel/ledger/store.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { runExec } from '../kernel/run/exec.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

async function runEcho(tp: ReturnType<typeof makeProject>, text: string) {
  return runExec(tp.project, { argv: [NODE, '-e', `console.log(${JSON.stringify(text)})`] });
}

test('claim resubmission gate: same signature without new evidence -> CONFLICT', async () => {
  const tp = makeProject();
  try {
    const a = await runEcho(tp, 'hit at offset 42');
    const shapedRef = a.outcome.stdout.shapedRef;
    const shaped = a.shapedStdout;
    const span = { start: 0, end: 5 };
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const base = {
      claimType: 'interpreted',
      text: '输出包含 hit',
      quotes: [{ shapedRef, span, text: shaped.slice(0, 5) }],
      refs: [a.outcome.id],
    };
    const c1 = verifier.submit(base);
    assert.equal(c1.state, 'proposed');
    verifier.verify(c1.id); // cheap predicate -> accepted
    // second submission, same refs and same span -> blocked
    assert.throws(() => verifier.submit(base), /already submitted/);
    // same signature but a NEW span -> allowed
    const c3 = verifier.submit({ ...base, quotes: [{ shapedRef, span: { start: 1, end: 6 }, text: shaped.slice(1, 6) }] });
    assert.ok(c3.id.startsWith('c'));
  } finally {
    tp.cleanup();
  }
});

test('negative ledger: transient entry expires and unblocks', async () => {
  const tp = makeProject();
  try {
    const ledger = new Ledger(tp.project);
    ledger.addNegative({
      signature: 'http-probe|signature@1:probe-route',
      failureClass: 'timeout',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() - 1, // already expired
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    assert.equal(ledger.blockedSignature('http-probe|signature@1:probe-route'), null);
    // hard block
    ledger.addNegative({
      signature: 'generic|signature@1:dead',
      failureClass: 'probe-contradicted',
      transient: false,
      condemnedBy: 'output.contains@1.0.0',
      unblockOn: 'probe_version',
      expiresAt: null,
      blockScope: 'route',
      artifactRef: null,
      route: 'c0001',
    });
    const blocked = ledger.blockedSignature('generic|signature@1:dead');
    assert.ok(blocked);
    assert.equal(blocked.transient, false);
  } finally {
    tp.cleanup();
  }
});

test('recent outcomes dedupe by canonicalKey; open-claim legs exempt', async () => {
  const tp = makeProject();
  try {
    const ledger = new Ledger(tp.project);
    const a1 = await runExec(tp.project, { argv: [NODE, '-e', ''] });
    const a2 = await runExec(tp.project, { argv: [NODE, '-e', ''] }); // same canonicalKey as a1
    const b = await runEcho(tp, 'different');

    let recent = ledger.recentOutcomes(5);
    const ids = recent.map((o) => o.id);
    // a1 and a2 share a canonicalKey -> only newest (a2) survives
    assert.ok(!ids.includes(a1.outcome.id), `ids=${ids}`);
    assert.ok(ids.includes(a2.outcome.id));
    assert.ok(ids.includes(b.outcome.id));

    // open a claim referencing a1 -> a1 becomes exempt
    const verifier = new ClaimVerifier(tp.project, ledger);
    verifier.submit({
      claimType: 'observed',
      text: '命令成功执行',
      quotes: [],
      refs: [a1.outcome.id],
    });
    recent = ledger.recentOutcomes(5);
    assert.ok(recent.some((o) => o.id === a1.outcome.id), 'claim leg must be exempt from dedupe');
  } finally {
    tp.cleanup();
  }
});

test('upsert by signature increments attempts', async () => {
  const tp = makeProject();
  try {
    const ledger = new Ledger(tp.project);
    const mk = () => ({
      signature: 'net|signature@1:nc h p',
      failureClass: 'timeout' as const,
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl' as const,
      expiresAt: Date.now() + 60_000,
      blockScope: 'route' as const,
      artifactRef: null,
      route: null,
    });
    ledger.addNegative(mk());
    ledger.addNegative(mk());
    const all = ledger.listNegatives();
    assert.equal(all.length, 1);
    assert.equal(all[0]?.attempts, 2);
  } finally {
    tp.cleanup();
  }
});
