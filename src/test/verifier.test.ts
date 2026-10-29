/** Verifier tests: quote anchoring, differential predicate, downgrade. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { Ledger } from '../kernel/ledger/store.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { runExec } from '../kernel/run/exec.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('legacy facts without provenance read as predicate-verified', () => {
  const tp = makeProject();
  try {
    const dir = path.join(tp.project.ctfDir, 'facts');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'f9001.json'), JSON.stringify({
      id: 'f9001', claimId: 'c9001', claimType: 'observed',
      predicate: 'process.exit-zero@1.0.0', classifiedBy: 'classify@1',
      value: {}, observationRefs: [], artifactHashes: {}, canonicalKey: '',
      status: 'verified', ts: Date.now(),
    }));
    const ledger = new Ledger(tp.project);
    assert.equal(ledger.listFacts().find((f) => f.id === 'f9001')?.verifiedBy, 'predicate');
    assert.equal(ledger.getFact('f9001').verifiedBy, 'predicate');
  } finally {
    tp.cleanup();
  }
});

test('quote must equal shaped[start:end]; mismatch rejected at submit', async () => {
  const tp = makeProject();
  try {
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("hello")'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    assert.throws(
      () =>
        verifier.submit({
          claimType: 'interpreted',
          text: 'x',
          quotes: [{ shapedRef: a.outcome.stdout.shapedRef, span: { start: 0, end: 5 }, text: 'WRONG' }],
          refs: [a.outcome.id],
        }),
      /quote does not match/,
    );
  } finally {
    tp.cleanup();
  }
});

test('interpreted claim: valid quotes + clean outcome -> accepted -> Fact', async () => {
  const tp = makeProject();
  try {
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("needle found here")'] });
    const shaped = a.shapedStdout;
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: '输出包含 needle',
      quotes: [{ shapedRef: a.outcome.stdout.shapedRef, span: { start: shaped.indexOf('needle'), end: shaped.indexOf('needle') + 6 }, text: 'needle' }],
      refs: [a.outcome.id],
    });
    const verdict = verifier.verify(claim.id);
    assert.equal(verdict.state, 'accepted');
    const ledger = new Ledger(tp.project);
    const facts = ledger.listFacts();
    assert.equal(facts.length, 1);
    assert.equal(facts[0]?.claimId, claim.id);
    assert.equal(facts[0]?.predicate, 'output.contains@1.0.0');
    assert.equal(facts[0]?.verifiedBy, 'predicate');
  } finally {
    tp.cleanup();
  }
});

test('differential claim: large length delta accepted, small rejected', async () => {
  const tp = makeProject();
  try {
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const baseline = await runExec(tp.project, {
      argv: [NODE, '-e', 'process.stdout.write("x".repeat(100))'],
    });
    const probeBig = await runExec(tp.project, {
      argv: [NODE, '-e', 'process.stdout.write("y".repeat(400))'],
    });
    const probeSmall = await runExec(tp.project, {
      argv: [NODE, '-e', 'process.stdout.write("z".repeat(105))'],
    });

    const ok = verifier.submit({
      claimType: 'differential',
      text: 'boolean blind: true/false 响应长度不同',
      quotes: [],
      refs: [baseline.outcome.id, probeBig.outcome.id],
      probe: { purpose: '比较响应长度', expect: 'delta > 10%', falsifier: '长度一致或都 403' },
    });
    const okVerdict = verifier.verify(ok.id);
    assert.equal(okVerdict.state, 'accepted');
    const ledger = new Ledger(tp.project);
    const fact = ledger.listFacts().find((f) => f.claimId === ok.id);
    assert.equal(fact?.predicate, 'http.length_delta@1.0.0');
    assert.equal((fact?.value as { baseline: number }).baseline, 100);

    const bad = verifier.submit({
      claimType: 'differential',
      text: '长度差异(应拒绝)',
      quotes: [],
      refs: [baseline.outcome.id, probeSmall.outcome.id],
    });
    const badVerdict = verifier.verify(bad.id);
    assert.equal(badVerdict.state, 'rejected');
    // rejected claim produced a code-owned negative entry
    const negs = ledger.listNegatives();
    assert.ok(negs.some((n) => n.signature === bad.signature && n.failureClass === 'probe-contradicted'));
  } finally {
    tp.cleanup();
  }
});

test('model cannot use an unregistered predicate or wrong claimType', async () => {
  const tp = makeProject();
  try {
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'console.log(1)'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    assert.throws(
      () =>
        verifier.submit({
          claimType: 'observed',
          text: 'x',
          quotes: [],
          refs: [a.outcome.id],
          predicate: 'made.up@9.9.9',
        }),
      /unregistered predicate/,
    );
    assert.throws(
      () =>
        verifier.submit({
          claimType: 'differential',
          text: 'x',
          quotes: [],
          refs: [a.outcome.id],
          predicate: 'process.exit-zero@1.0.0',
        }),
      /does not accept claimType/,
    );
  } finally {
    tp.cleanup();
  }
});

test('observed claim over failing outcome is rejected', async () => {
  const tp = makeProject();
  try {
    const bad = await runExec(tp.project, { argv: [NODE, '-e', 'process.exit(7)'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'observed',
      text: '命令成功',
      quotes: [],
      refs: [bad.outcome.id],
    });
    const verdict = verifier.verify(claim.id);
    assert.equal(verdict.state, 'rejected');
    assert.match(verdict.rejectedReason ?? '', /non-clean outcomes/);
  } finally {
    tp.cleanup();
  }
});
