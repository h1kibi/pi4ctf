/** case.evidence regex/head/tail retrieval. */
import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { Ledger } from '../kernel/ledger/store.js';
import { runExec } from '../kernel/run/exec.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

async function makeRun() {
  const tp = makeProject();
  const run = await runExec(tp.project, {
    argv: [NODE, '-e', 'console.log("alpha"); console.log("needle one"); console.log("beta"); console.log("needle two"); console.log("omega")'],
  });
  return { tp, ref: run.outcome.id, id: run.outcome.id };
}

test('case.evidence grep returns matches and context', async () => {
  const { tp, ref } = await makeRun();
  try {
    const res = await dispatch({
      op: 'case.evidence',
      root: tp.root,
      input: { ref, grep: 'needle', context: 1, maxMatches: 5 },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    const data = res.ok ? res.data as { matches: Array<{ line: number; text: string; matched: string; start: number; end: number; before: string[]; after: string[] }>; matchCount: number } : null;
    assert.equal(data?.matchCount, 2);
    assert.equal(data?.matches[0]?.line, 2);
    assert.equal(data?.matches[0]?.text, 'needle one');
    assert.equal(data?.matches[0]?.matched, 'needle');
    assert.equal((data?.matches[0]?.end ?? 0) - (data?.matches[0]?.start ?? 0), 'needle'.length);
    assert.deepEqual(data?.matches[0]?.before, ['alpha']);
    assert.deepEqual(data?.matches[0]?.after, ['beta']);
    assert.equal(data?.matches[1]?.line, 4);
  } finally {
    tp.cleanup();
  }
});

test('case.evidence head/tail are line-oriented and bounded', async () => {
  const { tp, ref } = await makeRun();
  try {
    const head = await dispatch({ op: 'case.evidence', root: tp.root, input: { ref, head: 2 } });
    assert.equal(head.ok, true);
    assert.equal(head.ok && head.data.text, 'alpha\nneedle one');
    const tail = await dispatch({ op: 'case.evidence', root: tp.root, input: { ref, tail: 1 } });
    assert.equal(tail.ok, true);
    assert.equal(tail.ok && tail.data.text, 'omega');
    const bad = await dispatch({ op: 'case.evidence', root: tp.root, input: { ref, grep: '[' } });
    assert.equal(bad.ok, false);
    assert.equal(!bad.ok && bad.error.code, 'INVALID_REQUEST');
  } finally {
    tp.cleanup();
  }
});


test('claim can locate a unique substring without explicit offsets', async () => {
  const { tp } = await makeRun();
  try {
    const run = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("needle unique")'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: 'the output contains the needle',
      quotes: [{ shapedRef: run.outcome.stdout.shapedRef, text: 'needle unique' }],
      refs: [run.outcome.id],
    });
    assert.deepEqual(claim.quotes[0]?.span, { start: 0, end: 'needle unique'.length });
    const verified = verifier.verify(claim.id);
    assert.equal(verified.state, 'accepted');
  } finally {
    tp.cleanup();
  }
});
