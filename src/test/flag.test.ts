/** Flag four-layer tests (docs/design.md §4.5). */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { submitFlag, readAcceptedFlag } from '../kernel/flag/flag.js';
import { Ledger } from '../kernel/ledger/store.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { runExec } from '../kernel/run/exec.js';
import { Project } from '../kernel/project.js';
import { dispatch } from '../adapter/protocol.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

/** Produce a project whose artifacts contain the real flag + a verified claim. */
async function solvedProject(opts?: Parameters<typeof makeProject>[0]) {
  const tp = makeProject(opts);
  const a = await runExec(tp.project, {
    argv: [NODE, '-e', `console.log(${JSON.stringify('flag{t3st_r00m_gl4d}')})`],
  });
  const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
  const claim = verifier.submit({
    claimType: 'interpreted',
    text: 'flag 出现在输出中',
    quotes: [
      {
        shapedRef: a.outcome.stdout.shapedRef,
        span: { start: 0, end: 18 },
        text: a.shapedStdout.slice(0, 18),
      },
    ],
    refs: [a.outcome.id],
  });
  verifier.verify(claim.id);
  const fact = new Ledger(tp.project).listFacts()[0];
  return { tp, factId: fact.id };
}


test('oracle with no flag/flagSha256 is not pinnable', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-empty-oracle-'));
  const oracle = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  fs.writeFileSync(oracle, '{}');
  try {
    const project = Project.init(root, {
      id: 'empty-oracle',
      title: 'empty-oracle',
      goal: 'x',
      category: 'misc',
      flagFormat: 'flag\\{[^}]+\\}',
      backend: 'host',
      oracle: { type: 'local', ref: path.relative(root, oracle) },
    });
    assert.equal(project.file().oracleHash, null);
    const out = project.reconfigure({ oracleRef: path.relative(root, oracle) });
    assert.equal(out.oracleHash, null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oracle, { force: true });
  }
});


test('unpinned oracle rejection is retryable after configure', async () => {
  const flag = 'flag{later_oracle}';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-late-oracle-'));
  const oracle = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  fs.writeFileSync(oracle, '{}');
  try {
    const project = Project.init(root, {
      id: 'late-oracle',
      title: 'late-oracle',
      goal: 'x',
      category: 'misc',
      flagFormat: 'flag\\{[^}]+\\}',
      backend: 'host',
      oracle: { type: 'local', ref: path.relative(root, oracle) },
    });
    const run = await runExec(project, { argv: [NODE, '-e', `console.log(${JSON.stringify(flag)})`] });
    const verifier = new ClaimVerifier(project, new Ledger(project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: 'flag in output',
      quotes: [{ shapedRef: run.outcome.stdout.shapedRef, span: { start: 0, end: flag.length }, text: flag }],
      refs: [run.outcome.id],
    });
    verifier.verify(claim.id);
    const factId = new Ledger(project).listFacts()[0].id;
    const first = submitFlag(project, new Ledger(project), { value: flag, evidenceRefs: [factId] });
    assert.equal(first.status, 'unverified');
    assert.match(first.detail.oracle ?? '', /not pinned/);
    const res = await dispatch({ op: 'flag', root, input: { value: flag, evidenceRefs: [factId] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok ? res.data.status : '', 'unverified');
    assert.equal(res.ok ? res.data.verified : null, false);
    assert.equal(res.ok ? res.data.layersPassed : 0, 4);
    assert.match(String(res.ok ? res.data.statusDetail : ''), /evidence complete; oracle unavailable/);
    fs.writeFileSync(oracle, JSON.stringify({ flag }));
    const cfg = project.reconfigure({ oracleRef: path.relative(root, oracle) });
    assert.ok(cfg.oracleHash);
    const second = submitFlag(project, new Ledger(project), { value: flag, evidenceRefs: [factId] });
    assert.equal(second.status, 'accepted', JSON.stringify(second.detail));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oracle, { force: true });
  }
});


test('oracle inside the challenge workspace is rejected', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-inside-oracle-'));
  try {
    fs.writeFileSync(path.join(root, 'oracle.json'), JSON.stringify({ flag: 'flag{x}' }));
    assert.throws(() => Project.init(root, {
      id: 'inside-oracle',
      title: 'inside-oracle',
      goal: 'x',
      category: 'misc',
      flagFormat: 'flag\\{[^}]+\\}',
      backend: 'host',
      oracle: { type: 'local', ref: 'oracle.json' },
    }), /outside the challenge workspace/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('all four layers pass -> accepted + flag.txt written once', async () => {
  const { tp, factId } = await solvedProject();
  try {
    const ledger = new Ledger(tp.project);
    const v1 = submitFlag(tp.project, ledger, { value: tp.flag, evidenceRefs: [factId] });
    assert.equal(v1.status, 'accepted', JSON.stringify(v1.detail));
    assert.equal(readAcceptedFlag(tp.project), tp.flag);
    // same value again -> dedupe layer rejects
    const v2 = submitFlag(tp.project, ledger, { value: tp.flag, evidenceRefs: [factId] });
    assert.equal(v2.status, 'rejected');
    assert.equal(v2.layers.dedupe, false);
    assert.equal(readAcceptedFlag(tp.project), tp.flag);
  } finally {
    tp.cleanup();
  }
});

test('oracle changed after init is rejected as self-generated', async () => {
  const { tp, factId } = await solvedProject();
  try {
    // Simulate the model writing the flag it just found into its own oracle.
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flag: tp.flag }, null, 2));
    const v = submitFlag(tp.project, new Ledger(tp.project), {
      value: tp.flag,
      evidenceRefs: [factId],
    });
    assert.equal(v.status, 'rejected');
    assert.equal(v.layers.oracle, false);
    assert.match(v.detail.oracle ?? '', /changed after project.init|self-generated/);
    assert.equal(readAcceptedFlag(tp.project), null);
  } finally {
    tp.cleanup();
  }
});

test('case.configure repairs flagFormat and pins a new oracle', async () => {
  const tp = makeProject();
  try {
    const sentinel = { flag: 'h1tc0n{r3p1n}' };
    fs.writeFileSync(tp.oraclePath, JSON.stringify(sentinel, null, 2));
    const out = tp.project.reconfigure({
      flagFormat: 'h1tc0n\\{[^}]+\\}',
      oracleRef: path.relative(tp.root, tp.oraclePath),
    });
    assert.equal(out.flagFormat, 'h1tc0n\\{[^}]+\\}');
    assert.ok(out.oracleHash);
    const file = tp.project.file();
    assert.equal(file.flagFormat, 'h1tc0n\\{[^}]+\\}');
    assert.equal(file.oracleHash, out.oracleHash);
  } finally {
    tp.cleanup();
  }
});

test('flag throws on corrupt outcome state instead of treating it as real', async () => {
  const { tp, factId } = await solvedProject();
  try {
    fs.writeFileSync(path.join(tp.project.ctfDir, 'outcomes', 'cmd-9999.json'), '{broken');
    assert.throws(
      () => submitFlag(tp.project, new Ledger(tp.project), { value: tp.flag, evidenceRefs: [factId] }),
      SyntaxError,
    );
  } finally {
    tp.cleanup();
  }
});

test('format layer: non-matching flag rejected, no flag.txt', async () => {
  const { tp, factId } = await solvedProject();
  try {
    const v = submitFlag(tp.project, new Ledger(tp.project), { value: 'not-a-flag', evidenceRefs: [factId] });
    assert.equal(v.status, 'rejected');
    assert.equal(v.layers.format, false);
    assert.equal(readAcceptedFlag(tp.project), null);
  } finally {
    tp.cleanup();
  }
});

test('provenance layer: flag never seen in any artifact is rejected', async () => {
  const { tp, factId } = await solvedProject();
  try {
    const v = submitFlag(tp.project, new Ledger(tp.project), { value: 'flag{never_seen_anywhere}', evidenceRefs: [factId] });
    assert.equal(v.status, 'rejected');
    assert.equal(v.layers.provenance, false);
    assert.equal(v.layers.oracle, false);
  } finally {
    tp.cleanup();
  }
});

test('evidence layer: no verified Fact link -> rejected even with oracle match', async () => {
  const tp = makeProject();
  try {
    // flag appears in an artifact, but no fact exists
    await runExec(tp.project, { argv: [NODE, '-e', `console.log(${JSON.stringify(tp.flag)})`] });
    const v = submitFlag(tp.project, new Ledger(tp.project), { value: tp.flag, evidenceRefs: [] });
    assert.equal(v.status, 'rejected');
    assert.equal(v.layers.provenance, true);
    assert.equal(v.layers.evidence, false);
    assert.equal(v.layers.oracle, false); // short-circuited
    assert.equal(readAcceptedFlag(tp.project), null);
  } finally {
    tp.cleanup();
  }
});

test('oracle layer: decoy flag in artifact with valid evidence still rejected', async () => {
  const tp = makeProject();
  try {
    // decoy flag printed by the challenge AND linked to a verified claim...
    const a = await runExec(tp.project, {
      argv: [NODE, '-e', `console.log(${JSON.stringify('flag{d3c0y}')})`],
    });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: '看到 decoy flag',
      quotes: [{ shapedRef: a.outcome.stdout.shapedRef, span: { start: 0, end: 11 }, text: 'flag{d3c0y}' }],
      refs: [a.outcome.id],
    });
    verifier.verify(claim.id);
    const fact = new Ledger(tp.project).listFacts()[0];
    const v = submitFlag(tp.project, new Ledger(tp.project), { value: 'flag{d3c0y}', evidenceRefs: [fact.id] });
    assert.equal(v.status, 'rejected');
    assert.equal(v.layers.oracle, false);
    assert.match(v.detail.oracle ?? '', /oracle rejected/);
    assert.equal(readAcceptedFlag(tp.project), null);
    // decoy is now case-scope blocked
    const v2 = submitFlag(tp.project, new Ledger(tp.project), { value: 'flag{d3c0y}', evidenceRefs: [fact.id] });
    assert.equal(v2.layers.dedupe, false);
  } finally {
    tp.cleanup();
  }
});

test('incomplete rejection does not permanently block a later valid flag', async () => {
  const tp = makeProject();
  try {
    // Premature submit: the flag is not in any artifact yet.
    const first = submitFlag(tp.project, new Ledger(tp.project), {
      value: tp.flag,
      evidenceRefs: [],
    });
    assert.equal(first.status, 'rejected');
    assert.equal(first.layers.provenance, false);
    assert.equal(first.layers.dedupe, true);

    // Produce the artifact + verified Fact, then retry the same value.
    const a = await runExec(tp.project, {
      argv: [NODE, '-e', `console.log(${JSON.stringify(tp.flag)})`],
    });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: 'output contains the flag',
      quotes: [{
        shapedRef: a.outcome.stdout.shapedRef,
        span: { start: 0, end: tp.flag.length },
        text: tp.flag,
      }],
      refs: [a.outcome.id],
    });
    verifier.verify(claim.id);
    const fact = new Ledger(tp.project).listFacts()[0];

    const retry = submitFlag(tp.project, new Ledger(tp.project), {
      value: tp.flag,
      evidenceRefs: [fact.id],
    });
    assert.equal(retry.status, 'accepted', JSON.stringify(retry.detail));
    assert.equal(retry.layers.dedupe, true);
    assert.equal(readAcceptedFlag(tp.project), tp.flag);
  } finally {
    tp.cleanup();
  }
});

test('flags.jsonl records every attempt with layer detail', async () => {
  const { tp, factId } = await solvedProject();
  try {
    const ledger = new Ledger(tp.project);
    submitFlag(tp.project, ledger, { value: 'garbage', evidenceRefs: [] });
    submitFlag(tp.project, ledger, { value: tp.flag, evidenceRefs: [factId] });
    const lines = fs
      .readFileSync(path.join(tp.project.ctfDir, 'flags.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[0].status, 'rejected');
    assert.equal(lines[1].status, 'accepted');
  } finally {
    tp.cleanup();
  }
});


test('flag reports the last flagFormat change', async () => {
  const { tp, factId } = await solvedProject();
  try {
    tp.project.reconfigure({ flagFormat: 'flag\\{[^}]+\\}' });
    const res = await dispatch({
      op: 'flag',
      root: tp.root,
      input: { value: tp.flag, evidenceRefs: [factId] },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(typeof (res.ok ? res.data.formatConfiguredAt : null), 'number');
    assert.equal(res.ok ? res.data.formatConfiguredBy : '', 'adapter');
    assert.equal(res.ok ? res.data.verified : false, true);
    assert.equal(res.ok ? res.data.layersPassed : 0, 5);
  } finally {
    tp.cleanup();
  }
});

test('docker flag validation warns instead of rejecting a host-side unreachable target', async () => {
  const { tp, factId } = await solvedProject({ target: { host: '127.0.0.1', port: 1 }, allowedHosts: ['127.0.0.1'] });
  try {
    tp.project.reconfigure({ backend: 'docker', dockerImage: 'alpine:3' });
    const res = await dispatch({
      op: 'flag',
      root: tp.root,
      input: { value: tp.flag, evidenceRefs: [factId], targetTimeoutMs: 100 },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.match(JSON.stringify(res), /backend=docker may still reach it/);
  } finally {
    tp.cleanup();
  }
});
