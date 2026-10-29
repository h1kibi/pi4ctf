/** Target-bound oracle/provenance, default format retry, and synthetic evidence. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { compilePacket } from '../kernel/context/packet.js';
import { DEFAULT_FLAG_FORMAT } from '../kernel/flag/format.js';
import { submitFlag } from '../kernel/flag/flag.js';
import { Ledger } from '../kernel/ledger/store.js';
import { Project } from '../kernel/project.js';
import { runExec } from '../kernel/run/exec.js';
import type { TargetSpec } from '../kernel/types.js';

const NODE = process.execPath;

function makeTargetProject(flag: string, target: TargetSpec | null, oracleTarget: unknown, flagFormat = DEFAULT_FLAG_FORMAT) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-target-flag-'));
  const oraclePath = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  fs.writeFileSync(oraclePath, JSON.stringify({ flag, target: oracleTarget }, null, 2));
  const project = Project.init(root, {
    id: 'target-flag',
    title: 'target-flag',
    goal: 'x',
    category: 'pwn',
    flagFormat,
    backend: 'host',
    target: target ?? undefined,
    oracle: { type: 'local', ref: path.relative(root, oraclePath) },
  });
  return { root, oraclePath, project, flag, cleanup: () => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oraclePath, { force: true });
  } };
}

async function solve(project: Project, flag: string, synthetic = false) {
  const run = await runExec(project, { argv: [NODE, '-e', `console.log(${JSON.stringify(flag)})`], synthetic });
  const verifier = new ClaimVerifier(project, new Ledger(project));
  const claim = verifier.submit({
    claimType: 'interpreted',
    text: 'flag in output',
    quotes: [{ shapedRef: run.outcome.stdout.shapedRef, span: { start: 0, end: flag.length }, text: flag }],
    refs: [run.outcome.id],
  });
  verifier.verify(claim.id);
  return { run, claim, fact: new Ledger(project).listFacts()[0] };
}

test('target-bound oracle accepts a current-target flag with generic default', async () => {
  const target = { host: '127.0.0.1', port: 4555, instanceId: 'inst-a' };
  const flag = 'NSSCTF{target_bound}';
  const tp = makeTargetProject(flag, target, target);
  try {
    const solved = await solve(tp.project, flag);
    assert.equal(solved.run.outcome.target, '127.0.0.1:4555');
    assert.equal(solved.run.outcome.instanceId, 'inst-a');
    assert.equal(solved.fact.target, '127.0.0.1:4555');
    assert.equal(solved.fact.instanceId, 'inst-a');
    const verdict = submitFlag(tp.project, new Ledger(tp.project), { value: flag, evidenceRefs: [solved.fact.id] });
    assert.equal(verdict.status, 'accepted', JSON.stringify(verdict.detail));
  } finally {
    tp.cleanup();
  }
});

test('oracle target/instance mismatch fails fast at init', () => {
  const current = { host: '127.0.0.1', port: 4555, instanceId: 'inst-new' };
  const old = { host: '127.0.0.1', port: 4555, instanceId: 'inst-old' };
  const flag = 'NSSCTF{old_instance}';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-mismatch-'));
  const oraclePath = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  fs.writeFileSync(oraclePath, JSON.stringify({ flag, target: old }, null, 2));
  try {
    assert.throws(() => Project.init(root, {
      id: 'mismatch', title: 'mismatch', goal: 'x', category: 'pwn',
      flagFormat: DEFAULT_FLAG_FORMAT, backend: 'host', target: current,
      oracle: { type: 'local', ref: path.relative(root, oraclePath) },
    }), /instanceId|does not match/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oraclePath, { force: true });
  }
});



test('oracle without instanceId fails fast when the case has an instance', () => {
  const target = { host: '127.0.0.1', port: 4555, instanceId: 'inst-a' };
  const flag = 'NSSCTF{unbound_instance}';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-noinstance-'));
  const oraclePath = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  fs.writeFileSync(oraclePath, JSON.stringify({ flag, target: { host: '127.0.0.1', port: 4555 } }, null, 2));
  try {
    assert.throws(() => Project.init(root, {
      id: 'noinstance', title: 'noinstance', goal: 'x', category: 'pwn',
      flagFormat: DEFAULT_FLAG_FORMAT, backend: 'host', target,
      oracle: { type: 'local', ref: path.relative(root, oraclePath) },
    }), /instance/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(oraclePath, { force: true });
  }
});

test('oracle rejection is retryable after the oracle is reconfigured', async () => {
  const target = { host: '127.0.0.1', port: 4555, instanceId: 'inst-a' };
  const oldFlag = 'NSSCTF{old_oracle}';
  const newFlag = 'NSSCTF{new_oracle}';
  const tp = makeTargetProject(oldFlag, target, target);
  try {
    const solved = await solve(tp.project, newFlag);
    const first = submitFlag(tp.project, new Ledger(tp.project), { value: newFlag, evidenceRefs: [solved.fact.id] });
    assert.equal(first.status, 'rejected');
    assert.match(first.detail.oracle ?? '', /rejected/);
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flag: newFlag, target }, null, 2));
    tp.project.reconfigure({ oracleRef: path.relative(tp.root, tp.oraclePath) });
    const second = submitFlag(tp.project, new Ledger(tp.project), { value: newFlag, evidenceRefs: [solved.fact.id] });
    assert.equal(second.status, 'accepted', JSON.stringify(second.detail));
  } finally {
    tp.cleanup();
  }
});

test('an old artifact cannot validate a flag after switching target', async () => {
  const a = { host: '127.0.0.1', port: 4555, instanceId: 'inst-a' };
  const b = { host: '127.0.0.1', port: 4556, instanceId: 'inst-b' };
  const flag = 'NSSCTF{old_artifact}';
  const tp = makeTargetProject(flag, a, a);
  try {
    const solved = await solve(tp.project, flag);
    fs.writeFileSync(tp.oraclePath, JSON.stringify({ flag, target: b }, null, 2));
    tp.project.reconfigure({ oracleRef: path.relative(tp.root, tp.oraclePath), target: b });
    const verdict = submitFlag(tp.project, new Ledger(tp.project), { value: flag, evidenceRefs: [solved.fact.id] });
    assert.equal(verdict.status, 'rejected');
    assert.equal(verdict.layers.provenance, false);
    assert.match(verdict.detail.provenance ?? '', /current target/);
  } finally {
    tp.cleanup();
  }
});

test('format rejection is retryable after case.configure changes flagFormat', async () => {
  const flag = 'NSSCTF{format_retry}';
  const tp = makeTargetProject(flag, null, null, 'WRONG\\\\{[^}]+\\\\}');
  try {
    const solved = await solve(tp.project, flag);
    const first = submitFlag(tp.project, new Ledger(tp.project), { value: flag, evidenceRefs: [solved.fact.id] });
    assert.equal(first.status, 'rejected');
    assert.equal(first.layers.format, false);
    tp.project.reconfigure({ flagFormat: DEFAULT_FLAG_FORMAT });
    const second = submitFlag(tp.project, new Ledger(tp.project), { value: flag, evidenceRefs: [solved.fact.id] });
    assert.equal(second.status, 'accepted', JSON.stringify(second.detail));
  } finally {
    tp.cleanup();
  }
});

test('synthetic fact is hidden from packet, complete, and flag evidence', async () => {
  const flag = 'NSSCTF{LOCAL_KERNEL_TEST}';
  const tp = makeTargetProject(flag, null, null);
  try {
    const solved = await solve(tp.project, flag, true);
    assert.equal(solved.fact.synthetic, true);
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.doesNotMatch(packet.text, new RegExp(solved.fact.id));
    assert.match(packet.text, /synthetic fact\(s\) hidden/);
    const verdict = submitFlag(tp.project, new Ledger(tp.project), { value: flag, evidenceRefs: [solved.fact.id] });
    assert.equal(verdict.status, 'rejected');
    assert.match(verdict.detail.evidence ?? '', /synthetic/);
    const ledger = JSON.parse(fs.readFileSync(path.join(tp.project.ctfDir, 'flags.jsonl'), 'utf8').trim());
    assert.equal(ledger.synthetic, true);
    const complete = await dispatch({ op: 'case.complete', root: tp.root });
    assert.equal(complete.ok, false);
  } finally {
    tp.cleanup();
  }
});
