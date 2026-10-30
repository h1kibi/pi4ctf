/** Packet compiler tests: budgets, drop order, untrusted wrapping, handoff. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { compilePacket, writeHandoff } from '../kernel/context/packet.js';
import { Ledger } from '../kernel/ledger/store.js';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { runExec } from '../kernel/run/exec.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('packet structure: all sections present, observations wrapped untrusted', async () => {
  const tp = makeProject();
  try {
    await runExec(tp.project, { argv: [NODE, '-e', 'console.log("observed output")'] });
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    for (const section of ['## Mission', '## Verified Facts', '## Open claims', '## Negative ledger', '## Plan', '## Budget']) {
      assert.ok(packet.text.includes(section), `missing ${section}`);
    }
    assert.match(packet.text, /<UNTRUSTED_DATA>\nobserved output\n<\/UNTRUSTED_DATA>/);
    assert.ok(packet.stats.totalBytes <= 20 * 1024, `packet too large: ${packet.stats.totalBytes}`);
  } finally {
    tp.cleanup();
  }
});

test('facts and negative never dropped; old observations dropped first', async () => {
  const tp = makeProject();
  try {
    // one verified fact
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("needle")'] });
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({
      claimType: 'interpreted',
      text: '包含 needle',
      quotes: [{ shapedRef: a.outcome.stdout.shapedRef, span: { start: 0, end: 6 }, text: a.shapedStdout.slice(0, 6) }],
      refs: [a.outcome.id],
    });
    verifier.verify(claim.id);
    // many fat, distinct outcomes to blow a tight budget (distinct payloads so
    // canonicalKey dedupe keeps them apart)
    for (let i = 0; i < 8; i++) {
      const fat = `B${i}`.repeat(750);
      await runExec(tp.project, { argv: [NODE, '-e', `console.log(${JSON.stringify(fat)})`] });
    }
    // tight total budget (default is 16KB; we simulate an overloaded packet
    // with an 8KB budget so the drop order is observable)
    const packet = compilePacket(tp.project, new Ledger(tp.project), { totalBudget: 8 * 1024 });
    // fact survives
    assert.match(packet.text, /## Verified Facts[\s\S]*needle/);
    // at least one old observation was dropped
    const recentSection = packet.stats.sections.find((s) => s.name === 'recent');
    assert.ok((recentSection?.dropped ?? 0) > 0, 'expected dropped observations');
    assert.ok(packet.stats.totalBytes <= 9 * 1024, `packet too large: ${packet.stats.totalBytes}`);
  } finally {
    tp.cleanup();
  }
});

test('packet delta: excluded outcome ids are not re-injected', async () => {
  const tp = makeProject();
  try {
    const a = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("old")'] });
    const b = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("new")'] });
    const packet = compilePacket(tp.project, new Ledger(tp.project), {
      excludeOutcomeIds: [a.outcome.id],
    });
    assert.equal(packet.text.includes(`### ${a.outcome.id}`), false);
    assert.equal(packet.text.includes(`### ${b.outcome.id}`), true);
    assert.deepEqual(packet.outcomeIds, [b.outcome.id]);
  } finally {
    tp.cleanup();
  }
});

test('packet hides outcomes from another target and marks a stale plan', async () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port: 1 } });
  try {
    const local = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("local")'] });
    const foreign = await runExec(tp.project, {
      argv: [NODE, '-e', 'console.log("foreign")'],
      target: { host: 'example.test', port: 2 },
    });
    tp.project.writePlan({ chain: [], next: 'solve the web challenge', preconditions: [], target: 'example.test:2' });
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.equal(packet.text.includes(`### ${foreign.outcome.id}`), false);
    assert.equal(packet.text.includes(`### ${local.outcome.id}`), true);
    assert.match(packet.text, /foreign-target outcomes hidden: 1/);
    assert.match(packet.text, /## Plan \(stale target/);
    assert.match(packet.text, /stale target: example\.test:2 \(current 127\.0\.0\.1:1\)/);
  } finally {
    tp.cleanup();
  }
});

test('packet warns that host ELF execution needs WSL/Docker on non-Linux', async () => {
  if (process.platform === 'linux') return;
  const tp = makeProject({ backend: 'host' });
  try {
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /host runtime: .*ELF execution requires WSL or Docker/);
  } finally {
    tp.cleanup();
  }
});

test('handoff writes progress.md with resume pointer', async () => {
  const tp = makeProject();
  try {
    tp.project.writePlan({ chain: ['probe', 'exploit'], next: 'run sqlmap', preconditions: [] });
    await runExec(tp.project, { argv: [NODE, '-e', 'console.log(1)'] });
    const { progressPath } = writeHandoff(tp.project, new Ledger(tp.project));
    assert.ok(fs.existsSync(progressPath));
    const text = fs.readFileSync(progressPath, 'utf8');
    assert.match(text, /## Resume pointer/);
    assert.match(text, /"next": "run sqlmap"/);
    assert.ok(path.basename(progressPath) === 'progress.md');
  } finally {
    tp.cleanup();
  }
});

test('negative ledger section marks HARD vs soft blocks', async () => {
  const tp = makeProject();
  try {
    const ledger = new Ledger(tp.project);
    ledger.addNegative({
      signature: 'generic|signature@1:hard-route',
      failureClass: 'probe-contradicted',
      transient: false,
      condemnedBy: 'x@1.0.0',
      unblockOn: 'probe_version',
      expiresAt: null,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const packet = compilePacket(tp.project, ledger);
    assert.match(packet.text, /hard-route class=probe-contradicted scope=route \[HARD\]/);
  } finally {
    tp.cleanup();
  }
});


test('packet separates environment incidents from route dead ends and shows budget health', async () => {
  const tp = makeProject({ category: 'web' } as never);
  try {
    const ledger = new Ledger(tp.project);
    ledger.addNegative({
      signature: 'timeout|signature@1:target-down',
      failureClass: 'timeout',
      family: 'environment',
      transient: true,
      condemnedBy: null,
      unblockOn: 'ttl',
      expiresAt: Date.now() + 60_000,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    ledger.addNegative({
      signature: 'generic|signature@1:bad-route',
      failureClass: 'probe-contradicted',
      family: 'approach',
      transient: false,
      condemnedBy: 'x@1.0.0',
      unblockOn: 'probe_version',
      expiresAt: null,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const packet = compilePacket(tp.project, ledger);
    assert.match(packet.text, /### Environment incidents/);
    assert.match(packet.text, /target-down class=timeout scope=route \[ttl\]/);
    assert.match(packet.text, /### Route dead ends/);
    assert.match(packet.text, /bad-route class=probe-contradicted scope=route \[HARD\]/);
    assert.match(packet.text, /commands: 0\/30 used; 30 remaining \(healthy\)/);
    assert.match(packet.text, /environment incidents: 1/);
    assert.match(packet.text, /route dead ends: 1/);
  } finally {
    tp.cleanup();
  }
});


test('budget health reports tight at half of the slot budget', async () => {
  const tp = makeProject();
  try {
    const filePath = `${tp.root}/.ctf/project.json`;
    const file = JSON.parse(fs.readFileSync(filePath, 'utf8')) as { counters: { command: number } };
    file.counters.command = 15;
    fs.writeFileSync(filePath, JSON.stringify(file));
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /commands: 15\/30 used; 15 remaining \(tight\)/);
  } finally {
    tp.cleanup();
  }
});
