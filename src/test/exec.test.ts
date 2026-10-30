/** exec engine tests: four processFailure states + atomic artifacts. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { runExec } from '../kernel/run/exec.js';
import { baseEnv } from '../kernel/sysutil.js';
import { Ledger } from '../kernel/ledger/store.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('exec exit 0 -> processFailure null, artifacts on disk', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, { argv: [NODE, '-e', 'console.log("hello kernel")'] });
    assert.equal(outcome.exit, 0);
    assert.equal(outcome.processFailure, null);
    assert.ok(outcome.id.startsWith('cmd-'));
    const raw = path.join(tp.project.ctfDir, outcome.stdout.rawRef);
    const shaped = path.join(tp.project.ctfDir, outcome.stdout.shapedRef);
    assert.ok(fs.existsSync(raw));
    assert.ok(fs.existsSync(shaped));
    assert.equal(fs.readFileSync(shaped, 'utf8'), 'hello kernel\n');
    assert.match(outcome.canonicalKey, /^exec-local\|signature@1:/);
    assert.equal(tp.project.file().counters.command, 1);
    const ledger = new Ledger(tp.project);
    assert.ok(ledger.getOutcome(outcome.id));
  } finally {
    tp.cleanup();
  }
});

test('oversized stdin rejects before reserving command budget', async () => {
  const tp = makeProject();
  try {
    await assert.rejects(
      runExec(tp.project, {
        argv: [NODE, '-e', 'console.log("never")'],
        stdin: 'x'.repeat(1024 * 1024 + 1),
      }),
      /stdin exceeds/,
    );
    assert.equal(tp.project.file().counters.command, 0);
  } finally {
    tp.cleanup();
  }
});

test('spawn failure releases reserved command budget', async () => {
  const tp = makeProject();
  try {
    await assert.rejects(
      runExec(tp.project, { argv: ['definitely-not-a-real-binary-zzz'] }),
      /spawn failed/,
    );
    assert.equal(tp.project.file().counters.command, 0);
  } finally {
    tp.cleanup();
  }
});

test('exec nonzero exit -> processFailure nonzero-exit', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, { argv: [NODE, '-e', 'process.exit(3)'] });
    assert.equal(outcome.exit, 3);
    assert.equal(outcome.processFailure, 'nonzero-exit');
    assert.equal(tp.project.file().counters.command, 1);
  } finally {
    tp.cleanup();
  }
});

test('exec timeout -> SIGTERM tree kill, processFailure timeout', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, {
      argv: [NODE, '-e', 'setTimeout(() => {}, 30000)'],
      timeoutMs: 800,
    });
    assert.equal(outcome.processFailure, 'timeout');
    assert.ok(outcome.durationMs < 10_000);
  } finally {
    tp.cleanup();
  }
});

test('exec closed-port curl -> nonzero-exit with empty stdout (connection refused)', async () => {
  const tp = makeProject();
  try {
    // Real no-output-when-expected (exit 0 + empty body + contracted class)
    // is covered in regressions.test.ts against a local empty-body server;
    // a closed port yields nonzero-exit, which is the honest expectation here.
    const { outcome } = await runExec(tp.project, {
      command: 'curl -s http://127.0.0.1:9/x --max-time 2',
      timeoutMs: 10_000,
    });
    assert.equal(outcome.processFailure, 'nonzero-exit');
    assert.equal(outcome.stdout.bytes, 0);
    assert.ok(outcome.durationMs < 9_000);
  } finally {
    tp.cleanup();
  }
});

test('proxy env is inherited by default; PI4CTF_INHERIT_PROXY=0 opts out', () => {
  const old = {
    http: process.env.HTTP_PROXY,
    inherit: process.env.PI4CTF_INHERIT_PROXY,
    arena: process.env.CYBERARENA_TEAM_ID,
    noProxy: process.env.NO_PROXY,
  };
  try {
    process.env.HTTP_PROXY = 'http://127.0.0.1:3128';
    process.env.NO_PROXY = 'localhost,127.0.0.1,::1';
    delete process.env.PI4CTF_INHERIT_PROXY;
    delete process.env.CYBERARENA_TEAM_ID;
    assert.equal(baseEnv().HTTP_PROXY, 'http://127.0.0.1:3128');
    assert.equal(baseEnv().NO_PROXY, 'localhost,127.0.0.1,::1');
    process.env.PI4CTF_INHERIT_PROXY = '0';
    assert.equal(baseEnv().HTTP_PROXY, undefined);
  } finally {
    if (old.http === undefined) delete process.env.HTTP_PROXY;
    else process.env.HTTP_PROXY = old.http;
    if (old.inherit === undefined) delete process.env.PI4CTF_INHERIT_PROXY;
    else process.env.PI4CTF_INHERIT_PROXY = old.inherit;
    if (old.arena === undefined) delete process.env.CYBERARENA_TEAM_ID;
    else process.env.CYBERARENA_TEAM_ID = old.arena;
    if (old.noProxy === undefined) delete process.env.NO_PROXY;
    else process.env.NO_PROXY = old.noProxy;
  }
});

test('command mode preserves shell variables (no argv-level expansion)', async () => {
  const tp = makeProject();
  try {
    const { outcome, shapedStdout } = await runExec(tp.project, {
      command: 'for i in 1 2 3; do echo "i=$i"; done',
      timeoutMs: 10_000,
    });
    assert.equal(outcome.exit, 0);
    assert.equal(shapedStdout, 'i=1\ni=2\ni=3\n');
    assert.equal(fs.readdirSync(tp.project.ctfDir).some((n) => n.startsWith('.run-')), false);
  } finally {
    tp.cleanup();
  }
});

test('filter pipeline nonzero exit is not a process failure', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, {
      command: "printf 'x\\n' | grep -q z",
      timeoutMs: 10_000,
    });
    assert.equal(outcome.exit, 1);
    assert.equal(outcome.stdout.bytes, 0);
    assert.equal(outcome.processFailure, null);
  } finally {
    tp.cleanup();
  }
});

test('exec captures stderr separately from stdout', async () => {
  const tp = makeProject();
  try {
    const { outcome, shapedStderr } = await runExec(tp.project, {
      argv: [NODE, '-e', 'console.error("boom"); console.log("out")'],
    });
    assert.equal(shapedStderr, 'boom\n');
    assert.match(outcome.stdout.excerpt, /out/);
    assert.equal(outcome.stderr.excerpt, 'boom\n');
  } finally {
    tp.cleanup();
  }
});

test('exec binary stdout -> hex shaped artifact', async () => {
  const tp = makeProject();
  try {
    const { outcome } = await runExec(tp.project, {
      argv: [NODE, '-e', 'process.stdout.write(Buffer.from([0,1,2,255,254,10]))'],
    });
    assert.equal(outcome.stdout.encoding, 'hex');
    const ledger = new Ledger(tp.project);
    const shaped = ledger.readArtifact(outcome.stdout.shapedRef);
    assert.match(shaped, /\[BINARY 6 bytes/);
  } finally {
    tp.cleanup();
  }
});

test('ids are monotonic and events are appended', async () => {
  const tp = makeProject();
  try {
    const a = await runExec(tp.project, { argv: [NODE, '-e', ''] });
    const b = await runExec(tp.project, { argv: [NODE, '-e', ''] });
    assert.notEqual(a.outcome.id, b.outcome.id);
    const events = fs.readFileSync(path.join(tp.project.ctfDir, 'events.jsonl'), 'utf8').trim().split('\n');
    assert.ok(events.some((l) => JSON.parse(l).type === 'run.exec'));
    assert.ok(events.some((l) => JSON.parse(l).type === 'observation.classified'));
  } finally {
    tp.cleanup();
  }
});
