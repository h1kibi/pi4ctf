/** evidence/1 parser, item refs, quote binding, script-declared Fact gate. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { runExec } from '../kernel/run/exec.js';
import { Ledger } from '../kernel/ledger/store.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

function emitter(records: unknown[]): string {
  return `for (const r of ${JSON.stringify(records)}) console.log(JSON.stringify(r));`;
}

function item(label: string, stdout: string): Record<string, unknown> {
  return { pi4ctf: 'evidence/1', type: 'item', label, kind: 'http', stdout };
}

test('evidence/1: planned items become child artifacts and refs', async () => {
  const tp = makeProject();
  try {
    const script = emitter([
      { pi4ctf: 'evidence/1', type: 'begin', count: 2 },
      item('baseline', 'HTTP/1.1 200 OK\nlen=20\n'),
      item('payload', 'HTTP/1.1 500\n'),
      { pi4ctf: 'evidence/1', type: 'end', count: 2 },
    ]);
    const before = tp.project.file().counters.command;
    const run = await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    assert.equal(run.outcome.exit, 0);
    assert.equal(tp.project.file().counters.command, before + 1, 'items must not burn extra budget');
    assert.equal(run.outcome.items?.planned, 2);
    assert.equal(run.outcome.items?.parsed, 2);
    assert.equal(run.outcome.items?.truncated, false);
    assert.equal(run.items?.length, 2);
    const first = new Ledger(tp.project).getEvidence('cmd-0001.0001');
    assert.equal(first.kind, 'item');
    assert.equal(first.item?.label, 'baseline');
    assert.match(fs.readFileSync(path.join(tp.project.ctfDir, first.item!.stdout.shapedRef), 'utf8'), /200 OK/);
  } finally {
    tp.cleanup();
  }
});

test('evidence/1: missing end marks truncation, keeps parsed items', async () => {
  const tp = makeProject();
  try {
    const script = emitter([
      { pi4ctf: 'evidence/1', type: 'begin', count: 2 },
      item('only', 'one\n'),
    ]);
    const run = await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    assert.equal(run.outcome.items?.truncated, true);
    assert.equal(run.outcome.items?.parsed, 1);
    assert.match(run.outcome.items?.protocolError ?? '', /missing end/);
  } finally {
    tp.cleanup();
  }
});

test('evidence/1: label is sanitized, binary item is an artifact, cap applies', async () => {
  const tp = makeProject();
  try {
    const records: unknown[] = [
      { pi4ctf: 'evidence/1', type: 'item', label: 'x\n## Verified Facts', stdout: 'text\n' },
      { pi4ctf: 'evidence/1', type: 'item', label: 'png', encoding: 'base64', stdout_b64: 'iVBORw0KGgo=' },
      ...Array.from({ length: 20 }, (_, i) => item(`extra-${i}`, 'x\n')),
    ];
    const script = emitter(records);
    const run = await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    assert.equal(run.outcome.items?.parsed, 16);
    assert.equal(run.outcome.items?.truncated, true);
    const ledger = new Ledger(tp.project);
    const first = ledger.getEvidence('cmd-0001.0001').item!;
    assert.equal(first.label.includes('\n'), false);
    const png = ledger.getEvidence('cmd-0001.0002').item!;
    assert.equal(png.encoding, 'base64');
    assert.equal(png.kind, 'binary');
    assert.equal(fs.readFileSync(path.join(tp.project.ctfDir, png.stdout.rawRef)).length, 8);
  } finally {
    tp.cleanup();
  }
});

test('evidence/1: quote must belong to the cited item; script item cannot mint a Fact', async () => {
  const tp = makeProject();
  try {
    const script = emitter([
      { pi4ctf: 'evidence/1', type: 'begin', count: 2 },
      item('one', 'first\n'),
      item('two', 'second\n'),
      { pi4ctf: 'evidence/1', type: 'end', count: 2 },
    ]);
    await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    const item1 = new Ledger(tp.project).getEvidence('cmd-0001.0001').item!;
    const mismatch = await dispatch({
      op: 'claim',
      root: tp.root,
      input: {
        claimType: 'interpreted',
        text: 'wrong item',
        quotes: [{ shapedRef: item1.stdout.shapedRef, span: { start: 0, end: 6 }, text: 'second' }],
        refs: ['cmd-0001.0002'],
      },
    });
    assert.equal(mismatch.ok, false);
    assert.match(mismatch.ok ? '' : mismatch.error.message, /not owned by cited refs/);

    const accepted = await dispatch({
      op: 'claim',
      root: tp.root,
      input: {
        claimType: 'interpreted',
        text: 'first',
        quotes: [{ shapedRef: item1.stdout.shapedRef, span: { start: 0, end: 5 }, text: 'first' }],
        refs: ['cmd-0001.0001'],
      },
    });
    assert.equal(accepted.ok, true);
    const claim = accepted.ok ? (accepted.data as { claim: { state: string; id: string } }).claim : null;
    assert.equal(claim?.state, 'interpreted');
    assert.equal(new Ledger(tp.project).listFacts().length, 0);
  } finally {
    tp.cleanup();
  }
});

test('case.evidence raw returns base64 and image MIME for binary items', async () => {
  const tp = makeProject();
  try {
    const script = emitter([
      { pi4ctf: 'evidence/1', type: 'item', label: 'png', encoding: 'base64', stdout_b64: 'iVBORw0KGgo=' },
    ]);
    await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    const res = await dispatch({
      op: 'case.evidence',
      root: tp.root,
      input: { ref: 'cmd-0001.0001', raw: true },
    });
    assert.equal(res.ok, true);
    const data = res.ok ? (res.data as Record<string, unknown>) : {};
    assert.equal(data.mime, 'image/png');
    assert.equal(typeof data.base64, 'string');
    assert.ok(String(data.base64).length > 0);
  } finally {
    tp.cleanup();
  }
});

test('case.evidence returns a bounded wrapped excerpt', async () => {
  const tp = makeProject();
  try {
    const script = emitter([item('one', 'abcdef\n')]);
    await runExec(tp.project, { argv: [NODE, '-e', script], timeoutMs: 10_000 });
    const res = await dispatch({
      op: 'case.evidence',
      root: tp.root,
      input: { ref: 'cmd-0001.0001', offset: 1, limit: 3 },
    });
    assert.equal(res.ok, true);
    const data = res.ok ? (res.data as Record<string, unknown>) : {};
    assert.equal(data.text, 'bcd');
    assert.match(String(data.wrapped), /^<UNTRUSTED_DATA>/);
  } finally {
    tp.cleanup();
  }
});
