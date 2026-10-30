/** Kernel-executed probe batches: kernel-owned items, differential, negative. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { after, before, test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { commandClassOf } from '../kernel/classify/classify.js';
import { Ledger } from '../kernel/ledger/store.js';
import { signature } from '../kernel/shape/signature.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;
let server: http.Server;
let port = 0;

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/fail') {
      res.writeHead(500);
      res.end('boom');
      return;
    }
    const body = req.url === '/long' ? 'y'.repeat(40) : 'x'.repeat(10);
    res.writeHead(200);
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as import('node:net').AddressInfo).port;
});

after(() => server.close());

test('kernel probes: item differential produces a Fact with hashes', async () => {
  const tp = makeProject();
  try {
    const before = tp.project.file().counters.command;
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          { label: 'base', argv: [NODE, '-e', "console.log('x'.repeat(10))"] },
          { label: 'probe', argv: [NODE, '-e', "console.log('x'.repeat(20))"] },
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    assert.equal(tp.project.file().counters.command, before + 1);
    const data = run.ok ? (run.data as Record<string, unknown>) : {};
    assert.equal((data.itemIndex as { provenance?: string }).provenance, 'kernel');
    const item = new Ledger(tp.project).getEvidence('cmd-0001.0001').item!;
    assert.ok(item.observationRef && fs.existsSync(path.join(tp.project.ctfDir, item.observationRef)));
    const claim = await dispatch({
      op: 'claim',
      root: tp.root,
      input: {
        claimType: 'differential',
        text: 'item lengths differ',
        quotes: [],
        refs: ['cmd-0001.0001', 'cmd-0001.0002'],
      },
    });
    assert.equal(claim.ok, true, JSON.stringify(claim));
    const parentEvidence = await dispatch({ op: 'case.evidence', root: tp.root, input: { ref: 'cmd-0001' } });
    assert.equal(parentEvidence.ok, true);
    assert.equal(parentEvidence.ok && parentEvidence.data.batch, true);
    assert.deepEqual(parentEvidence.ok ? parentEvidence.data.children : [], ['cmd-0001.0001', 'cmd-0001.0002']);
    const batchGrep = await dispatch({ op: 'case.evidence', root: tp.root, input: { ref: 'cmd-0001', grep: 'x', maxMatches: 5 } });
    assert.equal(batchGrep.ok, true);
    assert.equal(batchGrep.ok && batchGrep.data.matchCount, 2);
    assert.deepEqual(batchGrep.ok ? (batchGrep.data.matches as Array<{ ref: string }>).map((m) => m.ref) : [], ['cmd-0001.0001', 'cmd-0001.0002']);
    const facts = new Ledger(tp.project).listFacts();
    assert.equal(facts.length, 1);
    assert.equal(Object.keys(facts[0]!.artifactHashes).length >= 2, true);
  } finally {
    tp.cleanup();
  }
});

test('kernel probes: item-level server-error enters the negative ledger', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          { label: 'ok', argv: ['curl', '-si', `http://127.0.0.1:${port}/ok`] },
          { label: 'fail', argv: ['curl', '-si', `http://127.0.0.1:${port}/fail`] },
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? (run.data as { itemFailures?: number; items?: Array<{ status?: unknown }> }) : {};
    assert.equal(data.itemFailures, 1);
    const negs = new Ledger(tp.project).listNegatives();
    assert.ok(negs.some((n) => n.failureClass === 'server-error'));
  } finally {
    tp.cleanup();
  }
});

test('kernel probes: hard-blocked command does not execute', async () => {
  const tp = makeProject();
  try {
    const argv = [NODE, '-e', 'require("fs").writeFileSync("probe-blocked.txt","x")'];
    new Ledger(tp.project).addNegative({
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
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: { probes: [{ label: 'blocked', argv }] },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? run.data as { errors?: Array<{ message: string }>; itemCount?: number } : {};
    assert.equal(data.itemCount, 0);
    assert.match(data.errors?.[0]?.message ?? '', /probe hard-blocked/);
    assert.equal(fs.existsSync(path.join(tp.root, 'probe-blocked.txt')), false);
  } finally {
    tp.cleanup();
  }
});

test('kernel probes: hard-blocked HTTP does not reach the target', async () => {
  const tp = makeProject();
  let hits = 0;
  const server = http.createServer((_req, res) => {
    hits += 1;
    res.end('x');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  try {
    const url = `http://127.0.0.1:${port}/blocked`;
    new Ledger(tp.project).addNegative({
      signature: `http-probe|signature@1:${signature(['http', 'GET', url]).signature}`,
      failureClass: 'schema-mismatch',
      transient: false,
      condemnedBy: 'test',
      unblockOn: 'env_change',
      expiresAt: null,
      blockScope: 'route',
      artifactRef: null,
      route: null,
    });
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: { probes: [{ label: 'blocked-http', http: { url } }] },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? run.data as { errors?: Array<{ message: string }>; itemCount?: number } : {};
    assert.equal(data.itemCount, 0);
    assert.match(data.errors?.[0]?.message ?? '', /probe hard-blocked/);
    assert.equal(hits, 0);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    tp.cleanup();
  }
});

test('kernel probes: concurrency preserves order and cleans command scripts', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        concurrency: 3,
        probes: [
          { label: 'a', command: "printf 'a\\n'" },
          { label: 'b', command: "printf 'b\\n'" },
          { label: 'c', command: "printf 'c\\n'" },
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? (run.data as { items?: Array<{ label: string; id: string }> }) : {};
    assert.deepEqual(data.items?.map((i) => i.label), ['a', 'b', 'c']);
    assert.equal(fs.readdirSync(tp.project.ctfDir).some((n) => n.startsWith('.run-')), false);
  } finally {
    tp.cleanup();
  }
});

test('kernel probes: batch timeout stops remaining probes and marks truncation', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        timeoutMs: 100,
        probes: [
          { label: 'slow', argv: [NODE, '-e', 'setTimeout(() => {}, 5000)'] },
          { label: 'never', argv: [NODE, '-e', 'console.log("never")'] },
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? (run.data as { itemCount?: number; itemIndex?: { truncated?: boolean; planned?: number; parsed?: number }; incomplete?: Array<{ index: number; status: string }>; notRun?: number[]; completed?: string[]; errors?: unknown[] }) : {};
    assert.equal(data.itemCount, 1);
    assert.equal(data.itemIndex?.planned, 2);
    assert.equal(data.itemIndex?.parsed, 1);
    assert.equal(data.itemIndex?.truncated, true);
    assert.deepEqual(data.notRun, [2]);
    assert.equal(data.incomplete?.[0]?.status, 'notRun');
    assert.equal(data.completed?.length, 1);
    assert.deepEqual(data.errors, []);
  } finally {
    tp.cleanup();
  }
});

test('kernel probes: more than 16 is rejected', async () => {
  const tp = makeProject();
  try {
    const res = await dispatch({
      op: 'run',
      root: tp.root,
      input: { probes: Array.from({ length: 17 }, (_, i) => ({ label: `p${i}`, argv: [NODE, '-e', ''] })) },
    });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'LIMIT');
  } finally {
    tp.cleanup();
  }
});


test('kernel probes: completed batch is not truncated by summary emission', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: Array.from({ length: 8 }, (_, i) => ({ label: `p${i}`, argv: [NODE, '-e', `console.log(${i})`] })),
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? (run.data as {
      items?: Array<{ label: string }>;
      itemCount?: number;
      notRun?: number[];
      incomplete?: unknown[];
      itemIndex?: { truncated?: boolean; protocolError?: string | null };
    }) : {};
    assert.equal(data.itemCount, 8);
    assert.equal(data.items?.length, 8);
    assert.deepEqual(data.notRun, []);
    assert.deepEqual(data.incomplete, []);
    assert.equal(data.itemIndex?.truncated, false);
    assert.equal(data.itemIndex?.protocolError, null);
  } finally {
    tp.cleanup();
  }
});


test('kernel probes: one bad probe does not reject the batch or lose the good item', async () => {
  const tp = makeProject();
  try {
    const before = tp.project.file().counters.command;
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          { label: 'bad', argv: [] },
          { label: 'good', argv: [NODE, '-e', 'console.log("still-here")'] },
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const data = run.ok ? (run.data as {
      itemCount?: number;
      items?: Array<{ label: string }>;
      errors?: Array<{ index: number; message: string }>;
      incomplete?: Array<{ index: number; status: string }>;
      notRun?: number[];
    }) : {};
    assert.equal(data.itemCount, 1);
    assert.equal(data.items?.[0]?.label, 'good');
    assert.equal(data.errors?.[0]?.index, 1);
    assert.equal(data.incomplete?.find((i) => i.index === 1)?.status, 'error');
    assert.deepEqual(data.notRun, []);
    assert.equal(tp.project.file().counters.command, before + 1);
  } finally {
    tp.cleanup();
  }
});
