/** External artifact ingest -> quote/claim/flag evidence chain. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { makeProject } from './helpers.js';

test('artifact.ingest creates a usable outcome and supports a full flag chain', async () => {
  const tp = makeProject();
  const outside = path.join(os.tmpdir(), `pi4ctf-ingest-${Date.now()}.txt`);
  try {
    fs.writeFileSync(outside, `webhook capture\n${tp.flag}\n`);
    const ingested = await dispatch({
      op: 'artifact.ingest',
      root: tp.root,
      input: { path: outside, name: 'webhook' },
    });
    assert.equal(ingested.ok, true, JSON.stringify(ingested));
    const data = ingested.ok ? (ingested.data as Record<string, unknown>) : {};
    const outcomeId = String(data.id);
    const artifact = String(data.artifact);
    assert.match(fs.readFileSync(path.join(tp.root, '.ctf', artifact), 'utf8'), new RegExp(tp.flag));

    const claim = await dispatch({
      op: 'claim',
      root: tp.root,
      input: {
        claimType: 'observed',
        text: 'the webhook artifact was ingested cleanly',
        quotes: [],
        refs: [outcomeId],
      },
    });
    assert.equal(claim.ok, true, JSON.stringify(claim));
    const claimData = claim.ok ? (claim.data as { claim?: { state?: string } }) : {};
    assert.equal(claimData.claim?.state, 'accepted');
    const factId = fs.readdirSync(path.join(tp.root, '.ctf', 'facts'))
      .map((n) => JSON.parse(fs.readFileSync(path.join(tp.root, '.ctf', 'facts', n), 'utf8')).id)
      .find(Boolean);
    assert.ok(factId);

    const flag = await dispatch({
      op: 'flag',
      root: tp.root,
      input: { value: tp.flag, evidenceRefs: [String(factId)] },
    });
    assert.equal(flag.ok, true, JSON.stringify(flag));
  } finally {
    tp.cleanup();
    fs.rmSync(outside, { force: true });
  }
});


test('artifact.ingest transform records source hash and decodes hex', async () => {
  const tp = makeProject();
  const outside = path.join(os.tmpdir(), `pi4ctf-hex-${Date.now()}.txt`);
  try {
    fs.writeFileSync(outside, Buffer.from(`derived\n${tp.flag}\n`, 'utf8').toString('hex'));
    const ingested = await dispatch({
      op: 'artifact.ingest',
      root: tp.root,
      input: { path: outside, name: 'hex', transform: 'hex' },
    });
    assert.equal(ingested.ok, true, JSON.stringify(ingested));
    const data = ingested.ok ? (ingested.data as Record<string, unknown>) : {};
    assert.equal(data.transform, 'hex');
    assert.match(String(data.sourceSha256), /^[0-9a-f]{64}$/);
    const artifact = String(data.artifact);
    assert.match(fs.readFileSync(path.join(tp.root, '.ctf', artifact), 'utf8'), new RegExp(tp.flag));
    const outcome = JSON.parse(fs.readFileSync(path.join(tp.root, '.ctf', 'outcomes', String(data.id) + '.json'), 'utf8')) as { derivedFrom?: { sha256: string; transform: string } };
    assert.equal(outcome.derivedFrom?.transform, 'hex');
    assert.equal(outcome.derivedFrom?.sha256, data.sourceSha256);

    const claim = await dispatch({
      op: 'claim',
      root: tp.root,
      input: { claimType: 'observed', text: 'derived hex artifact is readable', quotes: [], refs: [String(data.id)] },
    });
    assert.equal(claim.ok, true, JSON.stringify(claim));
    const factId = fs.readdirSync(path.join(tp.root, '.ctf', 'facts'))
      .map((n) => JSON.parse(fs.readFileSync(path.join(tp.root, '.ctf', 'facts', n), 'utf8')).id)
      .find(Boolean);
    const flag = await dispatch({ op: 'flag', root: tp.root, input: { value: tp.flag, evidenceRefs: [String(factId)] } });
    assert.equal(flag.ok, true, JSON.stringify(flag));
  } finally {
    tp.cleanup();
    fs.rmSync(outside, { force: true });
  }
});

test('artifact.ingest refuses the case oracle and .ctf state', async () => {
  const tp = makeProject();
  try {
    const oracleRel = path.relative(tp.root, tp.oraclePath);
    const oracle = await dispatch({ op: 'artifact.ingest', root: tp.root, input: { path: oracleRel } });
    assert.equal(oracle.ok, false);
    assert.equal(oracle.ok ? '' : oracle.error.code, 'SECURITY');

    const state = await dispatch({ op: 'artifact.ingest', root: tp.root, input: { path: '.ctf/project.json' } });
    assert.equal(state.ok, false);
    assert.equal(state.ok ? '' : state.error.code, 'SECURITY');
  } finally {
    tp.cleanup();
  }
});

test('artifact.ingest refuses files outside workspace, temp and configured roots', async () => {
  const tp = makeProject();
  const outsideDir = fs.mkdtempSync(path.join(os.homedir(), '.pi4ctf-ingest-'));
  const outside = path.join(outsideDir, 'outside.txt');
  try {
    fs.writeFileSync(outside, 'outside\n');
    const res = await dispatch({ op: 'artifact.ingest', root: tp.root, input: { path: outside } });
    assert.equal(res.ok, false);
    assert.equal(res.ok ? '' : res.error.code, 'SECURITY');
  } finally {
    tp.cleanup();
    fs.rmSync(outsideDir, { recursive: true, force: true });
  }
});
