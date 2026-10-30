/** time.delta predicate fixtures: fixed durations, clean-sample gates. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { ClaimVerifier } from '../kernel/claim/verifier.js';
import { Ledger } from '../kernel/ledger/store.js';
import type { Observation, ProcessOutcome } from '../kernel/types.js';
import { makeProject, type TestProject } from './helpers.js';

interface TimeCase {
  name: string;
  expected: 'interpreted' | 'rejected';
  target: string | null;
  durationsMs: number[];
  httpStatuses?: Array<number | null>;
  processFailures?: Array<'timeout' | null>;
  semanticFailures?: Array<'server-error' | null>;
  reason?: string;
}

interface TimeFixture {
  claimType: 'time-based';
  cases: TimeCase[];
}

function writeEvidence(tp: TestProject, c: TimeCase): string[] {
  for (const dir of ['artifacts', 'outcomes', 'observations']) {
    fs.mkdirSync(path.join(tp.project.ctfDir, dir), { recursive: true });
  }
  const refs: string[] = [];
  for (let i = 0; i < c.durationsMs.length; i += 1) {
    const { id } = tp.project.allocId('command');
    const stdoutRef = `artifacts/${id}.stdout.shaped.log`;
    const stderrRef = `artifacts/${id}.stderr.shaped.log`;
    fs.writeFileSync(path.join(tp.project.ctfDir, stdoutRef), '');
    fs.writeFileSync(path.join(tp.project.ctfDir, stderrRef), '');
    const stream = (which: 'stdout' | 'stderr'): ProcessOutcome['stdout'] => {
      const base = `artifacts/${id}.${which}`;
      return {
        sha256: '',
        bytes: 0,
        rawRef: `${base}.raw.log`,
        shapedRef: `${base}.shaped.log`,
        excerpt: '',
        encoding: 'utf8',
        truncated: false,
        outputTruncated: false,
      };
    };
    const outcome: ProcessOutcome = {
      id,
      argvTemplate: ['sleep', 'probe'],
      argvRaw: ['sleep', 'probe'],
      target: c.target,
      intentClass: 'generic',
      canonicalKey: `time-fixture|${id}`,
      exit: 0,
      signal: null,
      durationMs: c.durationsMs[i]!,
      shell: null,
      stdout: stream('stdout'),
      stderr: stream('stderr'),
      processFailure: c.processFailures?.[i] ?? null,
      synthetic: false,
      ts: Date.now() + i,
    };
    fs.writeFileSync(path.join(tp.project.ctfDir, `outcomes/${id}.json`), JSON.stringify(outcome, null, 2));
    const status = c.httpStatuses?.[i] ?? null;
    const observation: Observation = {
      outcomeId: id,
      commandClass: 'generic',
      contractId: null,
      parsed: status === null
        ? {}
        : { 'http.status': { value: status, shapedRef: stdoutRef, span: { start: 0, end: 0 } } },
      semanticFailure: c.semanticFailures?.[i] ?? null,
      semanticDetail: null,
    };
    fs.writeFileSync(
      path.join(tp.project.ctfDir, `observations/${id}.json`),
      JSON.stringify(observation, null, 2),
    );
    refs.push(id);
  }
  return refs;
}

test('time.delta requires a declared project target', () => {
  const tp = makeProject();
  try {
    const fixture = JSON.parse(
      fs.readFileSync(
        path.resolve(import.meta.dirname, '..', '..', 'fixtures', 'predicates', 'time-delta', 'accept.json'),
        'utf8',
      ),
    ) as TimeFixture;
    const c = fixture.cases[0]!;
    const refs = writeEvidence(tp, c);
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    const claim = verifier.submit({ claimType: 'time-based', text: c.name, quotes: [], refs });
    const result = verifier.verify(claim.id);
    assert.equal(result.state, 'rejected');
    assert.match(result.rejectedReason ?? '', /declared project target/);
  } finally {
    tp.cleanup();
  }
});

test('time.delta yields interpreted evidence for fixed 2x median and rejects every dirty shape', () => {
  const tp = makeProject({ target: { host: '127.0.0.1', port: 8080 } });
  try {
    const verifier = new ClaimVerifier(tp.project, new Ledger(tp.project));
    for (const file of ['accept.json', 'reject.json']) {
      const fixture = JSON.parse(
        fs.readFileSync(
          path.resolve(import.meta.dirname, '..', '..', 'fixtures', 'predicates', 'time-delta', file),
          'utf8',
        ),
      ) as TimeFixture;
      assert.equal(fixture.claimType, 'time-based');
      for (const c of fixture.cases) {
        const refs = writeEvidence(tp, c);
        const claim = verifier.submit({
          claimType: 'time-based',
          text: c.name,
          quotes: [],
          refs,
        });
        const result = verifier.verify(claim.id);
        assert.equal(result.state, c.expected, `${c.name}: ${result.rejectedReason ?? ''}`);
        if (c.reason) {
          assert.match(result.rejectedReason ?? '', new RegExp(c.reason), c.name);
        }
      }
    }
    assert.equal(new Ledger(tp.project).listFacts().length, 0, 'time-based must not mint a Fact');
  } finally {
    tp.cleanup();
  }
});
