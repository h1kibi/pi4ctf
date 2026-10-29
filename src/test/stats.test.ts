/** Cross-case budget baseline: recorded only for flag-accepted completes. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { runExec } from '../kernel/run/exec.js';
import { categoryMedian, recordSolve } from '../kernel/stats.js';
import { compilePacket } from '../kernel/context/packet.js';
import { Ledger } from '../kernel/ledger/store.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('solve stats are written only on accepted completion and produce a category median', async () => {
  const statsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-stats-'));
  const previous = process.env.PI4CTF_STATS_PATH;
  process.env.PI4CTF_STATS_PATH = path.join(statsDir, 'solve-stats.jsonl');
  try {
    const one = makeProject();
    const three = makeProject();
    try {
      await runExec(one.project, { argv: [NODE, '-e', ''] });
      for (let i = 0; i < 3; i++) await runExec(three.project, { argv: [NODE, '-e', ''] });
      recordSolve(one.project, false);
      assert.equal(categoryMedian('web'), null, 'failed closes must not enter the baseline');
      recordSolve(one.project, true);
      recordSolve(three.project, true);
      const baseline = categoryMedian('web');
      assert.deepEqual(baseline, { median: 2, n: 2 });
      const packet = compilePacket(one.project, new Ledger(one.project));
      assert.match(packet.text, /category web: median 2 runs to solve \(n=2\)/);
    } finally {
      one.cleanup();
      three.cleanup();
    }
  } finally {
    if (previous === undefined) delete process.env.PI4CTF_STATS_PATH;
    else process.env.PI4CTF_STATS_PATH = previous;
    fs.rmSync(statsDir, { recursive: true, force: true });
  }
});
