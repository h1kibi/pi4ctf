import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from './error.js';
import type { ProjectFile } from './types.js';
import { TURN_BUDGET } from './types.js';

/** Largest existing cmd-NNNN id; keeps restart non-destructive. */
export function maxCommandSeq(ctfDir: string): number {
  const dir = path.join(ctfDir, 'outcomes');
  if (!fs.existsSync(dir)) return 0;
  let max = 0;
  for (const name of fs.readdirSync(dir)) {
    const m = /^cmd-(\d+)\.json$/.exec(name);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return max;
}

/** Increment the command counter and return the next id sequence.
 *  Budget and deadline are checked under the caller's project lock. */
export function allocateCommand(file: ProjectFile, ctfDir: string, enforceBudget: boolean): number {
  if (enforceBudget) {
    if (file.status !== 'active') {
      throw new KernelError('CONFLICT', `case is ${file.status}; command allocation requires an active case`);
    }
    const turns = file.counters.command ?? 0;
    if (turns >= TURN_BUDGET) {
      throw new KernelError('LIMIT', `turn budget exhausted (${turns}/${TURN_BUDGET} commands); case must restart or close`);
    }
    if (file.deadlineMs !== null && Date.now() > file.deadlineMs - 60_000) {
      throw new KernelError('TIMEOUT', 'deadline reached; case must restart or close');
    }
  }
  file.counters.command = (file.counters.command ?? 0) + 1;
  const prior = Math.max(file.counters.commandSeq ?? 0, maxCommandSeq(ctfDir));
  const seq = prior + 1;
  file.counters.commandSeq = seq;
  return seq;
}
