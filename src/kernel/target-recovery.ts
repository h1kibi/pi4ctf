/** Target self-heal: optional user-owned reset endpoint + bounded recovery. */
import * as path from 'node:path';
import { MAX_TARGET_RESETS } from './types.js';
import { oracleReset, readOracle } from './oracle.js';
import { checkReachable, targetRef } from './target.js';
import type { Project } from './project.js';
import type { TargetSpec } from './types.js';

export interface TargetRecovery {
  attempted: boolean;
  recovered: boolean;
  detail: string;
}

const POLL_MS = 500;

/**
 * A target crash is often only observable on the next run. If the oracle
 * carries a reset hook, invoke it once (capped per case) and poll TCP before
 * deciding that the target is still dead. No hook means no invented recovery.
 */
export async function recoverTarget(
  project: Project,
  target: TargetSpec,
  checkTimeoutMs = 2000,
  maxWaitMs = 30_000,
): Promise<TargetRecovery> {
  const file = project.file();
  const oracle = readOracle(path.resolve(project.root, file.oracle.ref))?.oracle;
  const reset = oracle ? oracleReset(oracle) : null;
  if (!reset) return { attempted: false, recovered: false, detail: 'oracle has no reset hook' };
  const used = file.counters.targetReset ?? 0;
  if (used >= MAX_TARGET_RESETS) {
    return { attempted: false, recovered: false, detail: `reset limit reached (${used}/${MAX_TARGET_RESETS})` };
  }

  const attempt = project.recordTargetReset();
  let httpStatus: number | null = null;
  let resetError: string | null = null;
  try {
    const response = await fetch(reset.url, {
      method: reset.method ?? 'POST',
      headers: reset.headers,
      body: reset.body,
      signal: AbortSignal.timeout(reset.timeoutMs ?? 15_000),
    });
    httpStatus = response.status;
    if (!response.ok) resetError = `reset endpoint returned ${response.status}`;
  } catch (err) {
    resetError = err instanceof Error ? err.message : String(err);
  }

  const deadline = Date.now() + maxWaitMs;
  while (!resetError && Date.now() < deadline) {
    const reach = await checkReachable(target, checkTimeoutMs);
    if (reach.checked && reach.ok) {
      project.appendEvent('target.recover', 'kernel', {
        target: targetRef(target),
        attempt,
        status: 'recovered',
        httpStatus,
      });
      return { attempted: true, recovered: true, detail: `reset hook accepted (HTTP ${httpStatus ?? 'n/a'})` };
    }
    const sleep = Promise.withResolvers<void>();
    setTimeout(sleep.resolve, POLL_MS);
    await sleep.promise;
  }

  project.appendEvent('target.recover', 'kernel', {
    target: targetRef(target),
    attempt,
    status: 'failed',
    httpStatus,
    error: resetError,
  });
  return {
    attempted: true,
    recovered: false,
    detail: resetError ?? `target still unreachable after ${Math.round(maxWaitMs / 1000)}s`,
  };
}
