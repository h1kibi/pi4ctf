import { KernelError } from '../kernel/error.js';
import { recoverTarget } from '../kernel/target-recovery.js';
import { checkReachable, type Reachability } from '../kernel/target.js';
import { Project } from '../kernel/project.js';
import type { FailureClass, NegativeEntry, TargetSpec } from '../kernel/types.js';
import { TURN_BUDGET } from '../kernel/types.js';

const TTL_TRANSIENT_MS = 10 * 60_000;
const TTL_SERVER_ERROR_MS = 60_000;
const TTL_CLIENT_BLOCKED_MS = 5 * 60_000;

/** External termination conditions enforced before execution. */
export function assertCaseBudget(project: Project): void {
  const file = project.file();
  if (file.status !== 'active') {
    throw new KernelError('CONFLICT', `case is ${file.status}; run requires an active case`);
  }
  const turns = file.counters.command ?? 0;
  if (turns >= TURN_BUDGET) {
    throw new KernelError('LIMIT', `turn budget exhausted (${turns}/${TURN_BUDGET} commands); case must restart or close`);
  }
  if (file.deadlineMs !== null && Date.now() > file.deadlineMs - 60_000) {
    throw new KernelError('TIMEOUT', 'deadline reached; case must restart or close');
  }
}

export interface NegativeSpec {
  failureClass: FailureClass;
  family: 'environment' | 'approach';
  transient: boolean;
  unblockOn: NegativeEntry['unblockOn'];
  ttlMs: number | null;
}

/** Code-owned negative-entry policy for a failed outcome. */
export function negativeSpecFor(
  processFailure: string | null,
  semanticFailure: string | null,
): NegativeSpec {
  switch (semanticFailure) {
    case 'target-unreachable':
      return { failureClass: 'timeout', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
    case 'server-error':
      return { failureClass: 'server-error', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_SERVER_ERROR_MS };
    case 'client-blocked':
      return { failureClass: 'client-blocked', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_CLIENT_BLOCKED_MS };
    case 'tty-required':
      return { failureClass: 'tty-required', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
    case 'schema-mismatch':
      return { failureClass: 'schema-mismatch', family: 'approach', transient: false, unblockOn: 'env_change', ttlMs: null };
    case 'probe-contradicted':
      return { failureClass: 'probe-contradicted', family: 'approach', transient: false, unblockOn: 'probe_version', ttlMs: null };
  }
  if (processFailure === 'timeout') {
    return { failureClass: 'timeout', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
  }
  if (processFailure === 'nonzero-exit') {
    return { failureClass: 'nonzero-exit', family: 'approach', transient: true, unblockOn: 'probe', ttlMs: TTL_TRANSIENT_MS };
  }
  if (processFailure === 'no-output-when-expected') {
    return { failureClass: 'no-output', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
  }
  return { failureClass: 'probe-contradicted', family: 'approach', transient: false, unblockOn: 'probe_version', ttlMs: null };
}

export function routeSignature(intentClass: string, signature: string): string {
  return `${intentClass}|signature@1:${signature}`;
}

/** Reachability policy shared by configure, run, and flag. */
export async function reachabilityWithRecovery(
  project: Project,
  target: TargetSpec,
  timeoutMs: number,
  backend: 'host' | 'docker',
): Promise<{ reach: Reachability; warnings: string[] }> {
  let reach = await checkReachable(target, timeoutMs);
  if (!reach.checked || reach.ok) return { reach, warnings: [] };
  if (backend === 'docker') return { reach, warnings: [] };
  const recovery = await recoverTarget(project, target, timeoutMs);
  if (!recovery.attempted) return { reach, warnings: [] };
  if (recovery.recovered) {
    reach = await checkReachable(target, timeoutMs);
    if (reach.checked && reach.ok) {
      return { reach, warnings: [`target reset recovered the instance (${recovery.detail})`] };
    }
  }
  return { reach, warnings: [`target reset failed: ${recovery.detail}`] };
}
