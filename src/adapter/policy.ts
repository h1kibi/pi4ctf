import { KernelError } from '../kernel/error.js';
import { recoverTarget } from '../kernel/target-recovery.js';
import { checkReachable, type Reachability } from '../kernel/target.js';
import { Project } from '../kernel/project.js';
import type { TargetSpec } from '../kernel/types.js';
import { TURN_BUDGET } from '../kernel/types.js';

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
