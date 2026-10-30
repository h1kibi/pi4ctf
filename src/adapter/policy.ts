import { recoverTarget } from '../kernel/target-recovery.js';
import { checkReachable, type Reachability } from '../kernel/target.js';
import { Project } from '../kernel/project.js';
import type { TargetSpec } from '../kernel/types.js';

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
