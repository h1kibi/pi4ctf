import { KernelError } from './error.js';
import { Project } from './project.js';
import { TURN_BUDGET } from './types.js';

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
