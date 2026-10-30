import { readJsonIfExists } from './fsutil.js';
import type { PlanBlock } from './types.js';

export function readPlanBlock(filePath: string): PlanBlock {
  return readJsonIfExists<PlanBlock>(filePath) ?? {
    chain: [],
    next: '',
    preconditions: [],
  };
}

export function normalizePlan(plan: PlanBlock): PlanBlock {
  return {
    chain: plan.chain.slice(0, 8).map((step) => step.slice(0, 200)),
    next: plan.next.slice(0, 300),
    preconditions: plan.preconditions.slice(0, 5).map((item) => item.slice(0, 150)),
  };
}
