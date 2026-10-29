/** Execution and ownership context for environment memory. */
import { execHostOf, type ExecHost } from '../../kernel/run/exec.js';
import type { Project } from '../../kernel/project.js';

/**
 * The environment provider needs where to probe and which caller owns the
 * record. It does not need challenge state, ledgers, oracle data, or budgets.
 */
export interface EnvContext {
  /** Backend launch context used for internal probes. */
  host: ExecHost;
  /** Writer identity used for provenance and foreign-record markers. */
  origin: string;
  /** Root user-declared tool paths must stay outside of. */
  protectedRoot: string;
}

/** Context for a challenge project: probe through its backend, attribute to its id. */
export function envContextOf(project: Project): EnvContext {
  return { host: execHostOf(project), origin: project.file().id, protectedRoot: project.root };
}
