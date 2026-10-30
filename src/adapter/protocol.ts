/**
 * JSON protocol adapter for pi4ctf.
 *
 * This module owns only the external seam: kernel-only authorization, explicit
 * operation routing, and conversion of thrown errors to protocol responses.
 * Operation policy and behavior live in static handlers under ./handlers.
 */
import { toErrorResponse, KernelError } from '../kernel/error.js';
import { assertNotKernelOnly } from '../kernel/security.js';
import { safeOpen } from './helpers.js';
import { handleCase } from './handlers/case.js';
import { handleClaim } from './handlers/claim.js';
import { handleEnv } from './handlers/env.js';
import { handleFlag } from './handlers/flag.js';
import { handleRun } from './handlers/run.js';
import type { Request, Response } from './types.js';

export type { OkResponse, Request, Response } from './types.js';
export { assertCaseBudget } from './policy.js';

export async function dispatch(req: Request): Promise<Response> {
  try {
    return await dispatchInner(req);
  } catch (err) {
    return toErrorResponse(err);
  }
}

async function dispatchInner(req: Request): Promise<Response> {
  const { op } = req;
  const input = req.input ?? {};
  const projectOrNull = req.root ? safeOpen(req.root) : null;
  assertNotKernelOnly(projectOrNull, op);

  if (op === 'run') return handleRun(req, op, input);
  if (op === 'claim') return handleClaim(req, op, input);
  if (op === 'flag') return handleFlag(req, op, input);
  if (op === 'env.memory') return handleEnv(req, op, input);

  if (
    op === 'project.init' ||
    op === 'project.status' ||
    op === 'project.close' ||
    op === 'case.close' ||
    op === 'case.restart' ||
    op === 'case.resetBudget' ||
    op === 'case.configure' ||
    op === 'case.clearNegatives' ||
    op === 'case.plan' ||
    op === 'case.evidence' ||
    op === 'proc' ||
    op === 'case.preflight' ||
    op === 'case.context' ||
    op === 'artifact.ingest' ||
    op === 'case.handoff' ||
    op === 'case.complete' ||
    op === 'case.doctor'
  ) {
    return handleCase(req, op, input);
  }

  throw new KernelError('INVALID_REQUEST', `unknown op: ${op}`);
}
