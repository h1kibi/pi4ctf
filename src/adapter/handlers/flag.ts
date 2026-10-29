import { KernelError } from '../../kernel/error.js';
import { Ledger } from '../../kernel/ledger/store.js';
import { submitFlag } from '../../kernel/flag/flag.js';
import { reachabilityWithRecovery } from '../policy.js';
import type { Request, Response } from '../types.js';
import { failedLayers, needRoot, ok, str } from '../helpers.js';
export async function handleFlag(req: Request, op: string, input: Record<string, unknown>): Promise<Response> {
  if (op !== 'flag') throw new Error(`unexpected flag op: ${op}`);
  const project = needRoot(req);
  const target = project.file().target ?? null;
  const warnings: string[] = [];
  if (target) {
    const n = Number(input.targetTimeoutMs);
    const targetTimeoutMs = Number.isFinite(n) ? Math.min(30_000, Math.max(100, n)) : 2000;
    const checked = await reachabilityWithRecovery(project, target, targetTimeoutMs, project.file().backend);
    warnings.push(...checked.warnings);
    const reach = checked.reach;
    if (reach.checked && !reach.ok) {
      const message = `target ${target.host}${target.port ? `:${target.port}` : ''} is unreachable from the host (${reach.error ?? 'unknown'})`;
      if (project.file().backend === 'docker') {
        warnings.push(`${message}; backend=docker may still reach it, continuing without host-side proof`);
      } else {
        throw new KernelError('TARGET_UNREACHABLE', `${message}; refusing to validate a flag against a dead instance`);
      }
    }
  }
  const value = str(input, 'value');
  const verdict = submitFlag(project, new Ledger(project), {
    value,
    sourceRef: input.sourceRef ? String(input.sourceRef) : null,
    evidenceRefs: Array.isArray(input.evidenceRefs) ? (input.evidenceRefs as unknown[]).map(String) : [],
  });
  const formatChange = project.lastFormatChange();
  const formatAudit = formatChange
    ? { formatConfiguredAt: formatChange.ts, formatConfiguredBy: formatChange.actor }
    : {};
  const layersPassed = Object.values(verdict.layers).filter(Boolean).length;
  if (verdict.status === 'rejected') {
    return {
      ok: false,
      error: {
        code: 'FLAG_REJECTED',
        message: `flag rejected: ${failedLayers(verdict.layers, verdict.detail)}`,
        details: { layers: verdict.layers, layersPassed, detail: verdict.detail, ...formatAudit },
      },
    };
  }
  if (verdict.status === 'unverified') {
    return ok(op, {
      status: 'unverified',
      verified: false,
      layersPassed,
      statusDetail: layersPassed === 4 ? 'evidence complete; oracle unavailable' : 'evidence incomplete',
      layers: verdict.layers,
      detail: verdict.detail,
      oracle: 'unavailable',
      flagTxt: null,
      warnings,
      ...formatAudit,
    });
  }
  return ok(op, {
    status: 'accepted',
    verified: true,
    layersPassed,
    layers: verdict.layers,
    flagTxt: '.ctf/flag.txt',
    warnings,
    ...formatAudit,
  });
}

