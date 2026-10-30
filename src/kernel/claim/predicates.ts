/**
 * Kernel-owned claim predicates (docs/design.md §4.4, ADR 0001 §2).
 *
 * The registry and pure checks live here; ClaimVerifier owns claim lifecycle,
 * quote validation, Facts, and NegativeEntries. Predicates receive a resolved
 * project target, so this module has no Project or ledger dependency.
 */
import { KernelError } from '../error.js';
import type { Claim, EvidenceItem, Observation, ProcessOutcome } from '../types.js';

export interface PredicateSpec {
  id: string; // name@semver
  claimTypes: string[];
  requiredEvidence: ('outcome' | 'quote')[];
}

export const PREDICATES: Record<string, PredicateSpec> = {
  'process.exit-zero@1.0.0': {
    id: 'process.exit-zero@1.0.0',
    claimTypes: ['observed'],
    requiredEvidence: ['outcome'],
  },
  'output.contains@1.0.0': {
    id: 'output.contains@1.0.0',
    claimTypes: ['interpreted'],
    requiredEvidence: ['outcome', 'quote'],
  },
  'http.length_delta@1.0.0': {
    id: 'http.length_delta@1.0.0',
    claimTypes: ['differential'],
    requiredEvidence: ['outcome'],
  },
};

/** claimType -> default predicate. Claims cannot pick a predicate the
 *  registry does not offer for their claimType. */
export function defaultPredicateFor(claimType: string): PredicateSpec {
  for (const spec of Object.values(PREDICATES)) {
    if (spec.claimTypes.includes(claimType)) return spec;
  }
  throw new KernelError('INVALID_REQUEST', `unknown claimType: ${claimType}`);
}

const LEN_DELTA_THRESHOLD = 0.1; // frozen threshold

export interface VerifyContext {
  outcomes: ProcessOutcome[];
  items: EvidenceItem[];
  observations: Map<string, Observation>;
  shapedTexts: Map<string, string>;
}

export interface PredicateResult {
  verdict: 'accepted' | 'rejected';
  reason: string;
  value: Record<string, unknown>;
}

export function runPredicate(
  spec: PredicateSpec,
  claim: Claim,
  ctx: VerifyContext,
  target: string | null,
): PredicateResult {
  switch (spec.id) {
    case 'process.exit-zero@1.0.0':
      return checkExitZero(ctx);
    case 'output.contains@1.0.0':
      return checkContains(claim, ctx);
    case 'http.length_delta@1.0.0':
      return checkLengthDelta(ctx, target);
    default:
      throw new KernelError('INTERNAL', `predicate has no impl: ${spec.id}`);
  }
}

/** All referenced outcomes must share one argvTemplate (payload slots are
 *  already normalized away by signature@1) — a differential claim
 *  over two different commands is fabricated evidence (review R2). */
function requireSameTemplate(ctx: VerifyContext): PredicateResult | null {
  const templates = new Set(ctx.outcomes.map((o) => o.argvTemplate.join(' ')));
  if (templates.size > 1) {
    return {
      verdict: 'rejected',
      reason: `legs must share one argvTemplate; got ${templates.size} distinct templates`,
      value: { templates: [...templates].slice(0, 4) },
    };
  }
  return null;
}

/** observed: every referenced outcome exited 0 with no process failure. */
function checkExitZero(ctx: VerifyContext): PredicateResult {
  const bad = ctx.items.length > 0
    ? ctx.items.filter((i) => (i.exit ?? 0) !== 0 || (i.processFailure ?? null) !== null)
    : ctx.outcomes.filter((o) => o.exit !== 0 || o.processFailure !== null);
  if (bad.length > 0) {
    return {
      verdict: 'rejected',
      reason: `non-clean outcomes: ${bad.map((o) => `${o.id}(exit=${o.exit},failure=${o.processFailure})`).join(', ')}`,
      value: {},
    };
  }
  return { verdict: 'accepted', reason: 'all outcomes exit 0', value: { outcomes: ctx.outcomes.map((o) => o.id) } };
}

/** interpreted: quotes validated at submit; re-check every quote still
 *  matches (defense in depth) and the referenced outcomes are clean. */
function checkContains(claim: Claim, ctx: VerifyContext): PredicateResult {
  const exitBad = ctx.items.length > 0
    ? ctx.items.find((i) => (i.processFailure ?? null) !== null)
    : ctx.outcomes.find((o) => o.processFailure !== null);
  if (exitBad) {
    return { verdict: 'rejected', reason: `outcome ${exitBad.id} processFailure=${exitBad.processFailure}`, value: {} };
  }
  return {
    verdict: 'accepted',
    reason: 'quotes anchored and outcomes clean',
    value: {
      quotes: claim.quotes.length,
      firstQuote: claim.quotes[0]?.text.slice(0, 80) ?? null,
    },
  };
}

/** differential: two http legs of the SAME command template (payload slots
 *  aside) against the same target, ok statuses, and a length delta >=
 *  threshold (review R2 — unrelated commands must not fabricate a Fact). */
function checkLengthDelta(ctx: VerifyContext, target: string | null): PredicateResult {
  const rawTargets = ctx.outcomes.map((o) => o.target ?? '');
  if (rawTargets.some(Boolean)) {
    const wanted = target;
    if (!wanted) {
      return {
        verdict: 'rejected',
        reason: 'differential evidence has a target but the project has no declared target',
        value: { targets: rawTargets.slice(0, 4) },
      };
    }
    if (rawTargets.some((t) => t === '') || new Set(rawTargets).size !== 1 || rawTargets[0] !== wanted) {
      return {
        verdict: 'rejected',
        reason: `differential target must match project target ${wanted}; got ${rawTargets.map((t) => t || '(empty)').join(', ')}`,
        value: { targets: rawTargets.slice(0, 4), expected: wanted },
      };
    }
  }
  if (ctx.items.length > 0) {
    if (ctx.items.length < 2) {
      return { verdict: 'rejected', reason: 'differential needs >=2 item refs (baseline + probe)', value: {} };
    }
    const parents = new Set(ctx.items.map((i) => i.parentOutcomeId));
    const kinds = new Set(ctx.items.map((i) => i.kind));
    if (parents.size !== 1) {
      return { verdict: 'rejected', reason: 'differential item legs must share one parent', value: {} };
    }
    if (kinds.size !== 1) {
      return { verdict: 'rejected', reason: 'differential item legs must share one kernel kind', value: {} };
    }
    const bad = ctx.items.find((i) => i.exit !== 0 || i.processFailure !== null || i.semanticFailure !== null);
    if (bad) {
      return { verdict: 'rejected', reason: `item ${bad.id} is not clean`, value: {} };
    }
    const [baseline, probe] = ctx.items;
    const bl = baseline.stdout.bytes;
    const pl = probe.stdout.bytes;
    const delta = Math.abs(pl - bl);
    const ratio = bl === 0 ? (pl === 0 ? 0 : Infinity) : delta / Math.max(bl, 1);
    const value = { baseline: bl, probe: pl, delta, ratio: Number(ratio.toFixed(4)) };
    if (ratio < LEN_DELTA_THRESHOLD) {
      return { verdict: 'rejected', reason: `length delta ratio ${ratio.toFixed(4)} < threshold ${LEN_DELTA_THRESHOLD}`, value };
    }
    return { verdict: 'accepted', reason: `item length delta ratio ${ratio.toFixed(4)} >= ${LEN_DELTA_THRESHOLD}`, value };
  }
  if (ctx.outcomes.length < 2) {
    return { verdict: 'rejected', reason: 'differential needs >=2 refs (baseline + probe)', value: {} };
  }
  const templateMismatch = requireSameTemplate(ctx);
  if (templateMismatch) return templateMismatch;
  for (const o of ctx.outcomes) {
    const obs = ctx.observations.get(o.id);
    const status = obs?.parsed['http.status']?.value;
    if (typeof status === 'number' && (status >= 400 || status === 0)) {
      return { verdict: 'rejected', reason: `${o.id} http.status=${status}`, value: {} };
    }
    if (obs?.semanticFailure) {
      return { verdict: 'rejected', reason: `${o.id} semanticFailure=${obs.semanticFailure}`, value: {} };
    }
    if (o.processFailure) {
      return { verdict: 'rejected', reason: `${o.id} processFailure=${o.processFailure}`, value: {} };
    }
  }
  const [baseline, probe] = ctx.outcomes;
  const bl = baseline.stdout.bytes;
  const pl = probe.stdout.bytes;
  const delta = Math.abs(pl - bl);
  const ratio = bl === 0 ? (pl === 0 ? 0 : Infinity) : delta / Math.max(bl, 1);
  const value = { baseline: bl, probe: pl, delta, ratio: Number(ratio.toFixed(4)) };
  if (ratio < LEN_DELTA_THRESHOLD) {
    return {
      verdict: 'rejected',
      reason: `length delta ratio ${ratio.toFixed(4)} < threshold ${LEN_DELTA_THRESHOLD}`,
      value,
    };
  }
  return { verdict: 'accepted', reason: `length delta ratio ${ratio.toFixed(4)} >= ${LEN_DELTA_THRESHOLD}`, value };
}
