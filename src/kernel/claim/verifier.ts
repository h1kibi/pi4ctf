/**
 * Claim verifier (docs/design.md §4.4, ADR 0001 §1–2).
 *
 * proposed -> checking -> accepted | rejected   (interpreted = downgrade,
 * produces no Fact). Cheap predicates run synchronously in-kernel; the model
 * cannot invent predicates or pick a weaker verification strength. Accepted
 * claims become Facts; rejected claims produce code-owned NegativeEntries.
 */
import { KernelError } from '../error.js';
import { Ledger } from '../ledger/store.js';
import { Project } from '../project.js';
import { checkQuote } from '../classify/classify.js';
import type { Claim, EvidenceItem, Observation, ProcessOutcome } from '../types.js';

// ---------------------------------------------------------------------------
// Predicate registry (kernel-owned, frozen with fixtures; ADR 0001 §2)
// ---------------------------------------------------------------------------

export interface PredicateSpec {
  id: string; // name@semver
  claimTypes: string[];
  requiredEvidence: ('outcome' | 'quote')[];
  check: 'probe' | 'parse';
  fixtureIds: string[];
}

export const PREDICATES: Record<string, PredicateSpec> = {
  'process.exit-zero@1.0.0': {
    id: 'process.exit-zero@1.0.0',
    claimTypes: ['observed'],
    requiredEvidence: ['outcome'],
    check: 'probe',
    fixtureIds: ['fx-exit-zero', 'fx-exit-nonzero'],
  },
  'output.contains@1.0.0': {
    id: 'output.contains@1.0.0',
    claimTypes: ['interpreted'],
    requiredEvidence: ['outcome', 'quote'],
    check: 'parse',
    fixtureIds: ['fx-contains-hit', 'fx-contains-miss'],
  },
  'http.length_delta@1.0.0': {
    id: 'http.length_delta@1.0.0',
    claimTypes: ['differential'],
    requiredEvidence: ['outcome'],
    check: 'parse',
    fixtureIds: ['fx-len-delta-true', 'fx-len-delta-false'],
  },
  'time.delta@1.0.0': {
    id: 'time.delta@1.0.0',
    claimTypes: ['time-based'],
    requiredEvidence: ['outcome'],
    check: 'probe',
    fixtureIds: ['fx-time-delta-true', 'fx-time-delta-false'],
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

const LEN_DELTA_THRESHOLD = 0.1; // frozen in fixture fx-len-delta-*
const TIME_DELTA_FACTOR = 2.0; // frozen in fixture fx-time-delta-*

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

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

export class ClaimVerifier {
  constructor(
    private readonly project: Project,
    private readonly ledger: Ledger,
  ) {}

  /** Submit a claim: validate quotes against shaped spans, apply the
   *  resubmission gate, persist as proposed. */
  submit(input: {
    claimType: string;
    text: string;
    quotes: { shapedRef: string; span?: { start: number; end: number }; text: string }[];
    refs: string[];
    probe?: { purpose: string; expect: string; falsifier: string };
    predicate?: string;
  }): Claim {
    const predicate = input.predicate
      ? this.lookupPredicate(input.predicate, input.claimType)
      : defaultPredicateFor(input.claimType);

    if (input.text.length > 2048) throw new KernelError('LIMIT', 'claim text exceeds 2KB');
    if (input.refs.length === 0) throw new KernelError('INVALID_REQUEST', 'claim needs >=1 ref');
    if (input.refs.length > 16) throw new KernelError('LIMIT', 'too many refs');
    if (input.quotes.length > 8) throw new KernelError('LIMIT', 'too many quotes');
    if (input.quotes.length === 0 && predicate.requiredEvidence.includes('quote')) {
      throw new KernelError('INVALID_REQUEST', `claimType ${input.claimType} requires quotes`);
    }

    // Resolve refs first; script-declared items may only support interpreted
    // claims, never a code-owned Fact.
    const evidence = input.refs.map((r) => this.ledger.getEvidence(r));
    if (evidence.some((e) => e.kind === 'item' && e.item?.provenance === 'script-declared') && input.claimType !== 'interpreted') {
      throw new KernelError('INVALID_REQUEST', 'script-declared evidence only supports interpreted claims');
    }
    const allowedShaped = this.ledger.allowedShapedRefs(input.refs);

    // Validate every quote: text must equal shaped[start:end] of an artifact
    // belonging to one of the cited refs.
    const shapedCache = new Map<string, string>();
    const quotes = input.quotes.map((q) => {
      if (!allowedShaped.has(q.shapedRef)) {
        const allowed = [...allowedShaped].sort();
        throw new KernelError(
          'INVALID_REQUEST',
          `quote artifact ${q.shapedRef} is not owned by cited refs; allowed: ${allowed.slice(0, 6).join(', ')}${allowed.length > 6 ? ', ...' : ''}`,
        );
      }
      let shaped = shapedCache.get(q.shapedRef);
      if (shaped === undefined) {
        shaped = this.ledger.readArtifact(q.shapedRef);
        shapedCache.set(q.shapedRef, shaped);
      }
      let span = q.span;
      if (span === undefined) {
        const start = shaped.indexOf(q.text);
        if (start < 0) {
          throw new KernelError('INVALID_REQUEST', `quote text is not present in ${q.shapedRef}`);
        }
        span = { start, end: start + q.text.length };
      }
      checkQuote(q.text, shaped, span);
      return { shapedRef: q.shapedRef, text: q.text, span };
    });

    // Refs were resolved above; item refs are valid evidence.

    const signature = `${input.claimType}|${predicate.id}|${input.refs.slice().sort().join(',')}`;

    // Resubmission gate: same signature blocked unless a new artifact/span.
    const prior = this.ledger.findSameSignature(signature);
    if (prior.length > 0) {
      const priorSpans = new Set(
        prior.flatMap((c) => c.quotes.map((q) => `${q.shapedRef}:${q.span.start}-${q.span.end}`)),
      );
      const newSpan = quotes.some(
        (q) => !priorSpans.has(`${q.shapedRef}:${q.span.start}-${q.span.end}`),
      );
      const newArtifact = input.refs.some((r) => !prior.some((c) => c.refs.includes(r)));
      if (!newSpan && !newArtifact) {
        throw new KernelError(
          'CONFLICT',
          `claim signature already submitted (${prior[0]?.id}); resubmission requires a new artifact or span`,
        );
      }
    }

    const synthetic = evidence.some((e) => e.outcome.synthetic === true);
    const targets = new Set(evidence.map((e) => e.outcome.target ?? '').filter(Boolean));
    const target = targets.size === 1 ? [...targets][0] : null;
    const instances = new Set(evidence.map((e) => e.outcome.instanceId ?? '').filter(Boolean));
    const instanceId = instances.size === 1 ? [...instances][0] : null;
    const { id } = this.project.allocId('claim');
    const claim: Claim = {
      id,
      claimType: input.claimType,
      text: input.text,
      quotes,
      refs: input.refs,
      probe: input.probe ?? null,
      state: 'proposed',
      signature,
      predicate: predicate.id,
      rejectedReason: null,
      target,
      instanceId,
      synthetic,
      ts: Date.now(),
    };
    this.ledger.saveClaim(claim);
    this.project.appendEvent('claim.submit', 'model', {
      id,
      claimType: input.claimType,
      predicate: predicate.id,
      refs: input.refs,
    });
    return claim;
  }

  /** Verify a claim with its registered predicate. */
  verify(claimId: string): Claim {
    const claim = this.ledger.getClaim(claimId);
    if (claim.state === 'accepted' || claim.state === 'rejected') {
      throw new KernelError('CONFLICT', `claim ${claimId} is ${claim.state}; terminal`);
    }
    const predicate = this.lookupPredicate(claim.predicate ?? '', claim.claimType);

    claim.state = 'checking';
    this.ledger.saveClaim(claim);

    const ctx = this.loadContext(claim);
    const result = this.runPredicate(predicate, claim, ctx);

    if (result.verdict === 'accepted') {
      const scriptDeclared = claim.refs.some((r) => {
        const e = this.ledger.getEvidence(r);
        return e.kind === 'item' && e.item?.provenance === 'script-declared';
      });
      if (scriptDeclared) {
        claim.state = 'interpreted';
        this.ledger.saveClaim(claim);
        this.project.appendEvent('claim.interpreted', 'kernel', { id: claim.id, predicate: predicate.id, reason: 'script-declared evidence' });
        return claim;
      }
      claim.state = 'accepted';
      this.ledger.saveClaim(claim);
      const artifactHashes: Record<string, string> = {};
      for (const ref of claim.refs) {
        const e = this.ledger.getEvidence(ref);
        const streams = e.item ? [e.item.stdout, e.item.stderr] : [e.outcome.stdout, e.outcome.stderr];
        for (const stream of streams) artifactHashes[stream.shapedRef] = stream.sha256;
      }
      const { id } = this.project.allocId('fact');
      const fact = {
        id,
        claimId: claim.id,
        claimType: claim.claimType,
        predicate: predicate.id,
        classifiedBy: 'classify@1',
        value: result.value,
        observationRefs: claim.refs,
        artifactHashes,
        canonicalKey: ctx.outcomes[0]?.canonicalKey ?? '',
        target: claim.target ?? null,
        instanceId: claim.instanceId ?? null,
        status: 'verified' as const,
        synthetic: claim.synthetic === true,
        ts: Date.now(),
      };
      this.ledger.saveFact(fact);
      this.project.appendEvent('claim.accepted', 'kernel', { id: claim.id, factId: id, predicate: predicate.id });
    } else {
      claim.state = 'rejected';
      claim.rejectedReason = result.reason;
      this.ledger.saveClaim(claim);
      this.project.appendEvent('claim.rejected', 'kernel', { id: claim.id, predicate: predicate.id, reason: result.reason });
      this.ledger.addNegative({
        id: undefined,
        signature: claim.signature,
        failureClass: 'probe-contradicted',
        family: 'approach',
        transient: false,
        condemnedBy: predicate.id,
        unblockOn: 'probe_version',
        expiresAt: null,
        blockScope: 'route',
        artifactRef: ctx.outcomes[0]?.stdout.rawRef ?? null,
        route: claim.id,
      });
    }
    return claim;
  }

  private lookupPredicate(id: string, claimType: string): PredicateSpec {
    const spec = PREDICATES[id];
    if (!spec) throw new KernelError('INVALID_REQUEST', `unregistered predicate: ${id}`);
    if (!spec.claimTypes.includes(claimType)) {
      throw new KernelError(
        'INVALID_REQUEST',
        `predicate ${id} does not accept claimType ${claimType}`,
      );
    }
    return spec;
  }

  private loadContext(claim: Claim): VerifyContext {
    const resolved = claim.refs.map((r) => this.ledger.getEvidence(r));
    const outcomes: ProcessOutcome[] = resolved.map((e) => e.outcome);
    const items: EvidenceItem[] = resolved.map((e) => e.item).filter((i): i is EvidenceItem => i !== null);
    const observations = new Map<string, Observation>();
    const shapedTexts = new Map<string, string>();
    for (const o of outcomes) {
      const obsPath = `observations/${o.id}.json`;
      observations.set(o.id, JSON.parse(this.ledger.readArtifact(obsPath)) as Observation);
      shapedTexts.set(o.id, this.ledger.readArtifact(o.stdout.shapedRef));
    }
    return { outcomes, items, observations, shapedTexts };
  }

  private runPredicate(spec: PredicateSpec, claim: Claim, ctx: VerifyContext): PredicateResult {
    switch (spec.id) {
      case 'process.exit-zero@1.0.0':
        return this.checkExitZero(ctx);
      case 'output.contains@1.0.0':
        return this.checkContains(claim, ctx);
      case 'http.length_delta@1.0.0':
        return this.checkLengthDelta(ctx);
      case 'time.delta@1.0.0':
        return this.checkTimeDelta(ctx);
      default:
        throw new KernelError('INTERNAL', `predicate has no impl: ${spec.id}`);
    }
  }

  /** All referenced outcomes must share one argvTemplate (payload slots are
   *  already normalized away by signature@1) — a differential/time-based
   *  claim over two different commands is fabricated evidence (review R2). */
  private requireSameTemplate(ctx: VerifyContext): PredicateResult | null {
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
  private checkExitZero(ctx: VerifyContext): PredicateResult {
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
  private checkContains(claim: Claim, ctx: VerifyContext): PredicateResult {
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
  private checkLengthDelta(ctx: VerifyContext): PredicateResult {
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
    const templateMismatch = this.requireSameTemplate(ctx);
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

  /** time-based: same template + same target, >=3 runs per side, median
   *  duration ratio >= 2x (review R2). */
  private checkTimeDelta(ctx: VerifyContext): PredicateResult {
    if (ctx.outcomes.length < 6) {
      return {
        verdict: 'rejected',
        reason: `time-based needs >=6 refs (3 baseline + 3 probe); got ${ctx.outcomes.length}`,
        value: {},
      };
    }
    const templateMismatch = this.requireSameTemplate(ctx);
    if (templateMismatch) return templateMismatch;
    const targets = new Set(ctx.outcomes.map((o) => o.target ?? ''));
    if (targets.size > 1) {
      return {
        verdict: 'rejected',
        reason: `time-based legs must share one target; got ${[...targets].join(', ')}`,
        value: {},
      };
    }
    const half = Math.floor(ctx.outcomes.length / 2);
    const baseline = median(ctx.outcomes.slice(0, half).map((o) => o.durationMs));
    const probe = median(ctx.outcomes.slice(half).map((o) => o.durationMs));
    const value = { baselineMs: baseline, probeMs: probe, factor: baseline === 0 ? Infinity : Number((probe / baseline).toFixed(3)) };
    if (baseline === 0 || probe / baseline < TIME_DELTA_FACTOR) {
      return { verdict: 'rejected', reason: `time factor ${value.factor} < ${TIME_DELTA_FACTOR}`, value };
    }
    return { verdict: 'accepted', reason: `time factor ${value.factor} >= ${TIME_DELTA_FACTOR}`, value };
  }
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}
