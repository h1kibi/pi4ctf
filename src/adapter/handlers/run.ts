import { KernelError } from '../../kernel/error.js';
import { Ledger } from '../../kernel/ledger/store.js';
import { commandClassOf, targetOf } from '../../kernel/classify/classify.js';
import { runExec, runProbes, type ProbeSpec } from '../../kernel/run/exec.js';
import { checkRunScope, checkTargetScope, scanInjection } from '../../kernel/security.js';
import { isLoopbackHost, parseTarget, targetFromEnv } from '../../kernel/target.js';
import { signature } from '../../kernel/shape/signature.js';
import { assertCaseBudget, negativeSpecFor, reachabilityWithRecovery, routeSignature } from '../policy.js';
import type { Request, Response } from '../types.js';
import { argvOf, needRoot, ok, readObservation } from '../helpers.js';

export async function handleRun(req: Request, op: string, input: Record<string, unknown>): Promise<Response> {
  switch (op) {
    // -- verb: run ------------------------------------------------------------
    case 'run': {
      const project = needRoot(req);
      const ledger = new Ledger(project);
      assertCaseBudget(project);
      const explicitTarget = input.target === undefined ? undefined : parseTarget(input.target);
      const envTarget = input.env && typeof input.env === 'object' && !Array.isArray(input.env)
        ? targetFromEnv(input.env as Record<string, unknown>)
        : null;
      const inlineTarget = !Array.isArray(input.probes)
        ? parseTarget(targetOf(argvOf(input)))
        : null;
      const effectiveTarget = explicitTarget === undefined
        ? (project.file().target ?? envTarget ?? inlineTarget ?? null)
        : explicitTarget;
      const warnings: string[] = [];
      let targetReachable: boolean | null = null;
      let targetCheckMs: number | null = null;
      const targetTimeoutMs = (() => {
        const n = Number(input.targetTimeoutMs);
        return Number.isFinite(n) ? Math.min(30_000, Math.max(100, n)) : 2000;
      })();
      if (effectiveTarget) {
        checkTargetScope(project, effectiveTarget);
        if (!Array.isArray(input.probes) && input.skipTargetCheck !== true && !isLoopbackHost(effectiveTarget.host)) {
          const checked = await reachabilityWithRecovery(project, effectiveTarget, targetTimeoutMs, project.file().backend);
          warnings.push(...checked.warnings);
          const reach = checked.reach;
          targetReachable = reach.checked ? reach.ok : null;
          targetCheckMs = reach.checked ? reach.ms : null;
          if (reach.checked && !reach.ok) {
            const message = `target ${effectiveTarget.host}${effectiveTarget.port ? `:${effectiveTarget.port}` : ''} is unreachable from the host (${reach.error ?? 'unknown'})`;
            if (project.file().backend === 'docker') {
              warnings.push(`${message}; backend=docker may still reach it, continuing without host-side proof`);
            } else {
              throw new KernelError(
                'TARGET_UNREACHABLE',
                `${message}; use skipTargetCheck=true for a target you start inside the run`,
              );
            }
          }
        }
      }
      if (Array.isArray(input.probes)) {
        const result = await runProbes(project, input.probes as ProbeSpec[], {
          concurrency: typeof input.concurrency === 'number' ? input.concurrency : undefined,
          timeoutMs: typeof input.timeoutMs === 'number' ? input.timeoutMs : undefined,
        });
        for (const failure of result.itemFailures ?? []) {
          if (failure.semanticFailure === 'target-unreachable') continue;
          const spec = negativeSpecFor(failure.processFailure, failure.semanticFailure);
          ledger.addNegative({
            signature: failure.signature,
            failureClass: spec.failureClass,
            family: spec.family,
            transient: spec.transient,
            condemnedBy: null,
            unblockOn: spec.unblockOn,
            expiresAt: spec.ttlMs === null ? null : Date.now() + spec.ttlMs,
            blockScope: 'route',
            artifactRef: failure.artifactRef,
            route: null,
          });
        }
        return ok(op, {
          id: result.outcome.id,
          exit: result.outcome.exit,
          durationMs: result.outcome.durationMs,
          processFailure: result.outcome.processFailure,
          semanticFailure: null,
          intentClass: result.outcome.intentClass,
          canonicalKey: result.outcome.canonicalKey,
          target: null,
          stdout: result.outcome.stdout.excerpt,
          stderr: result.outcome.stderr.excerpt,
          artifact: result.outcome.stdout.shapedRef,
          rawArtifact: result.outcome.stdout.rawRef,
          items: result.items ?? [],
          itemCount: result.items?.length ?? 0,
          itemIndex: result.outcome.items ?? null,
          itemFailures: result.itemFailures?.length ?? 0,
          incomplete: result.incomplete ?? [],
          errors: result.errors ?? [],
          completed: (result.items ?? []).map((item) => item.id),
          timedOut: (result.itemFailures ?? []).filter((f) => f.processFailure === 'timeout').map((f) => f.index),
          notRun: (result.incomplete ?? []).filter((i) => i.status === 'notRun').map((i) => i.index),
          warnings,
          injectionMarkers: [],
        });
      }

      const argv = argvOf(input);
      // Goal contract: scope-out run is blocked and audited (ADR 0003 §3).
      checkRunScope(project, argv);
      // Signature gate: hard-block deterministic dead ends; TTL for transient.
      const sig = signature(argv);
      const intentClass = commandClassOf(argv);
      const key = routeSignature(intentClass, sig.signature);
      const blocked = ledger.blockedSignature(key);
      if (blocked && !blocked.transient) {
        throw new KernelError(
          'CONFLICT',
          `route hard-blocked: ${blocked.failureClass} (condemned by ${blocked.condemnedBy ?? 'ledger'}); unblockOn=${blocked.unblockOn}`,
        );
      }
      const { outcome, shapedStdout, items } = await runExec(project, {
        argv: input.argv ? argv : undefined,
        command: input.command ? String(input.command) : undefined,
        cwd: input.cwd ? String(input.cwd) : undefined,
        timeoutMs: typeof input.timeoutMs === 'number' ? input.timeoutMs : undefined,
        stdin: typeof input.stdin === 'string' ? input.stdin : undefined,
        target: effectiveTarget,
        targetReachable,
        targetCheckMs,
        env: input.env && typeof input.env === 'object' && !Array.isArray(input.env)
          ? input.env as Record<string, unknown>
          : undefined,
        synthetic: input.synthetic === true,
      });
      // Stage C on the run path: failed outcomes enter the negative ledger
      // with code-owned classes (docs/design.md §4.2, ADR 0002 §4).
      const obs = readObservation(project, outcome.id);
      // exec-local is an opaque script (`python -c`, `node -e`, ...). Its
      // normalized signature collapses different programs to one route, so a
      // timeout/nonzero from one script must not condemn the shape. The model
      // still sees the ProcessOutcome; it just does not enter the ledger.
      if (outcome.intentClass !== 'exec-local' && obs?.semanticFailure !== 'target-unreachable' && (outcome.processFailure || obs?.semanticFailure)) {
        const spec = negativeSpecFor(outcome.processFailure, obs?.semanticFailure ?? null);
        ledger.addNegative({
          signature: key,
          failureClass: spec.failureClass,
          family: spec.family,
          transient: spec.transient,
          condemnedBy: null,
          unblockOn: spec.unblockOn,
          expiresAt: spec.ttlMs === null ? null : Date.now() + spec.ttlMs,
          blockScope: 'route',
          artifactRef: outcome.stdout.rawRef,
          route: null,
        });
      }
      const duplicateOf = ledger.listOutcomes().find((prior) => prior.id !== outcome.id && prior.canonicalKey === outcome.canonicalKey)?.id ?? null;
      return ok(op, {
        id: outcome.id,
        duplicateOf,
        exit: outcome.exit,
        durationMs: outcome.durationMs,
        processFailure: outcome.processFailure,
        semanticFailure: obs?.semanticFailure ?? null,
        intentClass: outcome.intentClass,
        canonicalKey: outcome.canonicalKey,
        target: outcome.target,
        instanceId: outcome.instanceId ?? null,
        targetReachable: outcome.targetReachable ?? null,
        targetCheckMs: outcome.targetCheckMs ?? null,
        synthetic: outcome.synthetic === true,
        stdout: outcome.stdout.excerpt,
        stderr: outcome.stderr.excerpt,
        artifact: outcome.stdout.shapedRef,
        rawArtifact: outcome.stdout.rawRef,
        stderrArtifact: outcome.stderr.shapedRef,
        items: (items ?? []).slice(0, 3),
        itemCount: items?.length ?? 0,
        itemIndex: outcome.items ?? null,
        injectionMarkers: scanInjection(shapedStdout),
        warnings,
      });
    }

    default:
      throw new KernelError('INVALID_REQUEST', `unexpected run op: ${op}`);
  }
}
