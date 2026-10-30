import * as fs from 'node:fs';
import * as path from 'node:path';
import { Project, type ProjectInitSpec } from '../../kernel/project.js';
import { KernelError } from '../../kernel/error.js';
import { Ledger } from '../../kernel/ledger/store.js';
import { compilePacket, writeHandoff } from '../../kernel/context/packet.js';
import { ingestArtifact } from '../../kernel/artifact/ingest.js';
import { readAcceptedFlag } from '../../kernel/flag/flag.js';
import { recordPreflight } from '../../kernel/preflight/preflight.js';
import { scanChallenge } from '../../providers/preflight/scan.js';
import { readProcess, type ProcAction } from '../../kernel/proc/proc.js';
import { parseTarget, targetRef } from '../../kernel/target.js';
import { recordSolve } from '../../kernel/stats.js';
import { DEFAULT_FLAG_FORMAT } from '../../kernel/flag/format.js';
import { assertCaseBudget } from '../../kernel/budget.js';
import { checkTargetScope, scanInjection, wrapUntrusted } from '../../kernel/security.js';
import { envSummary } from '../../providers/env/summary.js';
import { envContextOf } from '../../providers/env/context.js';
import { reachabilityWithRecovery } from '../policy.js';
import type { Request, Response } from '../types.js';
import { EVIDENCE_TEXT_CAP, evidenceHeadTail, evidenceLineMatches, doctor, needRoot, ok, str, imageMime } from '../helpers.js';

function initSpec(input: Record<string, unknown>): ProjectInitSpec {
  return {
    id: str(input, 'id', 'untitled'),
    title: str(input, 'title', 'untitled'),
    goal: str(input, 'goal', '拿到 flag 并验证'),
    origin: str(input, 'origin', ''),
    category: str(input, 'category', 'misc'),
    flagFormat: str(input, 'flagFormat', DEFAULT_FLAG_FORMAT),
    backend: input.backend === 'host' || input.backend === 'docker' ? input.backend : 'docker',
    dockerImage: input.dockerImage ? String(input.dockerImage) : undefined,
    target: parseTarget(input.target) ?? undefined,
    oracle: { type: 'local', ref: str(input, 'oracleRef', '../oracle.json') },
    deadlineMs: typeof input.deadlineMs === 'number' ? input.deadlineMs : null,
    allowedHosts: Array.isArray(input.allowedHosts) ? (input.allowedHosts as string[]).map(String) : ['*'],
  };
}

function casePlacement(project: Project): Record<string, unknown> {
  return {
    id: project.file().id,
    caseId: project.caseId || null,
    root: project.root,
    containerRoot: project.containerRoot,
    workspace: project.workspace,
  };
}

export async function handleCase(req: Request, op: string, input: Record<string, unknown>): Promise<Response> {
  switch (op) {
    case 'project.init': {
      // Legacy flat init, kept for direct kernel clients and existing projects.
      if (!req.root) throw new KernelError('INVALID_REQUEST', 'root is required');
      const project = Project.init(req.root, initSpec(input));
      return ok(op, casePlacement(project));
    }
    case 'case.init': {
      if (!req.root) throw new KernelError('INVALID_REQUEST', 'container root is required');
      if (typeof input.challengeRoot !== 'string' || input.challengeRoot.length === 0) {
        throw new KernelError('INVALID_REQUEST', 'challengeRoot is required');
      }
      const project = Project.initCase(
        req.root,
        input.challengeRoot,
        initSpec(input),
        typeof input.caseId === 'string' ? input.caseId : undefined,
      );
      return ok(op, casePlacement(project));
    }
    case 'case.activate': {
      if (!req.root) throw new KernelError('INVALID_REQUEST', 'container root is required');
      let project: Project;
      if (typeof input.caseId === 'string' && input.caseId.length > 0) {
        project = Project.activateCase(req.root, input.caseId);
      } else {
        if (typeof input.challengeRoot !== 'string' || input.challengeRoot.length === 0) {
          throw new KernelError('INVALID_REQUEST', 'caseId or challengeRoot is required');
        }
        const found = Project.findCaseByChallengeRoot(req.root, input.challengeRoot);
        if (!found) {
          throw new KernelError('NOT_FOUND', `no case for challenge root ${input.challengeRoot}`);
        }
        project = Project.activateCase(req.root, found);
      }
      return ok(op, casePlacement(project));
    }
    case 'project.status': {
      const project = needRoot(req);
      return ok(op, project.status());
    }
    case 'project.close':
    case 'case.close': {
      const project = needRoot(req);
      if (input.status === 'completed') {
        throw new KernelError('CONFLICT', 'case.close cannot mark a case completed; use case.complete (verified Fact gate)');
      }
      const status = input.status === 'stopped' ? 'stopped' : 'failed';
      project.close(status);
      return ok(op, { status });
    }
    case 'case.restart': {
      if (!req.root) throw new KernelError('INVALID_REQUEST', 'root is required');
      const project = typeof input.caseId === 'string' && input.caseId.length > 0
        ? Project.activateCase(req.root, input.caseId)
        : needRoot(req);
      const restarted = project.restart();
      const clearedNegatives = new Ledger(project).clearTransientNegatives();
      const progress = path.join(project.ctfDir, 'progress.md');
      const handoff = fs.existsSync(progress) ? fs.readFileSync(progress, 'utf8').slice(0, 4096) : '';
      return ok(op, {
        ...casePlacement(project),
        ...restarted,
        clearedNegatives,
        ...(handoff ? { handoff } : {}),
      });
    }
    case 'case.continue': {
      const project = needRoot(req);
      return ok(op, project.continueBudget());
    }
    case 'case.time': {
      const project = needRoot(req);
      const raw = input.minutes;
      const minutes = raw === null || raw === 0 ? null : Number(raw);
      return ok(op, project.setTimeLimit(minutes));
    }
    case 'case.configure': {
      const project = needRoot(req);
      const target = input.target === undefined ? undefined : parseTarget(input.target);
      const current = project.file();
      const backend = input.backend === 'host' || input.backend === 'docker' ? input.backend : current.backend;
      const warnings: string[] = [];
      // A re-pin must validate the target it will use: a new target, or the
      // current target when only the oracle reference changes.
      const targetToCheck = target !== undefined ? target : (input.oracleRef !== undefined ? current.target : undefined);
      if (target) checkTargetScope(project, target);
      if (targetToCheck) {
        const n = Number(input.targetTimeoutMs);
        const targetTimeoutMs = Number.isFinite(n) ? Math.min(30_000, Math.max(100, n)) : 2000;
        const checked = await reachabilityWithRecovery(project, targetToCheck, targetTimeoutMs, backend);
        warnings.push(...checked.warnings);
        const reach = checked.reach;
        if (reach.checked && !reach.ok) {
          const message = `target ${targetToCheck.host}${targetToCheck.port ? `:${targetToCheck.port}` : ''} is unreachable from the host (${reach.error ?? 'unknown'})`;
          if (backend === 'docker') warnings.push(`${message}; backend=docker may still reach it, continuing without host-side proof`);
          else throw new KernelError('TARGET_UNREACHABLE', `${message}; refusing to pin an oracle for it`);
        }
      }
      return ok(op, {
        ...project.reconfigure({
          flagFormat: input.flagFormat === undefined ? undefined : String(input.flagFormat),
          oracleRef: input.oracleRef === undefined ? undefined : String(input.oracleRef),
          backend: input.backend === 'host' || input.backend === 'docker' ? input.backend : undefined,
          dockerImage: input.dockerImage === undefined ? undefined : String(input.dockerImage),
          target,
          allowedHosts: Array.isArray(input.allowedHosts) ? (input.allowedHosts as unknown[]).map(String) : undefined,
        }),
        warnings,
      });
    }
    case 'case.clearNegatives': {
      const project = needRoot(req);
      const id = typeof input.id === 'string' ? input.id : undefined;
      return ok(op, { cleared: new Ledger(project).clearTransientNegatives(id) });
    }
    case 'case.map': {
      const project = needRoot(req);
      const ledger = new Ledger(project);
      const file = project.file();
      const target = targetRef(file.target ?? null);
      const recent = ledger.recentOutcomes(8).filter((outcome) =>
        target === null || outcome.target === null ||
        (outcome.target === target && (outcome.instanceId ?? '') === (file.target?.instanceId ?? '')),
      );
      return ok(op, {
        status: project.status(),
        plan: project.readPlan(),
        claims: ledger.openClaims(),
        negatives: ledger.listNegatives(),
        recent,
      });
    }
    case 'case.plan': {
      const project = needRoot(req);
      project.writePlan({
        chain: Array.isArray(input.chain) ? (input.chain as unknown[]).map(String) : [],
        next: str(input, 'next', ''),
        preconditions: Array.isArray(input.preconditions) ? (input.preconditions as unknown[]).map(String) : [],
      });
      return ok(op, { plan: project.readPlan() });
    }
    case 'case.evidence': {
      const project = needRoot(req);
      const ledger = new Ledger(project);
      const ref = str(input, 'ref');
      const resolved = ledger.getEvidence(ref);
      const stream = input.stream === 'stderr' ? 'stderr' : 'stdout';
      if (!resolved.item && resolved.outcome.items) {
        const childIds = resolved.outcome.items.ids;
        const children = childIds.map((id) => {
          const child = ledger.getEvidence(id);
          return {
            id,
            label: child.item?.label ?? null,
            kind: child.item?.kind ?? null,
            bytes: child.item?.stdout.bytes ?? 0,
            excerpt: child.item?.stdout.excerpt.slice(0, 256) ?? '',
          };
        });
        if (input.grep !== undefined) {
          const pattern = String(input.grep);
          if (pattern.length === 0) throw new KernelError('INVALID_REQUEST', 'grep must not be empty');
          const context = Math.min(5, Math.max(0, Number.isFinite(Number(input.context)) ? Number(input.context) : 0));
          const maxMatches = Math.min(100, Math.max(1, Number.isFinite(Number(input.maxMatches)) ? Number(input.maxMatches) : 20));
          const matches: Array<Record<string, unknown>> = [];
          for (const childId of childIds) {
            if (matches.length >= maxMatches) break;
            const child = ledger.getEvidence(childId);
            if (!child.item) continue;
            const text = ledger.readArtifact(child.item[stream].shapedRef);
            const found = evidenceLineMatches(text, pattern, context, maxMatches - matches.length);
            for (const m of found.matches) matches.push({ ...m, ref: childId });
          }
          const wrapped = wrapUntrusted(matches.map((m) => String(m.text ?? '')).join('\n'));
          return ok(op, {
            ref,
            batch: true,
            children: childIds,
            searched: childIds,
            matches,
            matchCount: matches.length,
            wrapped,
            hint: 'batch grep searched child items; use ref+line/start/end for exact evidence',
          });
        }
        return ok(op, {
          ref,
          batch: true,
          children: childIds,
          items: children,
          count: children.length,
          hint: 'probe-batch parent has no stdout; call case_evidence with a child id (cmd-0001.NNNN) or pass grep to search all children',
        });
      }
      if (input.raw === true) {
        const rawRef = resolved.item ? resolved.item[stream].rawRef : resolved.outcome[stream].rawRef;
        const data = ledger.readArtifactBuffer(rawRef);
        if (data.length > 32 * 1024 * 1024) throw new KernelError('LIMIT', 'raw evidence exceeds 32 MiB');
        return ok(op, {
          ref,
          kind: resolved.kind,
          provenance: resolved.item?.provenance ?? 'kernel',
          label: resolved.item?.label ?? null,
          encoding: 'base64',
          mime: imageMime(data),
          bytes: data.length,
          base64: data.toString('base64'),
          truncated: false,
        });
      }
      const refPath = resolved.item ? resolved.item[stream].shapedRef : resolved.outcome[stream].shapedRef;
      const full = ledger.readArtifact(refPath);
      const fullBytes = Buffer.byteLength(full);
      const source = fullBytes > EVIDENCE_TEXT_CAP ? full.slice(0, EVIDENCE_TEXT_CAP) : full;
      const grep = input.grep === undefined ? null : String(input.grep);
      const context = Math.min(5, Math.max(0, Number.isFinite(Number(input.context)) ? Number(input.context) : 0));
      const maxMatches = Math.min(100, Math.max(1, Number.isFinite(Number(input.maxMatches)) ? Number(input.maxMatches) : 20));
      if (grep !== null) {
        if (grep.length === 0) throw new KernelError('INVALID_REQUEST', 'grep must not be empty');
        const result = evidenceLineMatches(source, grep, context, maxMatches);
        return ok(op, {
          ref,
          kind: resolved.kind,
          provenance: resolved.item?.provenance ?? 'kernel',
          label: resolved.item?.label ?? null,
          encoding: resolved.item?.encoding ?? null,
          bytes: fullBytes,
          truncated: fullBytes > EVIDENCE_TEXT_CAP,
          totalLines: result.totalLines,
          matchCount: result.matches.length,
          matches: result.matches,
          wrapped: wrapUntrusted(result.matches.map((m) => m.text).join('\n')),
          injectionMarkers: result.matches.flatMap((m) => scanInjection(m.text)),
        });
      }
      const headRaw = Number(input.head);
      const tailRaw = Number(input.tail);
      const head = input.head !== undefined && Number.isFinite(headRaw)
        ? Math.min(1000, Math.max(1, Math.floor(headRaw)))
        : null;
      const tail = input.tail !== undefined && Number.isFinite(tailRaw)
        ? Math.min(1000, Math.max(1, Math.floor(tailRaw)))
        : null;
      if (head !== null || tail !== null) {
        const result = evidenceHeadTail(source, head, tail);
        return ok(op, {
          ref,
          kind: resolved.kind,
          provenance: resolved.item?.provenance ?? 'kernel',
          label: resolved.item?.label ?? null,
          encoding: resolved.item?.encoding ?? null,
          bytes: fullBytes,
          truncated: result.truncated || fullBytes > EVIDENCE_TEXT_CAP,
          totalLines: result.totalLines,
          text: result.text,
          wrapped: wrapUntrusted(result.text),
          injectionMarkers: scanInjection(result.text),
        });
      }
      const offset = Math.max(0, Number.isFinite(Number(input.offset)) ? Number(input.offset) : 0);
      const limit = Math.min(16384, Math.max(1, Number.isFinite(Number(input.limit)) ? Number(input.limit) : 2048));
      const text = source.slice(offset, offset + limit);
      return ok(op, {
        ref,
        kind: resolved.kind,
        provenance: resolved.item?.provenance ?? 'kernel',
        label: resolved.item?.label ?? null,
        encoding: resolved.item?.encoding ?? null,
        bytes: fullBytes,
        offset,
        limit,
        truncated: fullBytes > EVIDENCE_TEXT_CAP || offset + text.length < source.length,
        text,
        wrapped: wrapUntrusted(text),
        injectionMarkers: scanInjection(text),
      });
    }
    case 'proc': {
      const project = needRoot(req);
      const action = str(input, 'action');
      if (action !== 'maps' && action !== 'mem' && action !== 'libs') {
        throw new KernelError('INVALID_REQUEST', 'action must be maps | mem | libs');
      }
      const result = readProcess(project, {
        session: str(input, 'session'),
        action: action as ProcAction,
        address: typeof input.address === 'string' || typeof input.address === 'number' ? input.address : undefined,
        length: typeof input.length === 'number' ? input.length : undefined,
      });
      return ok(op, { ...result });
    }
    case 'case.preflight': {
      const project = needRoot(req);
      const scan = scanChallenge(project.root, {
        includeWorkspace: input.includeWorkspace === true,
        includeBuild: input.includeBuild === true,
      });
      const result = recordPreflight(project, scan);
      return ok(op, {
        path: path.relative(project.root, result.path).split(path.sep).join('/'),
        endpoint: result.endpoint,
        files: result.files,
        libc: result.libc,
        otherFiles: result.otherFiles,
        otherFilesTotal: result.otherFilesTotal,
        otherFilesTruncated: result.otherFilesTruncated,
        rootFiles: result.rootFiles,
        generated: result.generated,
        notes: result.notes,
      });
    }
    case 'case.context': {
      const project = needRoot(req);
      const seen = Array.isArray(input.seenOutcomes) ? (input.seenOutcomes as unknown[]).map(String) : [];
      const packet = compilePacket(project, new Ledger(project), { excludeOutcomeIds: seen, envSummary: envSummary(envContextOf(project)) });
      return ok(op, {
        packet: packet.text,
        stats: packet.stats,
        outcomeIds: packet.outcomeIds,
        integrity: packet.integrity,
        issues: packet.issues,
      });
    }
    case 'artifact.ingest': {
      const project = needRoot(req);
      assertCaseBudget(project);
      const ingested = ingestArtifact(project, {
        path: str(input, 'path'),
        name: input.name ? String(input.name) : undefined,
        target: input.target === undefined ? undefined : parseTarget(input.target),
        synthetic: input.synthetic === true,
        transform: input.transform === 'hex' || input.transform === 'base64' ? input.transform : undefined,
      });
      return ok(op, { ...ingested });
    }
    case 'case.handoff': {
      const project = needRoot(req);
      const { progressPath, packet } = writeHandoff(project, new Ledger(project), { envSummary: envSummary(envContextOf(project)) });
      return ok(op, {
        progressPath,
        packetBytes: packet.stats.totalBytes,
        integrity: packet.integrity,
        issues: packet.issues,
      });
    }
    case 'case.complete': {
      const project = needRoot(req);
      const ledger = new Ledger(project);
      const file = project.file();
      const currentTarget = file.target ? `${file.target.host}${file.target.port ? `:${file.target.port}` : ''}` : null;
      const facts = ledger.listFacts().filter((f) =>
        f.synthetic !== true &&
        (!currentTarget || (f.target === currentTarget && (f.instanceId ?? '') === (file.target?.instanceId ?? ''))),
      );
      if (facts.length === 0) {
        throw new KernelError('CONFLICT', 'complete requires at least one non-synthetic verified Fact from the current target');
      }
      const flag = readAcceptedFlag(project);
      project.close('completed');
      project.appendEvent('case.complete', 'kernel', { facts: facts.length, flagAccepted: flag !== null });
      recordSolve(project, flag !== null);
      return ok(op, { facts: facts.length, flagAccepted: flag !== null, flag });
    }
    case 'case.doctor': {
      const project = needRoot(req);
      return ok(op, doctor(project));
    }
    default:
      throw new KernelError('INVALID_REQUEST', `unknown case op: ${op}`);
  }
}
