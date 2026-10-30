/**
 * Stage A execution engine (docs/design.md §4.1, ADR 0002 §1).
 * exec produces ProcessOutcome only — no semantics. Runs bounded:
 * process group / tree kill, 120s default / 600s max timeout, 64 MiB
 * artifact cap (recorded, never silent — review R4), concurrent capture
 * with chunk arrays (no O(n^2) concat — review R10), stdin validated
 * before spawn.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import { atomicWriteFile, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import { classify, commandClassOf, contractFor, targetOf } from '../classify/classify.js';
import { canonicalKey, signature } from '../shape/signature.js';
import { targetFromEnv, targetRef } from '../target.js';
import { parseEvidenceItems, type ItemSummary } from '../evidence/items.js';
import type { ProcessOutcome, SemanticFailure } from '../types.js';
import { execHostOf, prepareDocker, prepareHost, type ExecHost, type RunRequest } from './prepare.js';
import { runRaw, type RawRun } from './process.js';
import { hasFilterStage, streamInfo, stripHostNoise } from './stream.js';
import { DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS } from './limits.js';



export interface ItemFailure {
  index: number;
  signature: string;
  processFailure: ProcessOutcome['processFailure'];
  semanticFailure: SemanticFailure;
  artifactRef: string;
}

export interface IncompleteProbe {
  index: number;
  label: string;
  status: 'notRun' | 'error';
}

export interface RunResult {
  outcome: ProcessOutcome;
  shapedStdout: string;
  shapedStderr: string;
  items?: ItemSummary[];
  itemFailures?: ItemFailure[];
  incomplete?: IncompleteProbe[];
  errors?: Array<{ index: number; label: string; message: string }>;
}

// ---------------------------------------------------------------------------
// Backends: how to launch and how to map paths (kernel-design §9.1).
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Tree kill: process group on POSIX, taskkill /T on Windows.
// ---------------------------------------------------------------------------







// ---------------------------------------------------------------------------
// exec: run + shape + atomic artifacts + ProcessOutcome + Stage B observation.
// ---------------------------------------------------------------------------



/** A filter stage makes empty stdout a legitimate result (`grep` no match),
 *  not a broken probe. Only command-mode shell pipelines need this. */


/** WSL's bash.exe prints a UTF-16 localhost-proxy warning to stderr before the
 *  command runs. It is host noise, not challenge evidence. */






/** Kernel-executed probe batch: one budget slot, up to 16 independently
 *  classified child items. Unlike evidence/1 script items, these items are
 *  observations: the kernel owns exit/stdout/status/classification. */




export interface InternalRunResult {
  stdout: string;
  stderr: string;
  exit: number;
  timedOut: boolean;
  durationMs: number;
}

/** Internal, non-evidence probe: same host/docker execution path as runExec,
 *  but no budget slot, outcome, observation, or ledger entry. */
export async function runInternal(
  host: ExecHost,
  req: Pick<RunRequest, 'argv' | 'command' | 'cwd' | 'timeoutMs' | 'stdin'>,
): Promise<InternalRunResult> {
  const prep = host.backend === 'docker' ? prepareDocker(host, req) : prepareHost(host, req);
  try {
    const raw = await runRaw(prep, Math.min(req.timeoutMs ?? 5_000, 30_000), req.stdin);
    return {
      stdout: raw.stdout.toString('utf8'),
      stderr: raw.stderr.toString('utf8'),
      exit: raw.exit ?? -1,
      timedOut: raw.timedOut,
      durationMs: raw.durationMs,
    };
  } finally {
    if (prep.tempFile) {
      try {
        fs.rmSync(prep.tempFile, { force: true });
      } catch {
        /* best effort */
      }
    }
  }
}

export async function runExec(project: Project, req: RunRequest): Promise<RunResult> {
  const file = project.file();
  const timeoutMs = Math.min(req.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  if (timeoutMs <= 0) throw new KernelError('INVALID_REQUEST', 'timeoutMs must be positive');

  const execHost = execHostOf(project);
  const prep =
    file.backend === 'docker' ? prepareDocker(execHost, req) : prepareHost(execHost, req);
  try {

  // commandClass is derived from the LOGICAL user command (review R1) so the
  // contract can inform expectOutput and canonicalKey matches what the
  // adapter's signature gate computed.
  const intentClass = commandClassOf(prep.userArgv);
  const contract = contractFor(intentClass);
  const { id } = project.reserveCommand();

  let raw: RawRun;
  try {
    raw = await runRaw(prep, timeoutMs, req.stdin);
  } catch (err) {
    if (err instanceof KernelError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    throw new KernelError('INTERNAL', `exec failed: ${message}`);
  }

  const stdoutS = streamInfo(id, 'stdout', raw.stdout, raw.outputTruncated, project);
  const stderrS = streamInfo(id, 'stderr', stripHostNoise(raw.stderr), raw.outputTruncated, project);
  const parsedItems = parseEvidenceItems(project, id, raw.stdout, {
    timedOut: raw.timedOut,
    outputTruncated: raw.outputTruncated,
  });

  const sig = signature(prep.userArgv);
  const declared = req.target === undefined
    ? (file.target ?? targetFromEnv(req.env) ?? null)
    : req.target;
  const target = declared ? targetRef(declared) : (prep.targetHint ?? targetOf(prep.userArgv));
  const shapedHash = sha256(stdoutS.shaped);

  let processFailure: ProcessOutcome['processFailure'] = null;
  if (raw.timedOut) processFailure = 'timeout';
  else if (raw.exit !== 0 && !hasFilterStage(req.command)) processFailure = 'nonzero-exit';
  else if (contract?.expectOutput && raw.stdout.length === 0 && !hasFilterStage(req.command)) {
    processFailure = 'no-output-when-expected';
  }

  const outcome: ProcessOutcome = {
    id,
    argvTemplate: sig.argvTemplate,
    argvRaw: prep.argv,
    target,
    intentClass,
    canonicalKey: canonicalKey(intentClass, sig.signature, shapedHash),
    exit: raw.exit,
    signal: raw.signal,
    durationMs: raw.durationMs,
    shell: prep.shell,
    stdout: stdoutS.info,
    stderr: stderrS.info,
    processFailure,
    instanceId: declared?.instanceId ?? null,
    targetReachable: req.targetReachable ?? null,
    targetCheckMs: req.targetCheckMs ?? null,
    synthetic: req.synthetic === true,
    items: parsedItems?.index,
    ts: Date.now(),
  };
  atomicWriteFile(
    path.join(project.ctfDir, `outcomes/${id}.json`),
    JSON.stringify(outcome, null, 2),
  );

  const observation = parsedItems
    ? {
        outcomeId: id,
        commandClass: intentClass,
        contractId: null,
        parsed: {},
        semanticFailure: null,
        semanticDetail: 'items container (script-declared)',
      }
    : classify(outcome, stdoutS.shaped, stderrS.shaped);
  atomicWriteFile(
    path.join(project.ctfDir, `observations/${id}.json`),
    JSON.stringify(observation, null, 2),
  );

  project.appendEvent('run.exec', req.actor ?? 'model', {
    id,
    intentClass,
    canonicalKey: outcome.canonicalKey,
    exit: outcome.exit,
    durationMs: outcome.durationMs,
    processFailure,
    outputTruncated: raw.outputTruncated,
    backend: file.backend,
    target,
    instanceId: declared?.instanceId ?? null,
    targetReachable: req.targetReachable ?? null,
    targetCheckMs: req.targetCheckMs ?? null,
    synthetic: req.synthetic === true,
  });
  project.appendEvent('observation.classified', 'kernel', {
    id,
    contractId: observation.contractId,
    semanticFailure: observation.semanticFailure,
    parsedKeys: Object.keys(observation.parsed),
  });

  return {
    outcome,
    shapedStdout: stdoutS.shaped,
    shapedStderr: stderrS.shaped,
    items: parsedItems?.summaries,
  };

  } finally {
    if (prep.tempFile) {
      try {
        fs.rmSync(prep.tempFile, { force: true });
      } catch {
        /* best effort; .ctf/.run-* is harmless if cleanup fails */
      }
    }
  }
}
