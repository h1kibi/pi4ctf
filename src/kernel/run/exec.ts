/**
 * Stage A execution engine (docs/design.md §4.1, ADR 0002 §1).
 * exec produces ProcessOutcome only — no semantics. Runs bounded:
 * process group / tree kill, 120s default / 600s max timeout, 64 MiB
 * artifact cap (recorded, never silent — review R4), concurrent capture
 * with chunk arrays (no O(n^2) concat — review R10), stdin validated
 * before spawn.
 */
import { Buffer } from 'node:buffer';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { KernelError } from '../error.js';
import { atomicWriteFile, resolveInside, sha256 } from '../fsutil.js';
import { Project } from '../project.js';
import { classify, commandClassOf, contractFor, statusFailureClass, targetOf } from '../classify/classify.js';
import { canonicalKey, routeSignature, signature } from '../shape/signature.js';
import { shape } from '../shape/shape.js';
import { baseEnv, commandExists, resolveBash } from '../sysutil.js';
import { checkRunScope } from '../security.js';
import { mergeEnv, targetFromEnv, targetRef } from '../target.js';
import { Ledger } from '../ledger/store.js';
import { parseEvidenceItems, type ItemSummary } from '../evidence/items.js';
import { CookieJar, performHttp, type HttpProbeSpec } from '../http/client.js';
import type { EvidenceItem, ItemIndex, ProcessOutcome, SemanticFailure, StreamInfo, TargetSpec } from '../types.js';

export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_TIMEOUT_MS = 600_000;
export const ARTIFACT_CAP = 64 * 1024 * 1024;
const STDIN_CAP = 1024 * 1024;
const GRACE_MS = 2_000;
const EXCERPT_CHARS = 1536;

export interface RunRequest {
  argv?: string[];
  command?: string;
  shell?: 'bash' | 'powershell';
  cwd?: string; // relative to project root
  timeoutMs?: number;
  stdin?: string;
  /** Explicit target for attribution/scope; defaults to project.target. */
  target?: TargetSpec | null;
  /** Extra environment; merged after target-derived HOST/PORT/TARGET. */
  env?: Record<string, unknown>;
  /** Adapter TCP precheck when a target was declared; null = not checked. */
  targetReachable?: boolean | null;
  targetCheckMs?: number | null;
  /** Dry-run/experiment marker; propagated to claims/facts where possible. */
  synthetic?: boolean;
  /** Internal kernel probes may carry expectOutput from the contract. */
  actor?: string;
}

export interface ProbeSpec {
  label?: string;
  http?: HttpProbeSpec;
  argv?: string[];
  command?: string;
  cwd?: string;
  timeoutMs?: number;
  stdin?: string;
  target?: TargetSpec | null;
  env?: Record<string, unknown>;
}

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

interface Prepared {
  /** Actual argv to spawn (may include docker/shell wrapper). */
  argv: string[];
  /** The logical user command; signature@1, target and scope derive from
   *  this — never from the wrapper (review R1). */
  userArgv: string[];
  cwd: string;
  shell: string | null;
  /** Target derived from the unstripped command (inline HOST/PORT). */
  targetHint?: string | null;
  /** Extra environment for host launches. Docker uses -e flags instead. */
  env: Record<string, string>;
  /** Temporary command script; removed after the run. */
  tempFile?: string;
}

/** Minimal launch context: where to run and on which backend. Internal
 *  (non-evidence) probes need only this, not a full challenge Project. */
export interface ExecHost {
  root: string;
  ctfDir: string;
  backend: 'host' | 'docker';
  dockerImage?: string;
  target: TargetSpec | null;
}

export function execHostOf(project: Project): ExecHost {
  const file = project.file();
  return {
    root: project.root,
    ctfDir: project.ctfDir,
    backend: file.backend,
    ...(file.dockerImage ? { dockerImage: file.dockerImage } : {}),
    target: file.target ?? null,
  };
}


/** Shell command mode often carries target/config as leading assignments:
 *  `HOST=... PORT=... python exp.py`. Those values belong in env/target
 *  metadata, not the route signature, otherwise the same exploit in argv mode
 *  gets a different canonicalKey. */
function stripLeadingEnvAssignments(argv: string[]): string[] {
  let i = 0;
  while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i] ?? '')) i++;
  return i === 0 ? argv : argv.slice(i);
}

function prepareHost(host: ExecHost, req: RunRequest): Prepared {
  const root = host.root;
  let argv: string[];
  let userArgv: string[];
  let shell: string | null = null;
  let tempFile: string | undefined;
  let targetHint: string | null = null;
  if (req.argv) {
    argv = req.argv.map(String);
    userArgv = argv;
  } else if (req.command) {
    // POSIX command semantics: bash is required. PowerShell corrupts curl
    // flags (Invoke-WebRequest alias) and mis-signs the run (review R1);
    // it stays available only when explicitly requested.
    if (req.shell === 'powershell') {
      argv = ['powershell', '-NoProfile', '-NonInteractive', '-Command', req.command];
      shell = 'powershell';
    } else {
      const bash = resolveBash();
      if (!commandExists(bash)) {
        throw new KernelError(
          'UNSUPPORTED',
          'command mode requires bash on PATH (Git Bash/WSL); use argv mode or install bash',
        );
      }
      // Never put the command text on bash's argv. WSL's bash.exe expands
      // `$var` in argv before Linux sees it, so loops/heredocs silently lose
      // their variables. A temp script keeps the command byte-for-byte.
      const cwd = req.cwd ? resolveInside(root, req.cwd) : root;
      if (!fs.existsSync(cwd)) fs.mkdirSync(cwd, { recursive: true });
      const scriptPath = path.join(host.ctfDir, `.run-${randomUUID()}.sh`);
      fs.writeFileSync(scriptPath, req.command, 'utf8');
      const scriptRel = path.relative(cwd, scriptPath).split(path.sep).join('/');
      argv = [bash, '-l', scriptRel];
      tempFile = scriptPath;
      shell = 'bash';
    }
    userArgv = stripLeadingEnvAssignments(req.command.trim().split(/\s+/).filter(Boolean));
  } else {
    throw new KernelError('INVALID_REQUEST', 'one of argv | command is required');
  }
  const cwd = req.cwd ? resolveInside(root, req.cwd) : root;
  if (!fs.existsSync(cwd)) fs.mkdirSync(cwd, { recursive: true });
  return { argv, userArgv, cwd, shell, tempFile, targetHint: targetHint ?? targetOf(userArgv), env: mergeEnv(req.target ?? host.target, req.env) };
}

function prepareDocker(host: ExecHost, req: RunRequest): Prepared {
  const image = host.dockerImage;
  if (!image) {
    throw new KernelError('UNSUPPORTED', 'docker backend requires dockerImage in project.json');
  }
  const root = host.root;
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace, { recursive: true });
  let userArgv: string[];
  let targetHint: string | null = null;
  if (req.argv) {
    userArgv = req.argv.map(String);
  } else if (req.command) {
    const rawArgv = req.command.trim().split(/\s+/).filter(Boolean);
    targetHint = targetOf(rawArgv);
    userArgv = stripLeadingEnvAssignments(rawArgv);
  } else {
    throw new KernelError('INVALID_REQUEST', 'one of argv | command is required');
  }
  // The image entrypoint is empty (sandbox/Dockerfile.kali), so argv runs
  // directly; shell commands wrap in bash inside the container.
  const inner = req.command ? ['bash', '-lc', req.command] : userArgv;
  const envFlags: string[] = [];
  for (const [key, value] of Object.entries(mergeEnv(req.target ?? host.target, req.env))) {
    envFlags.push('-e', `${key}=${value}`);
  }
  const argv = [
    'docker',
    'run',
    '--rm',
    '--network',
    'bridge',
    '--cap-add',
    'SYS_PTRACE',
    '-e',
    'TERM=xterm',
    '-e',
    'PYTHONUNBUFFERED=1',
    ...envFlags,
    '-v',
    `${root}:/challenge:ro`,
    '-v',
    `${workspace}:/challenge/workspace:rw`,
    '-w',
    '/challenge/workspace',
    image,
    ...inner,
  ];
  return { argv, userArgv, cwd: root, shell: req.command ? 'bash' : null, targetHint: targetHint ?? targetOf(userArgv), env: {} };
}

// ---------------------------------------------------------------------------
// Tree kill: process group on POSIX, taskkill /T on Windows.
// ---------------------------------------------------------------------------

function killTree(pid: number, signal: 'SIGTERM' | 'SIGKILL'): void {
  if (process.platform === 'win32') {
    spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-pid, signal);
    } catch {
      try {
        process.kill(pid, signal);
      } catch {
        /* already gone */
      }
    }
  }
}

interface RawRun {
  exit: number | null;
  signal: string | null;
  timedOut: boolean;
  durationMs: number;
  stdout: Buffer;
  stderr: Buffer;
  outputTruncated: boolean;
}

function runRaw(prep: Prepared, timeoutMs: number, stdin: string | undefined): Promise<RawRun> {
  // Validate stdin BEFORE spawning so an oversized input never leaves an
  // orphan child (review R10).
  if (stdin !== undefined && Buffer.byteLength(stdin) > STDIN_CAP) {
    return Promise.reject(new KernelError('LIMIT', `stdin exceeds ${STDIN_CAP} bytes`));
  }
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn(prep.argv[0], prep.argv.slice(1), {
      cwd: prep.cwd,
      env: { ...baseEnv(), ...prep.env },
      detached: process.platform !== 'win32',
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let timedOut = false;
    let settled = false;
    // Chunk arrays: concat once at the end (review R10).
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let total = 0;
    let outputTruncated = false;

    const capture = (buf: Buffer, which: 'out' | 'err') => {
      if (total >= ARTIFACT_CAP) {
        outputTruncated = true;
        return;
      }
      const room = ARTIFACT_CAP - total;
      const slice = buf.subarray(0, room);
      total += slice.length;
      if (which === 'out') outChunks.push(slice);
      else errChunks.push(slice);
    };

    child.stdout?.on('data', (d: Buffer) => capture(d, 'out'));
    child.stderr?.on('data', (d: Buffer) => capture(d, 'err'));
    // Pipe errors (EPIPE when the child exits early) must not crash the kernel.
    child.stdout?.on('error', () => {});
    child.stderr?.on('error', () => {});
    child.stdin?.on('error', () => {});

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      killTree(child.pid ?? 0, 'SIGTERM');
      setTimeout(() => {
        if (!settled && child.exitCode === null) killTree(child.pid ?? 0, 'SIGKILL');
      }, GRACE_MS).unref();
    }, timeoutMs);

    if (stdin !== undefined) {
      child.stdin?.write(stdin);
    }
    child.stdin?.end();

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new KernelError('NOT_FOUND', `spawn failed: ${err.message}`));
    });

    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exit: code,
        signal: signal ?? null,
        timedOut,
        durationMs: Date.now() - started,
        stdout: Buffer.concat(outChunks),
        stderr: Buffer.concat(errChunks),
        outputTruncated,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// exec: run + shape + atomic artifacts + ProcessOutcome + Stage B observation.
// ---------------------------------------------------------------------------

function streamInfo(
  id: string,
  which: 'stdout' | 'stderr',
  raw: Buffer,
  rawTruncated: boolean,
  project: Project,
): { info: StreamInfo; shaped: string } {
  const shapedResult = shape(raw);
  const base = `artifacts/${id}.${which}`;
  const rawRef = `${base}.raw.log`;
  const shapedRef = `${base}.shaped.log`;
  atomicWriteFile(path.join(project.ctfDir, rawRef), raw);
  atomicWriteFile(path.join(project.ctfDir, shapedRef), shapedResult.shaped);
  atomicWriteFile(path.join(project.ctfDir, `${base}.meta.json`), JSON.stringify({
    bytes: raw.length,
    shapedBytes: Buffer.byteLength(shapedResult.shaped),
    lines: shapedResult.shaped.split('\n').length - 1,
    sha256: sha256(raw),
    encoding: shapedResult.encoding,
    truncated: shapedResult.truncated,
    omittedChars: shapedResult.omittedChars,
    // capture-level cap hit (distinct from shape windowing) — review R4
    outputTruncated: rawTruncated,
  }, null, 2));
  return {
    info: {
      sha256: sha256(raw),
      bytes: raw.length,
      rawRef,
      shapedRef,
      excerpt: shapedResult.shaped.slice(0, EXCERPT_CHARS),
      encoding: shapedResult.encoding,
      truncated: shapedResult.truncated,
      outputTruncated: rawTruncated,
    },
    shaped: shapedResult.shaped,
  };
}

/** A filter stage makes empty stdout a legitimate result (`grep` no match),
 *  not a broken probe. Only command-mode shell pipelines need this. */
function hasFilterStage(command: string | undefined): boolean {
  return !!command && /\|\s*(?:grep|egrep|fgrep|rg|sed|awk|head|tail|jq|cut|sort|uniq|wc|tr)\b/.test(command);
}

/** WSL's bash.exe prints a UTF-16 localhost-proxy warning to stderr before the
 *  command runs. It is host noise, not challenge evidence. */
function stripHostNoise(buf: Buffer): Buffer {
  if (buf.length === 0) return buf;
  const text = buf.toString('utf16le');
  if (!/^wsl:/im.test(text)) return buf;
  return Buffer.from(
    text
      .split(/\r?\n/)
      .filter((line) => !/^wsl:/i.test(line))
      .join('\n'),
    'utf16le',
  );
}

function safeProbeLabel(value: string | undefined): string {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '?').slice(0, 64);
}

function emptyStream(id: string, which: 'stdout' | 'stderr', project: Project): StreamInfo {
  const base = `artifacts/${id}.${which}`;
  const rawRef = `${base}.raw.log`;
  const shapedRef = `${base}.shaped.log`;
  atomicWriteFile(path.join(project.ctfDir, rawRef), Buffer.alloc(0));
  atomicWriteFile(path.join(project.ctfDir, shapedRef), '');
  return {
    sha256: sha256(Buffer.alloc(0)),
    bytes: 0,
    rawRef,
    shapedRef,
    excerpt: '',
    encoding: 'utf8',
    truncated: false,
    outputTruncated: false,
  };
}

/** Kernel-executed probe batch: one budget slot, up to 16 independently
 *  classified child items. Unlike evidence/1 script items, these items are
 *  observations: the kernel owns exit/stdout/status/classification. */
export interface ProbeBatchOptions {
  /** 1..4; default 1 (sequential). */
  concurrency?: number;
  /** Whole-batch wall-clock deadline; default 600000 ms. */
  timeoutMs?: number;
}

export async function runProbes(
  project: Project,
  probes: ProbeSpec[],
  options: ProbeBatchOptions = {},
): Promise<RunResult> {
  if (probes.length < 1 || probes.length > 16) throw new KernelError('LIMIT', 'probes must contain 1..16 items');
  const file = project.file();
  const { id: parentId } = project.reserveCommand();
  const parentStdout = emptyStream(parentId, 'stdout', project);
  const parentStderr = emptyStream(parentId, 'stderr', project);
  const items: EvidenceItem[] = [];
  const summaries: ItemSummary[] = [];
  const failures: ItemFailure[] = [];
  const cookieJar = new CookieJar();
  const concurrency = Math.min(4, Math.max(1, Math.floor(options.concurrency ?? 1)));
  const batchDeadline = Date.now() + Math.min(MAX_TIMEOUT_MS, Math.max(1, options.timeoutMs ?? MAX_TIMEOUT_MS));
  fs.mkdirSync(path.join(project.ctfDir, 'items'), { recursive: true });

  const executeProbe = async (spec: ProbeSpec, i: number): Promise<{
    item: EvidenceItem;
    summary: ItemSummary;
    failure: ItemFailure | null;
  }> => {
    let prep: Prepared | null = null;
    let raw: RawRun;
    let intentClass: string;
    let sig: ReturnType<typeof signature>;
    let target: string | null;
    let shell: string | null = null;
    let statusOverride: number | null = null;
    let httpMeta: Record<string, string | number | boolean | null> = {};
    try {
      const remaining = Math.max(1, batchDeadline - Date.now());
      if (spec.http) {
        checkRunScope(project, [spec.http.url]);
        intentClass = 'http-probe';
        let httpSpec = spec.http;
        let bodyDigest: string | null = null;
        if (httpSpec.bodyFile) {
          const bodyPath = path.resolve(project.root, httpSpec.bodyFile);
          const bodyRel = path.relative(project.root, bodyPath);
          if (bodyRel.startsWith('..') || path.isAbsolute(bodyRel)) {
            throw new KernelError('SECURITY', `bodyFile must stay inside the project root: ${httpSpec.bodyFile}`);
          }
          let body: Buffer;
          try {
            body = fs.readFileSync(bodyPath);
          } catch {
            throw new KernelError('NOT_FOUND', `bodyFile not found: ${httpSpec.bodyFile}`);
          }
          if (body.length > 64 * 1024 * 1024) throw new KernelError('LIMIT', 'bodyFile exceeds 64 MiB');
          bodyDigest = sha256(body);
          httpSpec = { ...httpSpec, bodyB64: body.toString('base64') };
        } else if (httpSpec.bodyB64) {
          bodyDigest = sha256(Buffer.from(httpSpec.bodyB64, 'base64'));
        } else if (httpSpec.body !== undefined) {
          bodyDigest = sha256(Buffer.from(httpSpec.body, 'utf8'));
        }
        sig = signature(['http', (httpSpec.method ?? 'GET').toUpperCase(), httpSpec.url, ...(bodyDigest ? [bodyDigest] : [])]);
        const httpBlocked = new Ledger(project).blockedSignature(routeSignature(intentClass, sig.signature));
        if (httpBlocked && !httpBlocked.transient) {
          throw new KernelError('CONFLICT', `probe hard-blocked: ${httpBlocked.failureClass}; unblockOn=${httpBlocked.unblockOn}`);
        }
        const httpResult = await performHttp({
          ...httpSpec,
          timeoutMs: Math.min(httpSpec.timeoutMs ?? 30_000, remaining),
        }, cookieJar);
        target = httpResult.target;
        shell = null;
        statusOverride = httpResult.status;
        raw = {
          exit: httpResult.error ? 1 : 0,
          signal: null,
          timedOut: httpResult.timedOut,
          durationMs: httpResult.durationMs,
          stdout: httpResult.body,
          stderr: httpResult.error ? Buffer.from(httpResult.error) : Buffer.alloc(0),
          outputTruncated: httpResult.truncated,
        };
        httpMeta = {
          'http.status': httpResult.status,
          'http.url': httpResult.url,
          'http.headers': JSON.stringify(httpResult.headers).slice(0, 2048),
        };
      } else {
        const req: RunRequest = {
          argv: spec.argv,
          command: spec.command,
          cwd: spec.cwd,
          timeoutMs: spec.timeoutMs,
          stdin: spec.stdin,
          target: spec.target,
          env: spec.env,
        };
        const execHost = execHostOf(project);
        prep = file.backend === 'docker' ? prepareDocker(execHost, req) : prepareHost(execHost, req);
        checkRunScope(project, prep.userArgv);
        intentClass = commandClassOf(prep.userArgv);
        sig = signature(prep.userArgv);
        const commandBlocked = new Ledger(project).blockedSignature(routeSignature(intentClass, sig.signature));
        if (commandBlocked && !commandBlocked.transient) {
          throw new KernelError('CONFLICT', `probe hard-blocked: ${commandBlocked.failureClass}; unblockOn=${commandBlocked.unblockOn}`);
        }
        const declared = spec.target === undefined
          ? (file.target ?? targetFromEnv(spec.env) ?? null)
          : spec.target;
        target = declared ? targetRef(declared) : (prep.targetHint ?? targetOf(prep.userArgv));
        shell = prep.shell;
        const requestedTimeout = Math.min(req.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
        const timeoutMs = Math.min(requestedTimeout, remaining);
        if (timeoutMs <= 0) throw new KernelError('INVALID_REQUEST', 'timeoutMs must be positive');
        raw = await runRaw(prep, timeoutMs, req.stdin);
      }
      const itemId = `${parentId}.${String(i + 1).padStart(4, '0')}`;
      const artifactId = `${parentId}.item-${String(i + 1).padStart(4, '0')}`;
      const stdoutS = streamInfo(artifactId, 'stdout', raw.stdout, raw.outputTruncated, project);
      const stderrS = streamInfo(artifactId, 'stderr', stripHostNoise(raw.stderr), raw.outputTruncated, project);
      const contract = contractFor(intentClass);
      const shapedHash = sha256(stdoutS.shaped);
      const filterCommand = spec.http ? undefined : spec.command;
      let processFailure: ProcessOutcome['processFailure'] = null;
      if (raw.timedOut) processFailure = 'timeout';
      else if (raw.exit !== 0 && !hasFilterStage(filterCommand)) processFailure = 'nonzero-exit';
      else if (statusOverride === null && contract?.expectOutput && raw.stdout.length === 0 && !hasFilterStage(filterCommand)) {
        processFailure = 'no-output-when-expected';
      }
      const probeOutcome: ProcessOutcome = {
        id: itemId,
        argvTemplate: sig.argvTemplate,
        argvRaw: prep?.argv ?? ['http', target ?? '?'],
        target,
        intentClass,
        canonicalKey: canonicalKey(intentClass, sig.signature, shapedHash),
        exit: raw.exit,
        signal: raw.signal,
        durationMs: raw.durationMs,
        shell,
        stdout: stdoutS.info,
        stderr: stderrS.info,
        processFailure,
        instanceId: (spec.target === undefined ? file.target : spec.target)?.instanceId ?? null,
        synthetic: false,
        ts: Date.now(),
      };
      const observation = statusOverride !== null
        ? {
            outcomeId: itemId,
            commandClass: 'http-probe',
            contractId: 'contract.http-probe@1.0.0',
            parsed: {
              'http.status': {
                value: statusOverride,
                shapedRef: stdoutS.info.shapedRef,
                span: { start: 0, end: 0 },
              },
            },
            semanticFailure: statusFailureClass(statusOverride),
            semanticDetail: `http.status=${statusOverride}`,
          }
        : classify(probeOutcome, stdoutS.shaped, stderrS.shaped);
      const observationRef = `observations/${itemId}.json`;
      atomicWriteFile(path.join(project.ctfDir, observationRef), JSON.stringify(observation, null, 2));
      const statusValue = observation.parsed['http.status']?.value;
      const status = typeof statusValue === 'string' || typeof statusValue === 'number' || typeof statusValue === 'boolean'
        ? statusValue
        : null;
      const kind: EvidenceItem['kind'] = intentClass === 'http-probe' || intentClass === 'http-fuzz' || intentClass === 'sqli-probe'
        ? 'http'
        : stdoutS.info.encoding === 'hex'
          ? 'binary'
          : 'text';
      const item: EvidenceItem = {
        id: itemId,
        parentOutcomeId: parentId,
        index: i + 1,
        label: safeProbeLabel(spec.label),
        provenance: 'kernel',
        declaredKind: '',
        kind,
        status,
        encoding: stdoutS.info.encoding === 'hex' ? 'base64' : 'utf8',
        stdout: stdoutS.info,
        stderr: stderrS.info,
        meta: { ...httpMeta },
        semanticFailure: observation.semanticFailure,
        observationRef,
        truncated: stdoutS.info.truncated || stderrS.info.truncated,
        exit: raw.exit,
        processFailure,
        target,
        intentClass,
        canonicalKey: probeOutcome.canonicalKey,
        routeSignature: routeSignature(intentClass, sig.signature),
        durationMs: raw.durationMs,
      };
      atomicWriteFile(path.join(project.ctfDir, `items/${itemId}.json`), JSON.stringify(item, null, 2));
      const summary: ItemSummary = {
        id: item.id,
        label: item.label,
        kind: item.kind,
        bytes: item.stdout.bytes,
        excerpt: item.stdout.excerpt.slice(0, 256),
      };
      const failure = (processFailure || observation.semanticFailure)
        ? {
            index: item.index,
            signature: item.routeSignature!,
            processFailure,
            semanticFailure: observation.semanticFailure,
            artifactRef: item.stdout.rawRef,
          }
        : null;
      return { item, summary, failure };
    } finally {
      if (prep?.tempFile) {
        try {
          fs.rmSync(prep.tempFile, { force: true });
        } catch {
          /* best effort */
        }
      }
    }
  };

  const results: Array<Awaited<ReturnType<typeof executeProbe>>> = [];
  const errors: Array<{ index: number; label: string; message: string }> = [];
  for (let start = 0; start < probes.length; start += concurrency) {
    if (Date.now() >= batchDeadline) break;
    const chunk = probes.slice(start, start + concurrency);
    const chunkResults = await Promise.all(chunk.map(async (spec, j) => {
      try {
        return { ok: true as const, value: await executeProbe(spec, start + j) };
      } catch (err) {
        return {
          ok: false as const,
          index: start + j + 1,
          label: safeProbeLabel(spec.label),
          message: err instanceof Error ? err.message : String(err),
        };
      }
    }));
    for (const res of chunkResults) {
      if (res.ok) results.push(res.value);
      else errors.push({ index: res.index, label: res.label, message: res.message });
    }
  }
  results.sort((a, b) => a.item.index - b.item.index);
  for (const result of results) {
    items.push(result.item);
    summaries.push(result.summary);
    if (result.failure) failures.push(result.failure);
  }

  const completedIndexes = new Set(items.map((item) => item.index));
  const errorByIndex = new Map(errors.map((e) => [e.index, e]));
  const incomplete: IncompleteProbe[] = probes
    .map((spec, i) => ({ spec, i }))
    .filter(({ i }) => !completedIndexes.has(i + 1))
    .map(({ spec, i }) => ({
      index: i + 1,
      label: safeProbeLabel(spec.label),
      status: errorByIndex.has(i + 1) ? 'error' as const : 'notRun' as const,
    }));
  const index: ItemIndex = {
    protocol: 'evidence/1',
    provenance: 'kernel',
    planned: probes.length,
    parsed: items.length,
    emitted: items.length,
    truncated: incomplete.length > 0,
    protocolError: errors.length > 0
      ? 'probe errors; see errors/incomplete'
      : incomplete.length > 0
        ? 'batch deadline exceeded; notRun items listed in incomplete'
        : null,
    ids: items.map((item) => item.id),
  };
  const parent: ProcessOutcome = {
    id: parentId,
    argvTemplate: ['run.probes'],
    argvRaw: ['run.probes'],
    target: null,
    intentClass: 'probe-batch',
    canonicalKey: `probe-batch|${sha256(Buffer.from(JSON.stringify(probes)))}`,
    exit: 0,
    signal: null,
    durationMs: items.reduce((sum, item) => sum + (item.durationMs ?? 0), 0),
    shell: null,
    stdout: parentStdout,
    stderr: parentStderr,
    processFailure: null,
    items: index,
    ts: Date.now(),
  };
  atomicWriteFile(path.join(project.ctfDir, `outcomes/${parentId}.json`), JSON.stringify(parent, null, 2));
  atomicWriteFile(path.join(project.ctfDir, `observations/${parentId}.json`), JSON.stringify({
    outcomeId: parentId,
    commandClass: 'probe-batch',
    contractId: null,
    parsed: {},
    semanticFailure: null,
    semanticDetail: 'kernel probe batch container',
  }, null, 2));
  project.appendEvent('run.probes', 'model', {
    id: parentId,
    count: items.length,
    failures: failures.length,
  });
  return { outcome: parent, shapedStdout: '', shapedStderr: '', items: summaries, itemFailures: failures, incomplete, errors };
}

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
