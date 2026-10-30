/**
 * Core record types — mirrors docs/design.md §4.2 (4 records) and ADR 0002
 * (three-stage classification: ProcessOutcome -> Observation -> Fact/Negative).
 */

// ---------------------------------------------------------------------------
// Stage A: ProcessOutcome (process facts, code-owned)
// ---------------------------------------------------------------------------

export type ProcessFailure =
  | 'timeout'
  | 'nonzero-exit'
  | 'no-output-when-expected'
  | null;

export interface StreamInfo {
  /** sha256 of raw bytes. */
  sha256: string;
  bytes: number;
  /** Path relative to .ctf/ holding the raw output, e.g. artifacts/cmd-0001.stdout.log */
  rawRef: string;
  /** Path relative to .ctf/ holding the shaped text. */
  shapedRef: string;
  /** First bytes of shaped text, for quick packet use; full text lives in shapedRef. */
  excerpt: string;
  /** Whether shaped output was hex-encoded (binary detection). */
  encoding: 'utf8' | 'hex';
  truncated: boolean;
  /** Capture-level artifact cap was hit (64 MiB) — data was dropped and the
   *  evidence is incomplete (review R4). Distinct from shape windowing. */
  outputTruncated: boolean;
}

export interface ItemIndex {
  protocol: 'evidence/1';
  provenance: 'script-declared' | 'kernel';
  planned: number | null;
  parsed: number;
  emitted: number;
  truncated: boolean;
  protocolError: string | null;
  ids: string[];
}

export interface EvidenceItem {
  /** Canonical id, e.g. cmd-0001.0003. */
  id: string;
  parentOutcomeId: string;
  index: number;
  label: string;
  provenance: 'script-declared' | 'kernel';
  declaredKind: string;
  kind: 'http' | 'binary' | 'text' | 'unknown';
  status: string | number | boolean | null;
  encoding: 'utf8' | 'base64';
  stdout: StreamInfo;
  stderr: StreamInfo;
  meta: Record<string, string | number | boolean | null>;
  semanticFailure: SemanticFailure;
  observationRef?: string;
  truncated: boolean;
  // Kernel-probe fields; absent for script-declared items.
  exit?: number | null;
  processFailure?: ProcessFailure;
  target?: string | null;
  intentClass?: string;
  canonicalKey?: string;
  routeSignature?: string;
  durationMs?: number;
}

export interface ProcessOutcome {
  id: string; // cmd-0001
  argvTemplate: string[]; // signature@1 slots applied
  argvRaw: string[];
  target: string | null; // host:port when derivable
  intentClass: string; // commandClass
  canonicalKey: string; // intentClass|signature@1:...|shaped:sha256:...
  exit: number | null;
  signal: string | null;
  durationMs: number;
  shell: string | null;
  stdout: StreamInfo;
  stderr: StreamInfo;
  processFailure: ProcessFailure;
  /** Declared project/run target; also populated for exec-local when the
   *  project has a target, so script-internal networking is attributable. */
  instanceId?: string | null;
  /** Adapter TCP precheck when a target was declared; null = not checked. */
  targetReachable?: boolean | null;
  targetCheckMs?: number | null;
  synthetic?: boolean;
  items?: ItemIndex;
  ts: number; // epoch ms
}

// ---------------------------------------------------------------------------
// Stage B: Observation (capability contract + parsed fields + semanticFailure)
// ---------------------------------------------------------------------------

export type SemanticFailure =
  | 'schema-mismatch'
  | 'probe-contradicted'
  | 'server-error'
  | 'client-blocked'
  | 'target-unreachable'
  | 'tty-required'
  | 'command-not-found'
  | null;

export interface ParsedField {
  value: string | number | boolean | null;
  shapedRef: string; // e.g. artifacts/cmd-0021.stdout.shaped.log
  span: { start: number; end: number };
}

export interface Observation {
  outcomeId: string;
  commandClass: string;
  targetReachable?: boolean | null;
  /** Contract applied (from the kernel-owned registry); null for generic run. */
  contractId: string | null;
  parsed: Record<string, ParsedField>;
  semanticFailure: SemanticFailure;
  semanticDetail: string | null;
}

// ---------------------------------------------------------------------------
// claim (model proposal; kernel owns belief)
// ---------------------------------------------------------------------------

export type ClaimState = 'proposed' | 'checking' | 'accepted' | 'rejected' | 'interpreted';

export interface Quote {
  shapedRef: string; // artifacts/cmd-0021.stdout.shaped.log
  span: { start: number; end: number };
  /** Must equal shaped[start:end]; kernel checks. */
  text: string;
}

export interface ProbeSpec {
  purpose: string;
  expect: string;
  falsifier: string;
}

export interface Claim {
  id: string; // c0001
  claimType: string; // observed | interpreted | differential | exploit | cred | flag
  text: string;
  quotes: Quote[];
  refs: string[]; // cmd-0001 or cmd-0001.0003
  probe: ProbeSpec | null;
  state: ClaimState;
  /** claimType|predicateHint|refs joined; resubmission gate key. */
  signature: string;
  predicate: string | null;
  rejectedReason: string | null;
  target?: string | null;
  instanceId?: string | null;
  synthetic?: boolean;
  ts: number;
}

// ---------------------------------------------------------------------------
// Fact (predicate-verified conclusion)
// ---------------------------------------------------------------------------

export interface Fact {
  id: string; // f0001
  claimId: string;
  claimType: string;
  predicate: string; // e.g. http.length_delta@1.0.0
  classifiedBy: string; // classify@1
  value: Record<string, unknown>;
  observationRefs: string[];
  /** shapedRef -> raw sha256, for byte-level revalidation. */
  artifactHashes: Record<string, string>;
  canonicalKey: string;
  target?: string | null;
  instanceId?: string | null;
  status: 'verified';
  synthetic?: boolean;
  ts: number;
}

// ---------------------------------------------------------------------------
// NegativeEntry (dead ends; ADR 0002 §4)
// ---------------------------------------------------------------------------

export type FailureClass =
  | 'timeout'
  | 'nonzero-exit'
  | 'no-output'
  | 'schema-mismatch'
  | 'probe-contradicted'
  | 'client-blocked'
  | 'server-error'
  | 'tty-required'
  | 'command-not-found';

export interface NegativeEntry {
  /** File id n0001; assigned by the ledger on first insert. */
  id?: string;
  signature: string;
  attempts: number;
  lastAttemptAt: number;
  failureClass: FailureClass;
  /** environment failures are not evidence that the approach is wrong. */
  family?: 'environment' | 'approach';
  transient: boolean;
  condemnedBy: string | null; // predicate id that condemned it
  unblockOn: 'ttl' | 'env_change' | 'probe' | 'probe_version';
  expiresAt: number | null; // epoch ms; null = permanent
  blockScope: 'route' | 'case';
  artifactRef: string | null;
  route: string | null; // claim id
  /** Set once when a TTL entry expires; prevents repeat unblock events. */
  unblockedAt?: number | null;
  unblockReason?: 'ttl' | 'env_change' | 'probe' | 'probe_version' | null;
}

// ---------------------------------------------------------------------------
// Flag ledger
// ---------------------------------------------------------------------------

export interface FlagLayers {
  format: boolean;
  provenance: boolean;
  evidence: boolean;
  oracle: boolean;
  dedupe: boolean;
}

export interface FlagRecord {
  flag: string;
  flagSha256: string;
  source: { kind: string; ref: string | null };
  status: 'candidate' | 'accepted' | 'unverified' | 'rejected';
  layers: FlagLayers;
  detail: Record<string, string | null>;
  oracle: string;
  /** Context at submission; a later reconfigure/target switch may retry. */
  flagFormat?: string;
  oracleHash?: string | null;
  target?: TargetSpec | null;
  instanceId?: string | null;
  synthetic?: boolean;
  ts: number;
}

// ---------------------------------------------------------------------------
// Project / goal contract
// ---------------------------------------------------------------------------

export interface TargetSpec {
  host: string;
  port?: number;
  protocol?: 'tcp' | 'http' | 'https' | 'udp' | 'other';
  instanceId?: string;
  url?: string;
}

/** Optional user-owned reset endpoint for a remote target. This is read from
 *  the oracle (outside the workspace), never from model-written case state. */
export interface TargetResetSpec {
  url: string;
  method?: 'GET' | 'POST' | 'PUT';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface OracleFile {
  flag?: string;
  flagSha256?: string;
  target?: unknown;
  host?: string;
  port?: number;
  instanceId?: string;
  expiresAt?: string | number;
  reset?: TargetResetSpec;
}

export interface GoalContract {
  flagFormat: string;
  allowedHosts: string[];
  allowedPathPrefixes: string[];
  backend: 'host' | 'docker';
  dockerImage?: string;
  target: TargetSpec | null;
  deadlineMs: number | null;
  noAutoSubmit: true;
}

export interface ProjectFile {
  version: 1;
  id: string;
  title: string;
  goal: string;
  origin: string;
  status: 'active' | 'completed' | 'failed' | 'stopped';
  category: string;
  backend: 'host' | 'docker';
  dockerImage?: string;
  target?: TargetSpec;
  /** Challenge files root for this case. */
  root: string;
  /** Container root that owns .ctf/ and workspace/; absent for legacy flat projects. */
  containerRoot?: string;
  /** Timestamp case id; absent for legacy flat projects. */
  caseId?: string;
  rootIdentity: string;
  envHash: string;
  flagFormat: string;
  oracle: { type: 'local'; ref: string };
  /** SHA-256 of the oracle file at project.init; null = oracle absent then. */
  oracleHash: string | null;
  deadlineMs: number | null;
  /** Human-set reporting checkpoint; blocks new executions after this time. */
  timeLimitAtMs?: number | null;
  allowedHosts: string[];
  counters: Record<string, number>;
  revisions: Record<string, number>;
}

export interface PlanBlock {
  chain: string[];
  next: string;
  preconditions: string[];
  /** Target snapshot when this plan was written; stale after target switch. */
  target?: string | null;
}

export interface EventRecord {
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: Record<string, unknown>;
}

/** External turn budget (docs/design.md §6): enforced by code at the run
 *  verb, shared by the adapter gate and the packet budget line. */
export const TURN_BUDGET = 30;

/** Target reset attempts are audited and capped independently of the budget. */
export const MAX_TARGET_RESETS = 3;
