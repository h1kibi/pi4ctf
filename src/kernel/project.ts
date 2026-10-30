/**
 * Project state on disk: <challenge>/.ctf/ layout per docs/design.md §2 and
 * docs/kernel-design.md §2. One file per node, atomic replace, append-only
 * events, rebuildable projections.
 *
 * .ctf/
 *   project.json          counters, goal contract, root identity
 *   events.jsonl          append-only event log
 *   flags.jsonl           flag ledger
 *   artifacts/            raw + shaped + meta per outcome / session
 *   outcomes/cmd-0001.json
 *   observations/cmd-0001.json
 *   claims/c0001.json
 *   facts/f0001.json
 *   negatives/n0001.json
 *   sessions/
 *   plan.json             current plan block (packet source)
 *   chal.json             static ELF/libc metadata from case.preflight
 *   state.json            projection (rebuildable)
 *   progress.md           handoff artifact
 *   .lock
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { atomicWriteFile, FileLock, readJson, readJsonIfExists, rootIdentity, sha256 } from './fsutil.js';
import { KernelError } from './error.js';
import { MAX_CASE_RESTARTS } from './types.js';
import { normalizeTarget, sameTarget } from './target.js';
import { oracleBindingError, oracleFileHash, readOracle } from './oracle.js';
import type { EventRecord, PlanBlock, ProjectFile, TargetSpec } from './types.js';

export interface ProjectInitSpec {
  id: string;
  title: string;
  goal: string;
  origin?: string;
  category: string;
  flagFormat: string;
  backend?: 'host' | 'docker';
  dockerImage?: string;
  target?: TargetSpec;
  oracle: { type: 'local'; ref: string };
  deadlineMs?: number | null;
  allowedHosts?: string[];
}


export class Project {
  readonly root: string;
  readonly ctfDir: string;
  private readonly lock: FileLock;

  private constructor(root: string) {
    this.root = path.resolve(root);
    this.ctfDir = path.join(this.root, '.ctf');
    this.lock = FileLock.at(path.join(this.ctfDir, '.lock'));
  }

  static init(root: string, spec: ProjectInitSpec): Project {
    const rootAbs = path.resolve(root);
    fs.mkdirSync(rootAbs, { recursive: true });
    const ctfDir = path.join(rootAbs, '.ctf');
    if (fs.existsSync(path.join(ctfDir, 'project.json'))) {
      throw new KernelError('CONFLICT', `project already initialized at ${ctfDir}`);
    }
    // Oracle must be a relative reference to a file OUTSIDE the challenge
    // root but INSIDE its parent (kernel-design §8: 工作区外, no model writes).
    if (path.isAbsolute(spec.oracle.ref)) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must be relative');
    }
    const oracleAbs = path.resolve(rootAbs, spec.oracle.ref);
    const parent = path.dirname(rootAbs);
    const oracleRel = path.relative(parent, oracleAbs);
    if (oracleRel === '' || oracleRel.startsWith('..') || path.isAbsolute(oracleRel)) {
      throw new KernelError(
        'INVALID_REQUEST',
        `oracle.ref must stay inside the challenge parent directory (resolved to ${oracleAbs})`,
      );
    }
    if (oracleAbs === rootAbs || oracleAbs.startsWith(rootAbs + path.sep)) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must be outside the challenge workspace');
    }
    if (oracleAbs.startsWith(ctfDir + path.sep) || oracleAbs === ctfDir) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must not point inside .ctf/');
    }
    for (const dir of [
      'artifacts',
      'outcomes',
      'items',
      'observations',
      'claims',
      'facts',
      'negatives',
      'sessions',
    ]) {
      fs.mkdirSync(path.join(ctfDir, dir), { recursive: true });
    }
    const initialOracleHash = oracleFileHash(oracleAbs);
    const initialOracle = readOracle(oracleAbs)?.oracle;
    if (initialOracleHash && initialOracle) {
      const bindingError = oracleBindingError(initialOracle, spec.target ? normalizeTarget(spec.target) : null);
      if (bindingError) throw new KernelError('ORACLE', bindingError);
    }
    const project: ProjectFile = {
      version: 1,
      id: spec.id,
      title: spec.title,
      goal: spec.goal,
      origin: spec.origin ?? '',
      status: 'active',
      category: spec.category,
      backend: spec.backend ?? 'docker',
      dockerImage: spec.dockerImage,
      target: spec.target ? normalizeTarget(spec.target) : undefined,
      root: rootAbs,
      rootIdentity: rootIdentity(rootAbs),
      envHash: sha256(`${process.platform}:${process.arch}:${spec.backend ?? 'docker'}`),
      flagFormat: spec.flagFormat,
      oracle: spec.oracle,
      oracleHash: initialOracleHash,
      deadlineMs: spec.deadlineMs ?? null,
      allowedHosts: spec.allowedHosts ?? ['*'],
      counters: { command: 0, commandSeq: 0, claim: 0, fact: 0, negative: 0, event: 0, session: 0 },
      revisions: { event: 0, claim: 0, fact: 0, negative: 0 },
    };
    const proj = new Project(rootAbs);
    proj.lock.withLock(() => {
      const cur = readJsonIfExists<ProjectFile>(path.join(ctfDir, 'project.json'));
      if (cur) throw new KernelError('CONFLICT', 'project already initialized');
      fs.writeFileSync(
        path.join(ctfDir, 'project.json'),
        JSON.stringify(project, null, 2),
      );
      fs.writeFileSync(path.join(ctfDir, 'events.jsonl'), '');
      fs.writeFileSync(path.join(ctfDir, 'flags.jsonl'), '');
      proj.writePlan({ chain: [], next: '', preconditions: [] });
      proj.appendEvent('project.init', 'adapter', { id: spec.id, category: spec.category });
    });
    return proj;
  }

  /** Open an existing project; fail closed if the root was moved/replaced. */
  static open(root: string): Project {
    const rootAbs = path.resolve(root);
    const ctfDir = path.join(rootAbs, '.ctf');
    const projectJson = path.join(ctfDir, 'project.json');
    if (!fs.existsSync(projectJson)) {
      throw new KernelError('NOT_FOUND', `no project at ${ctfDir}`);
    }
    const file = readJson<ProjectFile>(projectJson);
    const currentId = rootIdentity(rootAbs);
    if (currentId !== file.rootIdentity) {
      throw new KernelError(
        'SECURITY',
        `root identity mismatch (expected ${file.rootIdentity}, got ${currentId}); project root moved or replaced`,
      );
    }
    return new Project(rootAbs);
  }

  /** Run fn under the project lock (short lock: ledgers, counters, events). */
  withLock<T>(fn: () => T): T {
    return this.lock.withLock(fn);
  }

  file(): ProjectFile {
    return readJson<ProjectFile>(path.join(this.ctfDir, 'project.json'));
  }

  private mutateFile(fn: (file: ProjectFile) => void): ProjectFile {
    return this.lock.withLock(() => {
      const filePath = path.join(this.ctfDir, 'project.json');
      const file = readJson<ProjectFile>(filePath);
      fn(file);
      atomicWriteFile(filePath, JSON.stringify(file, null, 2));
      return file;
    });
  }

  /** Allocate the next monotonic id for a kind, under lock. */
  allocId(kind: 'command' | 'claim' | 'fact' | 'negative' | 'session'): { id: string; seq: number } {
    const prefixes: Record<string, string> = {
      command: 'cmd-',
      claim: 'c',
      fact: 'f',
      negative: 'n',
      session: 's',
    };
    let commandSeq = 0;
    const file = this.mutateFile((f) => {
      f.counters[kind] = (f.counters[kind] ?? 0) + 1;
      if (kind === 'command') {
        // Budget and id sequence are separate: restart resets the former, but
        // old cmd-* files must never be overwritten. Existing projects migrate
        // by starting after the largest id already on disk.
        const prior = Math.max(f.counters.commandSeq ?? 0, this.maxCommandSeq());
        commandSeq = prior + 1;
        f.counters.commandSeq = commandSeq;
      }
    });
    const seq = kind === 'command' ? commandSeq : file.counters[kind];
    return { id: `${prefixes[kind]}${String(seq).padStart(4, '0')}`, seq };
  }

  /** Largest existing cmd-NNNN id (used to migrate projects created before the
   *  budget/id split, and to make restart non-destructive). */
  private maxCommandSeq(): number {
    const dir = path.join(this.ctfDir, 'outcomes');
    if (!fs.existsSync(dir)) return 0;
    let max = 0;
    for (const name of fs.readdirSync(dir)) {
      const m = /^cmd-(\d+)\.json$/.exec(name);
      if (m) max = Math.max(max, Number(m[1]));
    }
    return max;
  }

  /** Last successful flagFormat change, for audit in the flag response. */
  lastFormatChange(): { ts: number; actor: string; flagFormat: string } | null {
    const events = path.join(this.ctfDir, 'events.jsonl');
    if (!fs.existsSync(events)) return null;
    let last: { ts: number; actor: string; flagFormat: string } | null = null;
    for (const line of fs.readFileSync(events, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line) as {
          ts?: unknown;
          actor?: unknown;
          type?: unknown;
          payload?: { flagFormat?: unknown };
        };
        if (event.type !== 'project.reconfigure' || typeof event.ts !== 'number' || typeof event.payload?.flagFormat !== 'string') continue;
        last = {
          ts: event.ts,
          actor: typeof event.actor === 'string' ? event.actor : 'adapter',
          flagFormat: event.payload.flagFormat,
        };
      } catch {
        // Audit is best effort; a truncated event line must not block flag validation.
      }
    }
    return last;
  }

  appendEvent(type: string, actor: string, payload: Record<string, unknown>): EventRecord {
    return this.lock.withLock(() => {
      const filePath = path.join(this.ctfDir, 'project.json');
      const file = readJson<ProjectFile>(filePath);
      const seq = (file.counters.event ?? 0) + 1;
      const rec: EventRecord = { seq, ts: Date.now(), type, actor, payload };
      fs.appendFileSync(path.join(this.ctfDir, 'events.jsonl'), JSON.stringify(rec) + '\n');
      file.counters.event = seq;
      file.revisions.event = seq;
      atomicWriteFile(filePath, JSON.stringify(file, null, 2));
      return rec;
    });
  }

  // -- plan block -----------------------------------------------------------

  writePlan(plan: PlanBlock): void {
    const bounded: PlanBlock = {
      chain: plan.chain.slice(0, 8).map((s) => s.slice(0, 200)),
      next: plan.next.slice(0, 300),
      preconditions: plan.preconditions.slice(0, 5).map((s) => s.slice(0, 150)),
    };
    atomicWriteFile(path.join(this.ctfDir, 'plan.json'), JSON.stringify(bounded, null, 2));
    this.appendEvent('plan.update', 'adapter', { next: bounded.next });
  }

  readPlan(): PlanBlock {
    return (
      readJsonIfExists<PlanBlock>(path.join(this.ctfDir, 'plan.json')) ?? {
        chain: [],
        next: '',
        preconditions: [],
      }
    );
  }

  // -- goal contract --------------------------------------------------------

  goalContract() {
    const f = this.file();
    return {
      flagFormat: f.flagFormat,
      allowedHosts: f.allowedHosts,
      allowedPathPrefixes: ['.'],
      backend: f.backend,
      dockerImage: f.dockerImage,
      target: f.target ?? null,
      deadlineMs: f.deadlineMs,
      noAutoSubmit: true as const,
    };
  }

  status(): Record<string, unknown> {
    const f = this.file();
    const events = fs
      .readFileSync(path.join(this.ctfDir, 'events.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean);
    const last = events.length > 0 ? JSON.parse(events[events.length - 1]) : null;
    const flagAccepted = this.flagAccepted();
    let syntheticFacts = 0;
    let totalFacts = 0;
    const factsDir = path.join(this.ctfDir, 'facts');
    if (fs.existsSync(factsDir)) {
      for (const name of fs.readdirSync(factsDir)) {
        if (!name.endsWith('.json')) continue;
        try {
          const fact = JSON.parse(fs.readFileSync(path.join(factsDir, name), 'utf8')) as { synthetic?: boolean };
          totalFacts++;
          if (fact.synthetic) syntheticFacts++;
        } catch {
          // doctor reports unreadable nodes
        }
      }
    }
    return {
      id: f.id,
      title: f.title,
      status: f.status,
      category: f.category,
      backend: f.backend,
      target: f.target ?? null,
      deadlineMs: f.deadlineMs,
      counters: f.counters,
      facts: { total: totalFacts, synthetic: syntheticFacts },
      revisions: f.revisions,
      lastEvent: last ? { seq: last.seq, type: last.type, ts: last.ts } : null,
      flagAccepted,
    };
  }

  flagAccepted(): boolean {
    const ledger = path.join(this.ctfDir, 'flags.jsonl');
    if (!fs.existsSync(ledger)) return false;
    const current = this.file().target ?? null;
    return fs
      .readFileSync(ledger, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .some((line) => {
        const rec = JSON.parse(line) as { status?: string; target?: unknown };
        if (rec.status !== 'accepted') return false;
        if (!current) return true;
        // Missing target on a legacy record cannot prove it belongs to the
        // current rotating instance.
        if (!rec.target || typeof rec.target !== 'object') return false;
        return sameTarget(rec.target as Parameters<typeof sameTarget>[0], current);
      });
  }

  /** Explicitly update flagFormat/oracle/backend and pin the new oracle
   *  contents. Used to repair a bad flagFormat, adopt a real externally
   *  supplied oracle, or move a case between host and docker without
   *  discarding artifacts/claims/facts. */
  reconfigure(input: {
    flagFormat?: string;
    oracleRef?: string;
    backend?: 'host' | 'docker';
    dockerImage?: string;
    target?: TargetSpec | null;
    allowedHosts?: string[];
  }): {
    flagFormat: string;
    oracleRef: string;
    oracleHash: string | null;
    backend: 'host' | 'docker';
    dockerImage?: string;
    target: TargetSpec | null;
    allowedHosts: string[];
  } {
    const current = this.file();
    if (current.status !== 'active') {
      throw new KernelError('CONFLICT', `case is ${current.status}; configure requires an active case`);
    }
    const flagFormat = input.flagFormat ?? current.flagFormat;
    try {
      new RegExp(flagFormat);
    } catch {
      throw new KernelError('INVALID_REQUEST', `invalid flagFormat regex: ${flagFormat}`);
    }
    const oracleRef = input.oracleRef ?? current.oracle.ref;
    if (path.isAbsolute(oracleRef)) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must be relative');
    }
    const oracleAbs = path.resolve(this.root, oracleRef);
    const parent = path.dirname(this.root);
    const rel = path.relative(parent, oracleAbs);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must stay inside the challenge parent directory');
    }
    if (oracleAbs === this.root || oracleAbs.startsWith(this.root + path.sep)) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must be outside the challenge workspace');
    }
    if (oracleAbs.startsWith(this.ctfDir + path.sep) || oracleAbs === this.ctfDir) {
      throw new KernelError('INVALID_REQUEST', 'oracle.ref must not point inside .ctf/');
    }
    const backend = input.backend ?? current.backend;
    if (backend !== 'host' && backend !== 'docker') {
      throw new KernelError('INVALID_REQUEST', 'backend must be host or docker');
    }
    const allowedHosts = input.allowedHosts ?? current.allowedHosts;
    if (!Array.isArray(allowedHosts) || allowedHosts.length === 0 || allowedHosts.some((h) => typeof h !== 'string' || h.length === 0 || h.length > 200)) {
      throw new KernelError('INVALID_REQUEST', 'allowedHosts must be a non-empty string array');
    }
    const dockerImage = input.dockerImage ?? current.dockerImage;
    if (backend === 'docker' && !dockerImage) {
      throw new KernelError('INVALID_REQUEST', 'docker backend requires dockerImage');
    }
    const oracleHash = oracleFileHash(oracleAbs);
    const oracle = readOracle(oracleAbs)?.oracle;
    const target = input.target === undefined
      ? (current.target ?? null)
      : input.target === null
        ? null
        : normalizeTarget(input.target);
    if (oracleHash && oracle) {
      const bindingError = oracleBindingError(oracle, target);
      if (bindingError) throw new KernelError('ORACLE', bindingError);
    }
    this.mutateFile((file) => {
      file.flagFormat = flagFormat;
      file.oracle = { type: 'local', ref: oracleRef };
      file.oracleHash = oracleHash;
      file.backend = backend;
      file.allowedHosts = allowedHosts;
      if (target) file.target = target;
      else delete file.target;
      if (dockerImage) file.dockerImage = dockerImage;
      else delete file.dockerImage;
      file.envHash = sha256(`${process.platform}:${process.arch}:${backend}`);
    });
    this.appendEvent('project.reconfigure', 'adapter', {
      flagFormat,
      oracleRef,
      oraclePinned: oracleHash !== null,
      backend,
      dockerImage: dockerImage ?? null,
      target: target ?? null,
    });
    return { flagFormat, oracleRef, oracleHash, backend, dockerImage, target, allowedHosts };
  }

  /** Start a fresh command budget while preserving evidence/claims/facts.
   *  The case stays active; restart count is audited and capped. */
  restart(maxRestarts = MAX_CASE_RESTARTS): { restarts: number; command: number } {
    let restarts = 0;
    this.mutateFile((file) => {
      if (file.status !== 'active') {
        throw new KernelError('CONFLICT', `case is ${file.status}; restart requires an active case`);
      }
      restarts = file.counters.restart ?? 0;
      if (restarts >= maxRestarts) {
        throw new KernelError('LIMIT', `case restart limit reached (${restarts}/${maxRestarts})`);
      }
      file.counters.command = 0;
      file.counters.restart = restarts + 1;
    });
    this.appendEvent('case.restart', 'adapter', { restart: restarts + 1, command: 0 });
    return { restarts: restarts + 1, command: 0 };
  }

  /** Count an automatic target reset attempt; the cap is enforced by the
   *  caller so a failed reset is audited rather than silently retried. */
  recordTargetReset(): number {
    let count = 0;
    this.mutateFile((file) => {
      count = (file.counters.targetReset ?? 0) + 1;
      file.counters.targetReset = count;
    });
    return count;
  }

  close(status: 'completed' | 'failed' | 'stopped'): void {
    this.mutateFile((f) => {
      f.status = status;
    });
    this.appendEvent('project.close', 'adapter', { status });
  }
}
