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
import { allocateCommand } from './commands.js';
import { appendEventRecord, lastFormatChange as readLastFormatChange } from './events.js';
import { normalizePlan, readPlanBlock } from './plan.js';
import { normalizeTarget, sameTarget, targetRef } from './target.js';
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


interface Placement {
  root: string;
  ctfDir: string;
  containerRoot: string;
  caseId?: string;
  workspace: string;
}

interface CaseIndex {
  version: 1;
  active: string;
}

const CASE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;

function isInsideOrEqual(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export class Project {
  /** Challenge files root (the Docker :/challenge mount). */
  readonly root: string;
  /** Container root that owns .ctf/ and workspace/. */
  readonly containerRoot: string;
  /** Timestamp case id; empty for a legacy flat .ctf. */
  readonly caseId: string;
  /** Per-case writable workspace (container/workspace/<id>). */
  readonly workspace: string;
  readonly ctfDir: string;
  private readonly lock: FileLock;

  private constructor(root: string, placement: Omit<Placement, 'root'>) {
    this.root = path.resolve(root);
    this.containerRoot = path.resolve(placement.containerRoot);
    this.caseId = placement.caseId ?? '';
    this.ctfDir = path.resolve(placement.ctfDir);
    this.workspace = path.resolve(placement.workspace);
    this.lock = FileLock.at(path.join(this.ctfDir, '.lock'));
  }

  /** Legacy flat project: <challenge>/.ctf + <challenge>/workspace. */
  static init(root: string, spec: ProjectInitSpec): Project {
    const rootAbs = path.resolve(root);
    fs.mkdirSync(rootAbs, { recursive: true });
    const ctfDir = path.join(rootAbs, '.ctf');
    fs.mkdirSync(ctfDir, { recursive: true });
    if (fs.existsSync(path.join(ctfDir, 'project.json'))) {
      throw new KernelError('CONFLICT', `project already initialized at ${ctfDir}`);
    }
    return Project.initialize(
      {
        root: rootAbs,
        ctfDir,
        containerRoot: rootAbs,
        workspace: path.join(rootAbs, 'workspace'),
      },
      spec,
    );
  }

  /** Create one timestamped case under <container>/.ctf/<id>. The challenge
   *  root can be the container itself or a subdirectory (e.g. test/challenges/A). */
  static initCase(
    containerRoot: string,
    challengeRoot: string,
    spec: ProjectInitSpec,
    requestedId?: string,
  ): Project {
    const containerAbs = path.resolve(containerRoot);
    const challengeAbs = path.resolve(challengeRoot);
    fs.mkdirSync(containerAbs, { recursive: true });
    fs.mkdirSync(challengeAbs, { recursive: true });
    if (!isInsideOrEqual(containerAbs, challengeAbs)) {
      throw new KernelError('SECURITY', 'challenge root must be inside the container root');
    }
    const ctfRoot = path.join(containerAbs, '.ctf');
    fs.mkdirSync(ctfRoot, { recursive: true });
    let id = requestedId ?? Project.newCaseId();
    if (!CASE_ID_RE.test(id)) {
      throw new KernelError('INVALID_REQUEST', `invalid case id: ${id}`);
    }
    if (requestedId && fs.existsSync(path.join(ctfRoot, id))) {
      throw new KernelError('CONFLICT', `case already exists: ${id}`);
    }
    if (!requestedId) {
      let suffix = 2;
      while (fs.existsSync(path.join(ctfRoot, id))) {
        id = `${Project.newCaseId()}-${suffix++}`;
      }
    }
    const ctfDir = path.join(ctfRoot, id);
    fs.mkdirSync(ctfDir, { recursive: true });
    const workspace = path.join(containerAbs, 'workspace', id);
    fs.mkdirSync(workspace, { recursive: true });
    const project = Project.initialize(
      {
        root: challengeAbs,
        ctfDir,
        containerRoot: containerAbs,
        caseId: id,
        workspace,
      },
      spec,
    );
    Project.setActiveCase(containerAbs, id);
    return project;
  }

  static newCaseId(now = new Date()): string {
    const p = (n: number) => String(n).padStart(2, '0');
    return `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`;
  }

  private static initialize(placement: Placement, spec: ProjectInitSpec): Project {
    const rootAbs = placement.root;
    const ctfDir = placement.ctfDir;
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
    fs.mkdirSync(placement.workspace, { recursive: true });
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
      ...(placement.caseId ? { containerRoot: placement.containerRoot, caseId: placement.caseId } : {}),
      rootIdentity: rootIdentity(rootAbs),
      envHash: sha256(`${process.platform}:${process.arch}:${spec.backend ?? 'docker'}`),
      flagFormat: spec.flagFormat,
      oracle: spec.oracle,
      oracleHash: initialOracleHash,
      deadlineMs: spec.deadlineMs ?? null,
      timeLimitAtMs: null,
      allowedHosts: spec.allowedHosts ?? ['*'],
      counters: { command: 0, commandSeq: 0, claim: 0, fact: 0, negative: 0, event: 0, session: 0 },
      revisions: { event: 0, claim: 0, fact: 0, negative: 0 },
    };
    const proj = new Project(rootAbs, {
      ctfDir,
      containerRoot: placement.containerRoot,
      caseId: placement.caseId,
      workspace: placement.workspace,
    });
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

  static readIndex(containerRoot: string): CaseIndex | null {
    const file = path.join(path.resolve(containerRoot), '.ctf', 'index.json');
    if (!fs.existsSync(file)) return null;
    const raw = readJson<Partial<CaseIndex>>(file);
    if (raw.version !== 1 || typeof raw.active !== 'string' || !CASE_ID_RE.test(raw.active)) {
      throw new KernelError('CONFLICT', `invalid .ctf/index.json at ${file}`);
    }
    return { version: 1, active: raw.active };
  }

  static activeCaseId(containerRoot: string): string | null {
    return Project.readIndex(containerRoot)?.active ?? null;
  }

  static setActiveCase(containerRoot: string, caseId: string): void {
    const containerAbs = path.resolve(containerRoot);
    if (!CASE_ID_RE.test(caseId)) throw new KernelError('INVALID_REQUEST', `invalid case id: ${caseId}`);
    const ctfDir = path.join(containerAbs, '.ctf');
    if (!fs.existsSync(path.join(ctfDir, caseId, 'project.json'))) {
      throw new KernelError('NOT_FOUND', `case not found: ${caseId}`);
    }
    atomicWriteFile(
      path.join(ctfDir, 'index.json'),
      JSON.stringify({ version: 1, active: caseId }, null, 2),
    );
  }

  static caseIds(containerRoot: string): string[] {
    const ctfDir = path.join(path.resolve(containerRoot), '.ctf');
    if (!fs.existsSync(ctfDir)) return [];
    return fs
      .readdirSync(ctfDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && CASE_ID_RE.test(entry.name))
      .filter((entry) => fs.existsSync(path.join(ctfDir, entry.name, 'project.json')))
      .map((entry) => entry.name)
      .sort();
  }

  /** Best case whose challenge root equals or contains `directory`; a deeper
   *  challenge root wins over the container-wide case, then the newest wins. */
  static findCaseByChallengeRoot(containerRoot: string, directory: string): string | null {
    const wanted = path.resolve(directory);
    let best: { id: string; depth: number; mtime: number } | null = null;
    for (const id of Project.caseIds(containerRoot)) {
      try {
        const projectJson = path.join(path.resolve(containerRoot), '.ctf', id, 'project.json');
        const file = readJson<ProjectFile>(projectJson);
        const root = path.resolve(file.root);
        if (!isInsideOrEqual(root, wanted)) continue;
        const depth = root.length;
        const mtime = fs.statSync(projectJson).mtimeMs;
        if (!best || depth > best.depth || (depth === best.depth && mtime > best.mtime)) {
          best = { id, depth, mtime };
        }
      } catch {
        // A corrupt case is reported by doctor/status; activation skips it.
      }
    }
    return best?.id ?? null;
  }

  static openCase(containerRoot: string, caseId: string): Project {
    const containerAbs = path.resolve(containerRoot);
    if (!CASE_ID_RE.test(caseId)) throw new KernelError('INVALID_REQUEST', `invalid case id: ${caseId}`);
    const ctfDir = path.join(containerAbs, '.ctf', caseId);
    const projectJson = path.join(ctfDir, 'project.json');
    if (!fs.existsSync(projectJson)) {
      throw new KernelError('NOT_FOUND', `case not found: ${caseId} (looked in ${ctfDir})`);
    }
    const file = readJson<ProjectFile>(projectJson);
    const rootAbs = path.resolve(file.root);
    if (!isInsideOrEqual(containerAbs, rootAbs)) {
      throw new KernelError('SECURITY', 'case root escapes the container root');
    }
    if (file.containerRoot && path.resolve(file.containerRoot) !== containerAbs) {
      throw new KernelError('SECURITY', `case ${caseId} belongs to another container`);
    }
    const currentId = rootIdentity(rootAbs);
    if (currentId !== file.rootIdentity) {
      throw new KernelError(
        'SECURITY',
        `root identity mismatch (expected ${file.rootIdentity}, got ${currentId}); project root moved or replaced`,
      );
    }
    return new Project(rootAbs, {
      ctfDir,
      containerRoot: containerAbs,
      caseId,
      workspace: path.join(containerAbs, 'workspace', caseId),
    });
  }

  static activateCase(containerRoot: string, caseId: string): Project {
    const project = Project.openCase(containerRoot, caseId);
    Project.setActiveCase(containerRoot, caseId);
    return project;
  }

  /** Open the active case, or a legacy flat project. */
  static open(root: string): Project {
    const rootAbs = path.resolve(root);
    const index = Project.readIndex(rootAbs);
    if (index) return Project.openCase(rootAbs, index.active);
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
    return new Project(rootAbs, {
      ctfDir,
      containerRoot: rootAbs,
      workspace: path.join(rootAbs, 'workspace'),
    });
  }

  /** Run fn under the project lock (short lock: ledgers, counters, events). */
  withLock<T>(fn: () => T): T {
    return this.lock.withLock(fn);
  }

  file(): ProjectFile {
    return readJson<ProjectFile>(path.join(this.ctfDir, 'project.json'));
  }

  private mutateFile(fn: (file: ProjectFile) => void): ProjectFile {
    return this.mutateFileResult((file) => {
      fn(file);
      return file;
    });
  }

  private mutateFileResult<T>(fn: (file: ProjectFile) => T): T {
    return this.lock.withLock(() => {
      const filePath = path.join(this.ctfDir, 'project.json');
      const file = readJson<ProjectFile>(filePath);
      const result = fn(file);
      atomicWriteFile(filePath, JSON.stringify(file, null, 2));
      return result;
    });
  }

  /** Allocate the next monotonic id for a kind, under lock. */
  allocId(kind: 'claim' | 'fact' | 'negative' | 'session'): { id: string; seq: number } {
    const prefixes: Record<string, string> = {
      claim: 'c',
      fact: 'f',
      negative: 'n',
      session: 's',
    };
    const file = this.mutateFile((f) => {
      f.counters[kind] = (f.counters[kind] ?? 0) + 1;
    });
    const seq = file.counters[kind];
    return { id: `${prefixes[kind]}${String(seq).padStart(4, '0')}`, seq };
  }

  /** Reserve a command slot and id under one lock. Budget and deadline are
   *  checked at allocation time, so concurrent processes cannot overspend. */
  reserveCommand(): { id: string; seq: number } {
    let commandSeq = 0;
    this.mutateFile((f) => {
      commandSeq = allocateCommand(f, this.ctfDir, true);
    });
    return { id: `cmd-${String(commandSeq).padStart(4, '0')}`, seq: commandSeq };
  }

  /** Release a reservation that never produced a child process. The command
   *  sequence stays monotonic; only the budget counter is returned. */
  releaseCommand(): void {
    this.mutateFile((f) => {
      f.counters.command = Math.max(0, (f.counters.command ?? 0) - 1);
    });
  }

  /** Human-only budget continuation: same context, fresh command budget. */
  continueBudget(): { continues: number; command: number } {
    let continues = 0;
    this.mutateFile((f) => {
      if (f.status !== 'active') {
        throw new KernelError('CONFLICT', `case is ${f.status}; continue requires an active case`);
      }
      f.counters.command = 0;
      f.timeLimitAtMs = null;
      continues = (f.counters.continue ?? 0) + 1;
      f.counters.continue = continues;
    });
    this.appendEvent('case.continue', 'adapter', { continue: continues, command: 0 });
    return { continues, command: 0 };
  }

  /** Human-only time checkpoint. minutes=0 clears it. */
  setTimeLimit(minutes: number | null): { timeLimitAtMs: number | null } {
    let at: number | null = null;
    if (minutes !== null && minutes !== 0) {
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 7 * 24 * 60) {
        throw new KernelError('INVALID_REQUEST', 'time limit must be 1..10080 minutes, or 0 to clear');
      }
      at = Date.now() + minutes * 60_000;
    }
    this.mutateFile((f) => {
      f.timeLimitAtMs = at;
    });
    this.appendEvent('case.time', 'adapter', { minutes: at === null ? 0 : minutes, timeLimitAtMs: at });
    return { timeLimitAtMs: at };
  }

  /** Last successful flagFormat change, for audit in the flag response. */
  lastFormatChange(): { ts: number; actor: string; flagFormat: string } | null {
    return readLastFormatChange(path.join(this.ctfDir, 'events.jsonl'));
  }

  appendEvent(type: string, actor: string, payload: Record<string, unknown>): EventRecord {
    return this.mutateFileResult((file) =>
      appendEventRecord(file, path.join(this.ctfDir, 'events.jsonl'), type, actor, payload),
    );
  }

  // -- plan block -----------------------------------------------------------

  writePlan(plan: PlanBlock): void {
    const bounded = normalizePlan({
      ...plan,
      target: plan.target === undefined ? targetRef(this.file().target ?? null) : plan.target,
    });
    atomicWriteFile(path.join(this.ctfDir, 'plan.json'), JSON.stringify(bounded, null, 2));
    this.appendEvent('plan.update', 'adapter', { next: bounded.next });
  }

  readPlan(): PlanBlock {
    return readPlanBlock(path.join(this.ctfDir, 'plan.json'));
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
      caseId: this.caseId || null,
      root: this.root,
      containerRoot: this.containerRoot,
      workspace: this.workspace,
      title: f.title,
      status: f.status,
      category: f.category,
      backend: f.backend,
      target: f.target ?? null,
      deadlineMs: f.deadlineMs,
      timeLimitAtMs: f.timeLimitAtMs ?? null,
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
   *  Restart is human-only and deliberately uncapped: each attempt is audited. */
  restart(): { restarts: number; command: number; planCleared: boolean } {
    let restarts = 0;
    this.mutateFile((file) => {
      if (file.status !== 'active') {
        file.status = 'active';
      }
      file.counters.command = 0;
      file.timeLimitAtMs = null;
      restarts = (file.counters.restart ?? 0) + 1;
      file.counters.restart = restarts;
    });
    this.appendEvent('case.restart', 'adapter', { restart: restarts, command: 0 });
    const currentTarget = targetRef(this.file().target ?? null);
    const plan = this.readPlan();
    const planCleared = (plan.chain.length > 0 || plan.next.length > 0) && plan.target !== currentTarget;
    if (planCleared) {
      this.writePlan({ chain: [], next: '', preconditions: [], target: currentTarget });
    }
    return { restarts, command: 0, planCleared };
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
