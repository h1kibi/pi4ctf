/**
 * Ledger store: the four records (docs/design.md §4.2) plus the negative
 * ledger gate. Store rows are never deleted; dedupe only affects packet/
 * recent views and counters. One file per node, atomic replace, append-only
 * events.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import { atomicWriteFile, readJson } from '../fsutil.js';
import { Project } from '../project.js';
import type {
  Claim,
  EvidenceItem,
  Fact,
  NegativeEntry,
  Observation,
  ProcessOutcome,
} from '../types.js';

export interface PacketState {
  outcomes: ProcessOutcome[];
  claims: Claim[];
  facts: Fact[];
  negatives: NegativeEntry[];
  recent: ProcessOutcome[];
  issues: string[];
}

function isStreamRef(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const stream = value as Record<string, unknown>;
  return typeof stream.excerpt === 'string' && typeof stream.shapedRef === 'string';
}

/** Minimal shape required by packetState and packet rendering. Invalid rows
 *  become integrity issues instead of crashing context/handoff. */
function validPacketRow(dir: string, row: unknown): boolean {
  if (typeof row !== 'object' || row === null || Array.isArray(row)) return false;
  const r = row as Record<string, unknown>;
  if (typeof r.id !== 'string') return false;
  if (dir === 'outcomes') {
    if (typeof r.ts !== 'number'
      || typeof r.canonicalKey !== 'string'
      || typeof r.intentClass !== 'string'
      || !isStreamRef(r.stdout)
      || !isStreamRef(r.stderr)) return false;
    if (r.items !== undefined) {
      if (typeof r.items !== 'object' || r.items === null || Array.isArray(r.items)) return false;
      const ids = (r.items as Record<string, unknown>).ids;
      if (ids !== undefined && !Array.isArray(ids)) return false;
    }
    return true;
  }
  if (dir === 'claims') {
    return typeof r.state === 'string'
      && typeof r.claimType === 'string'
      && typeof r.text === 'string'
      && Array.isArray(r.refs)
      && r.refs.every((ref) => typeof ref === 'string');
  }
  if (dir === 'facts') {
    return typeof r.claimType === 'string'
      && typeof r.predicate === 'string'
      && Array.isArray(r.observationRefs)
      && r.value !== undefined;
  }
  if (dir === 'negatives') {
    return typeof r.signature === 'string'
      && typeof r.failureClass === 'string'
      && typeof r.blockScope === 'string';
  }
  return true;
}

export class Ledger {
  constructor(private readonly project: Project) {}

  // -- outcomes -------------------------------------------------------------

  getOutcome(id: string): ProcessOutcome {
    const p = path.join(this.project.ctfDir, `outcomes/${id}.json`);
    if (!fs.existsSync(p)) throw new KernelError('NOT_FOUND', `outcome ${id} not found`);
    return readJson<ProcessOutcome>(p);
  }

  getObservation(id: string): Observation {
    return JSON.parse(this.readArtifact(`observations/${id}.json`)) as Observation;
  }

  listOutcomes(): ProcessOutcome[] {
    // Timestamp order, not filename order: case.restart resets the budget
    // counter while command ids stay monotonic across the same case.
    return this.listDir<ProcessOutcome>('outcomes').sort((a, b) => (a.ts - b.ts) || a.id.localeCompare(b.id));
  }

  /** Resolve a parent outcome or a child evidence item by canonical ref. */
  getEvidence(ref: string): {
    kind: 'outcome' | 'item';
    outcome: ProcessOutcome;
    item: EvidenceItem | null;
  } {
    if (/^cmd-\d{4}$/.test(ref)) {
      return { kind: 'outcome', outcome: this.getOutcome(ref), item: null };
    }
    const m = /^(cmd-\d{4})\.(\d{4})$/.exec(ref);
    if (!m) throw new KernelError('INVALID_REQUEST', `invalid evidence ref: ${ref}`);
    const outcome = this.getOutcome(m[1]);
    const p = path.join(this.project.ctfDir, `items/${ref}.json`);
    if (!fs.existsSync(p)) throw new KernelError('NOT_FOUND', `evidence item ${ref} not found`);
    return { kind: 'item', outcome, item: readJson<EvidenceItem>(p) };
  }

  /** The only artifacts a claim quoting `refs` may anchor to. */
  allowedShapedRefs(refs: string[]): Set<string> {
    const allowed = new Set<string>();
    for (const ref of refs) {
      const resolved = this.getEvidence(ref);
      if (resolved.item) {
        allowed.add(resolved.item.stdout.shapedRef);
        allowed.add(resolved.item.stderr.shapedRef);
      } else {
        allowed.add(resolved.outcome.stdout.shapedRef);
        allowed.add(resolved.outcome.stderr.shapedRef);
      }
    }
    return allowed;
  }

  private resolveArtifact(relRef: string): string {
    if (relRef.includes('..') || path.isAbsolute(relRef)) {
      throw new KernelError('SECURITY', `bad artifact ref ${relRef}`);
    }
    // Per-segment no-follow (review C2): a symlink planted anywhere on the
    // path must not let the reader escape .ctf/.
    const normalized = path.posix.normalize(relRef.replace(/\\/g, '/'));
    let cur = this.project.ctfDir;
    for (const seg of normalized.split('/')) {
      if (seg === '' || seg === '.') continue;
      cur = path.join(cur, seg);
      let st: import('node:fs').Stats;
      try {
        st = fs.lstatSync(cur);
      } catch {
        throw new KernelError('NOT_FOUND', `artifact ${relRef} not found`);
      }
      if (st.isSymbolicLink()) {
        throw new KernelError('SECURITY', `symlink in artifact path: ${relRef}`);
      }
    }
    // Final containment: realpath must stay inside the realpath of .ctf.
    const realRoot = fs.realpathSync(this.project.ctfDir);
    const real = fs.realpathSync(cur);
    if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
      throw new KernelError('SECURITY', `artifact ref escapes .ctf: ${relRef}`);
    }
    if (!fs.existsSync(cur)) throw new KernelError('NOT_FOUND', `artifact ${relRef} not found`);
    return cur;
  }

  readArtifact(relRef: string): string {
    return fs.readFileSync(this.resolveArtifact(relRef), 'utf8');
  }

  readArtifactBuffer(relRef: string): Buffer {
    return fs.readFileSync(this.resolveArtifact(relRef));
  }

  // -- claims ---------------------------------------------------------------

  saveClaim(claim: Claim): void {
    atomicWriteFile(
      path.join(this.project.ctfDir, `claims/${claim.id}.json`),
      JSON.stringify(claim, null, 2),
    );
  }

  getClaim(id: string): Claim {
    const p = path.join(this.project.ctfDir, `claims/${id}.json`);
    if (!fs.existsSync(p)) throw new KernelError('NOT_FOUND', `claim ${id} not found`);
    return readJson<Claim>(p);
  }

  listClaims(): Claim[] {
    return this.listDir<Claim>('claims');
  }

  /** Open claims (proposed/checking) are the work queue; they enter the packet. */
  openClaims(): Claim[] {
    return this.listClaims().filter((c) => c.state === 'proposed' || c.state === 'checking');
  }

  /** Resubmission gate: same claim signature is blocked unless it cites a
   *  new artifact or a new span (docs/design.md §4.2). */
  findSameSignature(signature: string): Claim[] {
    return this.listClaims().filter((c) => c.signature === signature);
  }

  // -- facts ----------------------------------------------------------------

  saveFact(fact: Fact): void {
    atomicWriteFile(
      path.join(this.project.ctfDir, `facts/${fact.id}.json`),
      JSON.stringify(fact, null, 2),
    );
    this.project.appendEvent('fact.add', 'kernel', {
      id: fact.id,
      claimId: fact.claimId,
      predicate: fact.predicate,
    });
  }

  listFacts(): Fact[] {
    return this.listDir<Fact>('facts');
  }

  getFact(id: string): Fact {
    const p = path.join(this.project.ctfDir, `facts/${id}.json`);
    if (!fs.existsSync(p)) throw new KernelError('NOT_FOUND', `fact ${id} not found`);
    return readJson<Fact>(p);
  }

  // -- negative ledger ------------------------------------------------------

  listNegatives(): NegativeEntry[] {
    // Legacy exec-local entries collapsed every `python -c` into one signature;
    // they are no longer created and must not poison the packet or gate.
    return this.listDir<NegativeEntry>('negatives')
      .filter((n) => !(n.transient && n.signature.startsWith('exec-local|')));
  }

  /** Packet-only snapshot: unreadable rows are reported, not skipped silently.
   *  Claim and flag paths keep using the fail-fast list methods. */
  packetState(limit = 5): PacketState {
    const outcomeResult = this.listDirWithIssues<ProcessOutcome>('outcomes');
    outcomeResult.items.sort((a, b) => (a.ts - b.ts) || a.id.localeCompare(b.id));
    const claimResult = this.listDirWithIssues<Claim>('claims');
    const factResult = this.listDirWithIssues<Fact>('facts');
    const negativeResult = this.listDirWithIssues<NegativeEntry>('negatives');
    const claims = claimResult.items.filter((c) => c.state === 'proposed' || c.state === 'checking');
    const negatives = negativeResult.items.filter((n) => !(n.transient && n.signature.startsWith('exec-local|')));
    const exempt = new Set<string>();
    for (const claim of claims) {
      for (const ref of claim.refs) {
        exempt.add(ref);
        exempt.add(ref.split('.')[0]);
      }
    }
    const seen = new Set<string>();
    const recent: ProcessOutcome[] = [];
    for (const o of [...outcomeResult.items].reverse()) {
      if (exempt.has(o.id)) {
        recent.push(o);
        continue;
      }
      if (seen.has(o.canonicalKey)) continue;
      seen.add(o.canonicalKey);
      recent.push(o);
    }
    return {
      outcomes: outcomeResult.items,
      claims,
      facts: factResult.items,
      negatives,
      recent: recent.slice(0, limit),
      issues: [...outcomeResult.issues, ...claimResult.issues, ...factResult.issues, ...negativeResult.issues],
    };
  }

  /** Record/upsert a negative entry. failureClass is code-owned. Upsert is
   *  keyed by signature: attempts increment, latest class wins. */
  addNegative(entry: Omit<NegativeEntry, 'attempts' | 'lastAttemptAt' | 'id'> & { attempts?: number; id?: string }): NegativeEntry {
    const existing = this.listNegatives().find((n) => n.signature === entry.signature);
    const now = Date.now();
    const record = existing
      ? {
          ...existing,
          ...entry,
          id: existing.id,
          attempts: (existing.attempts ?? 0) + 1,
          lastAttemptAt: now,
          unblockedAt: null, // fresh failure re-arms the gate
          unblockReason: null,
        }
      : { ...entry, id: entry.id ?? this.project.allocId('negative').id, attempts: entry.attempts ?? 1, lastAttemptAt: now } as NegativeEntry;
    atomicWriteFile(
      path.join(this.project.ctfDir, `negatives/${record.id}.json`),
      JSON.stringify(record, null, 2),
    );
    this.project.appendEvent('negative.add', 'kernel', {
      signature: record.signature,
      failureClass: record.failureClass,
      transient: record.transient,
      blockScope: record.blockScope,
      attempts: record.attempts,
    });
    return record;
  }

  /** The signature gate: hard-block only non-transient entries; transient
   *  entries block until TTL/probe/env_change (ADR 0002 §4). Returns the
   *  blocking entry or null. Expiry is marked once on the entry so the
   *  `unblocked` audit event is not re-emitted on every check. */
  blockedSignature(signature: string): NegativeEntry | null {
    let blocked: NegativeEntry | null = null;
    for (const entry of this.listNegatives()) {
      if (entry.signature !== signature) continue;
      if (entry.transient) {
        if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
          if (!entry.unblockedAt && entry.id) {
            const marked = { ...entry, unblockedAt: Date.now(), unblockReason: 'ttl' as const };
            atomicWriteFile(
              path.join(this.project.ctfDir, `negatives/${marked.id}.json`),
              JSON.stringify(marked, null, 2),
            );
            this.project.appendEvent('negative.unblocked', 'kernel', {
              signature,
              reason: 'ttl',
            });
          }
          continue;
        }
        if (entry.unblockedAt) continue;
      }
      blocked = entry;
    }
    return blocked;
  }

  /** A restart is a new context: transient (soft) blocks from the previous
   *  attempt must not poison the next one. Hard blocks stay. Rows are marked,
   *  not deleted, so the audit trail survives. */
  clearTransientNegatives(id?: string): number {
    let cleared = 0;
    for (const entry of this.listNegatives()) {
      if (id && entry.id !== id) continue;
      if (!entry.transient || entry.unblockedAt) continue;
      if (!entry.id) continue;
      const marked = {
        ...entry,
        unblockedAt: Date.now(),
        unblockReason: 'env_change' as const,
      };
      atomicWriteFile(
        path.join(this.project.ctfDir, `negatives/${marked.id}.json`),
        JSON.stringify(marked, null, 2),
      );
      this.project.appendEvent('negative.unblocked', 'kernel', {
        signature: entry.signature,
        reason: 'env_change',
        source: 'case.restart',
      });
      cleared++;
    }
    return cleared;
  }

  // -- dedupe index (projection; store rows are never removed) --------------

  /** Count of executions per canonicalKey. */
  canonicalCounts(): Map<string, number> {
    const counts = new Map<string, number>();
    for (const o of this.listOutcomes()) {
      counts.set(o.canonicalKey, (counts.get(o.canonicalKey) ?? 0) + 1);
    }
    return counts;
  }

  /** Recent outcomes for the packet: newest first, deduped by canonicalKey
   *  except legs referenced by open claims (differential exemption,
   *  docs/design.md §4.1). */
  recentOutcomes(limit: number): ProcessOutcome[] {
    return this.packetState(limit).recent;
  }

  private listDirWithIssues<T>(dir: string): { items: T[]; issues: string[] } {
    const abs = path.join(this.project.ctfDir, dir);
    if (!fs.existsSync(abs)) return { items: [], issues: [] };
    let names: string[];
    try {
      names = fs
        .readdirSync(abs)
        .filter((n) => n.endsWith('.json'))
        .sort();
    } catch {
      return { items: [], issues: [`unreadable dir: ${dir}`] };
    }
    const items: T[] = [];
    const issues: string[] = [];
    for (const name of names) {
      try {
        const row = readJson<unknown>(path.join(abs, name));
        if (!validPacketRow(dir, row)) {
          issues.push(`invalid row: ${dir}/${name}`);
          continue;
        }
        items.push(row as T);
      } catch {
        issues.push(`unreadable json: ${dir}/${name}`);
      }
    }
    return { items, issues };
  }

  private listDir<T>(dir: string): T[] {
    const abs = path.join(this.project.ctfDir, dir);
    if (!fs.existsSync(abs)) return [];
    const names = fs
      .readdirSync(abs)
      .filter((n) => n.endsWith('.json'))
      .sort();
    const items: T[] = [];
    for (const name of names) {
      items.push(readJson<T>(path.join(abs, name)));
    }
    return items;
  }
}
