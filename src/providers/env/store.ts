/** User-scoped, host-authoritative tool-environment memory. */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { atomicWriteFile, FileLock, sha256 } from '../../kernel/fsutil.js';
import { KernelError } from '../../kernel/error.js';
import { matchesCapability, providesFor } from './table.js';
import type { EnvContext } from './context.js';
import { redactSecrets } from './redact.js';

export interface EnvIdentity {
  backend: 'host' | 'docker';
  platform: string;
  arch: string;
  wslDistro?: string;
}

export interface ToolSig {
  size: number;
  mtimeMs: number;
}

export interface EnvTool {
  path: string;
  realpath: string;
  version: string | null;
  env?: { JAVA_HOME?: string };
  sig: ToolSig | null;
  source: 'user' | 'probe';
  pathSource?: 'user' | 'probe';
  versionSource?: 'user' | 'probe' | null;
  onPath?: boolean | null;
  resolvedPath?: string;
  wrapperPath?: string;
  wrapperTargetMissing?: boolean;
  wrapperCwd?: string;
  wrapperSemanticsUnknown?: boolean;
  pathRepaired?: boolean;
  declaredAt?: number | null;
  origin?: string | null;
  seenAt: number;
}

export interface EnvNote {
  text: string;
  seenAt: number;
  origin?: string | null;
}

export interface EnvStore {
  schema: 1;
  env: EnvIdentity;
  tools: Record<string, EnvTool>;
  absent: Record<string, { seenAt: number; expiresAt?: number; origin?: string | null; reason?: string; actualId?: string; actualVersion?: string | null }>;
  notes?: EnvNote[];
}

export interface RecallTool extends EnvTool {
  id: string;
  status: 'verified' | 'repaired' | 'unverified' | 'stale' | 'missing';
  ageDays: number;
  provides: string[];
  versionKnown: boolean;
  pathExists: boolean | null;
  verifiedAt: number | null;
  declaredAt: number | null;
  discoveryFailed: boolean;
  needsReconfirmation: boolean;
  foreign: boolean;
}

export interface RecallResult {
  env: EnvIdentity;
  envKey: string;
  records: number;
  tools: RecallTool[];
  absent: Array<{ id: string; seenAt: number; expiresAt?: number; ageDays: number; origin?: string | null; foreign: boolean; reason: string; expired: boolean; confidence: 'confirmed' | 'stale' | 'other-origin'; scope: string; hint?: string; actualId?: string; actualVersion?: string | null }>;
  notes: Array<EnvNote & { foreign: boolean }>;
}

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}(?:@[0-9]{1,3})?$/;
const VERSION_RE = /^[0-9A-Za-z._+()\-\t ]{1,64}$/;
const MAX_TOOLS = 64;
const TTL_DAYS = 30;
/** Docker probe records carry no file signature, so only their age bounds
 *  their truthfulness; a rebuilt image tag must not stay "verified" for a month. */
const DOCKER_TTL_DAYS = 7;

export function isToolId(value: string): boolean {
  return ID_RE.test(value);
}

function sanitize(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'default';
}

function userNamespace(): string {
  return sanitize(process.env.PI4CTF_USER_NS ?? os.userInfo().username.toLowerCase());
}

function homeDir(): string {
  return path.resolve(process.env.PI4CTF_HOME ?? path.join(os.homedir(), '.pi4ctf'));
}

export function envIdentity(ctx: EnvContext): EnvIdentity {
  const distro = process.env.WSL_DISTRO_NAME;
  return {
    backend: ctx.host.backend,
    platform: process.platform,
    arch: process.arch,
    ...(ctx.host.backend === 'host' && distro ? { wslDistro: distro } : {}),
  };
}

export function envKey(ctx: EnvContext): string {
  const identity = envIdentity(ctx);
  if (identity.backend === 'docker') {
    return `docker/${ctx.host.dockerImage ?? 'unknown'}`;
  }
  if (identity.wslDistro) {
    return `wsl/${identity.wslDistro}/${identity.platform}/${identity.arch}`;
  }
  return `host/${identity.platform}/${identity.arch}`;
}

export function storePath(ctx: EnvContext): string {
  const key = envKey(ctx);
  const file = `${sanitize(key)}~${sha256(key).slice(0, 8)}.json`;
  return path.join(homeDir(), 'envs', userNamespace(), file);
}

function emptyStore(ctx: EnvContext): EnvStore {
  return { schema: 1, env: envIdentity(ctx), tools: {}, absent: {}, notes: [] };
}

function normalizeToolFields(store: EnvStore): boolean {
  let changed = false;
  for (const tool of Object.values(store.tools)) {
    if (!tool.origin) { tool.origin = 'legacy'; changed = true; }
    if (!tool.pathSource) { tool.pathSource = tool.source; changed = true; }
    if (tool.versionSource === undefined) { tool.versionSource = tool.version ? tool.source : null; changed = true; }
    if (tool.onPath === undefined) { tool.onPath = tool.source === 'probe' ? true : null; changed = true; }
    if ((tool.source === 'user' || tool.versionSource === 'user') && tool.declaredAt === undefined) {
      tool.declaredAt = tool.seenAt;
      changed = true;
    }
  }
  return changed;
}

function normalizeAbsentFields(store: EnvStore): boolean {
  let changed = false;
  for (const entry of Object.values(store.absent)) {
    if (!entry.origin) { entry.origin = 'legacy'; changed = true; }
    if (entry.expiresAt === undefined) { entry.expiresAt = entry.seenAt + TTL_DAYS * 86_400_000; changed = true; }
  }
  for (const [id, entry] of Object.entries(store.absent)) {
    const base = id.split('@')[0] ?? id;
    const sameBase = Object.entries(store.tools).find(([key]) => key.split('@')[0] === base);
    if (!entry.reason) {
      if (id.includes('@') && sameBase) entry.reason = 'major-mismatch';
      else if (store.tools[id]?.realpath && fs.existsSync(store.tools[id].realpath)) entry.reason = 'not-on-path';
      else entry.reason = 'not-found';
      changed = true;
    }
    if (entry.reason === 'major-mismatch' && sameBase) {
      entry.actualId = sameBase[0];
      entry.actualVersion = sameBase[1].version;
      changed = true;
    }
  }
  return changed;
}

function reconcileToolAbsent(store: EnvStore): boolean {
  let changed = false;
  for (const [id, tool] of Object.entries(store.tools)) {
    if (tool.onPath === null && store.absent[id]) {
      tool.onPath = false;
      changed = true;
    }
  }
  return changed;
}

function dropUnversionedDuplicates(store: EnvStore): boolean {
  let changed = false;
  for (const [id, tool] of Object.entries(store.tools)) {
    if (id.includes('@')) continue;
    const duplicate = Object.entries(store.tools).find(([key, other]) =>
      key !== id && key.includes('@') && other.realpath === tool.realpath && other.version === tool.version,
    );
    if (duplicate) {
      delete store.tools[id];
      changed = true;
    }
  }
  return changed;
}

function dropAbsentShadowedByTools(store: EnvStore): boolean {
  let changed = false;
  for (const id of Object.keys(store.absent)) {
    const base = id.split('@')[0] ?? id;
    const hasFamily = id.includes('@')
      ? Boolean(store.tools[id])
      : Object.keys(store.tools).some((key) => key.split('@')[0] === base);
    if (hasFamily) { delete store.absent[id]; changed = true; }
  }
  return changed;
}

function normalizeStore(store: EnvStore): boolean {
  let changed = false;
  for (const normalize of [
    normalizeToolFields,
    normalizeAbsentFields,
    reconcileToolAbsent,
    dropUnversionedDuplicates,
    dropAbsentShadowedByTools,
  ]) {
    if (normalize(store)) changed = true;
  }
  return changed;
}

function isForeign(origin: string | null | undefined, currentOrigin: string): boolean {
  if (!origin || origin === 'legacy' || origin === 'env') return false;
  return origin !== currentOrigin;
}

export function loadStore(ctx: EnvContext): EnvStore {
  const file = storePath(ctx);
  if (!fs.existsSync(file)) return emptyStore(ctx);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as EnvStore;
    if (parsed.schema !== 1 || !parsed.tools || !parsed.absent) throw new Error('unsupported schema');
    const migrated = normalizeStore(parsed);
    const tools: EnvStore['tools'] = {};
    for (const [id, tool] of Object.entries(parsed.tools)) {
      if (!ID_RE.test(id) || !tool || typeof tool.path !== 'string' || typeof tool.realpath !== 'string') continue;
      if (tool.version !== null && (typeof tool.version !== 'string' || !VERSION_RE.test(tool.version))) continue;
      if (tool.source !== 'user' && tool.source !== 'probe') continue;
      if (!Number.isFinite(tool.seenAt)) continue;
      tools[id] = tool;
    }
    const absent: EnvStore['absent'] = {};
    for (const [id, value] of Object.entries(parsed.absent)) {
      if (ID_RE.test(id) && value && Number.isFinite(value.seenAt)) absent[id] = value;
    }
    const result = { ...parsed, tools, absent, notes: Array.isArray(parsed.notes) ? parsed.notes.filter((note): note is EnvNote => Boolean(note) && typeof note.text === 'string' && Number.isFinite(note.seenAt)).slice(0, 20) : [] };
    if (migrated) {
      try {
        const lock = FileLock.at(`${file}.lock`);
        lock.withLock(() => atomicWriteFile(file, JSON.stringify(result, null, 2)));
      } catch {
        // A read should still work if migration persistence is blocked.
      }
    }
    return result;
  } catch {
    try {
      fs.renameSync(file, `${file}.corrupt.${Date.now()}`);
    } catch {
      /* best effort */
    }
    return emptyStore(ctx);
  }
}

function updateStore(ctx: EnvContext, mutate: (store: EnvStore) => void): EnvStore {
  const file = storePath(ctx);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lock = FileLock.at(`${file}.lock`);
  return lock.withLock(() => {
    const store = loadStore(ctx);
    mutate(store);
    atomicWriteFile(file, JSON.stringify(store, null, 2));
    try {
      fs.chmodSync(file, 0o600);
    } catch {
      /* Windows may not enforce POSIX modes */
    }
    return store;
  });
}

function deleteAbsentMatching(store: EnvStore, id: string): void {
  for (const key of Object.keys(store.absent)) {
    if (key === id || key.startsWith(`${id}@`)) delete store.absent[key];
  }
}

function deleteMatching(store: EnvStore, id: string): void {
  for (const key of Object.keys(store.tools)) {
    if (key === id || key.startsWith(`${id}@`)) delete store.tools[key];
  }
  deleteAbsentMatching(store, id);
}

function pathOps(ctx: EnvContext): typeof path.posix {
  const identity = envIdentity(ctx);
  return identity.backend === 'host' && !identity.wslDistro ? path as unknown as typeof path.posix : path.posix;
}

function validatePath(ctx: EnvContext, file: string): string {
  const ops = pathOps(ctx);
  if (!ops.isAbsolute(file)) throw new KernelError('INVALID_REQUEST', 'tool path must be absolute');
  if (/[\0\r\n]/.test(file)) throw new KernelError('INVALID_REQUEST', 'tool path contains control characters');
  return ops.normalize(file);
}

function insideAny(file: string, roots: string[]): boolean {
  return roots.some((root) => {
    const rel = path.relative(path.resolve(root), path.resolve(file));
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
}

function assertExternalPath(ctx: EnvContext, file: string): void {
  if (ctx.host.backend !== 'host') return;
  const roots = [ctx.protectedRoot, os.tmpdir(), homeDir()];
  if (insideAny(file, roots)) {
    throw new KernelError('INVALID_REQUEST', 'tool path must be outside the challenge, temp, and env-memory directories');
  }
}

function validateJavaHome(ctx: EnvContext, javaHome: string, toolPath: string): string {
  const home = validatePath(ctx, javaHome);
  const rel = pathOps(ctx).relative(home, toolPath);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new KernelError('INVALID_REQUEST', 'JAVA_HOME must be an ancestor of the tool path');
  }
  return home;
}

function validateRecord(ctx: EnvContext, input: {
  id: string;
  path: string;
  version?: string | null;
  env?: { JAVA_HOME?: string };
  source: 'user' | 'probe';
  sig?: ToolSig | null;
}): EnvTool {
  if (!ID_RE.test(input.id)) throw new KernelError('INVALID_REQUEST', 'invalid tool id');
  const toolPath = validatePath(ctx, input.path);
  assertExternalPath(ctx, toolPath);
  if (input.version !== undefined && input.version !== null && !VERSION_RE.test(input.version)) {
    throw new KernelError('INVALID_REQUEST', 'invalid tool version');
  }
  const env: EnvTool['env'] = {};
  if (input.env?.JAVA_HOME) env.JAVA_HOME = validateJavaHome(ctx, input.env.JAVA_HOME, toolPath);
  const identity = envIdentity(ctx);
  let realpath = toolPath;
  if (identity.backend === 'host') {
    try {
      realpath = fs.realpathSync(toolPath);
    } catch {
      // A user may teach a path before installing it; keep the declared path.
    }
    assertExternalPath(ctx, realpath);
  }
  return {
    path: toolPath,
    realpath,
    version: input.version ?? null,
    ...(Object.keys(env).length ? { env } : {}),
    sig: input.sig ?? null,
    source: input.source,
    pathSource: input.source,
    versionSource: input.version ? input.source : null,
    onPath: input.source === 'probe' ? true : null,
    declaredAt: input.source === 'user' ? Date.now() : undefined,
    origin: ctx.origin,
    seenAt: Date.now(),
  };
}

function ageDays(seenAt: number): number {
  return Math.max(0, Math.round((Date.now() - seenAt) / 86_400_000));
}

function deriveStatus(ctx: EnvContext, tool: EnvTool): RecallTool['status'] {
  const identity = envIdentity(ctx);
  if (tool.onPath === false && tool.source === 'user') return 'unverified';
  if (tool.wrapperTargetMissing || tool.pathRepaired) return 'repaired';
  if (identity.backend === 'host') {
    try {
      const st = fs.statSync(tool.realpath);
      if (tool.sig && (tool.sig.size !== st.size || tool.sig.mtimeMs !== st.mtimeMs)) return 'stale';
    } catch {
      return 'missing';
    }
  }
  if (tool.source === 'user' && !tool.sig) return 'unverified';
  if (tool.source === 'probe' && identity.backend === 'host' && !tool.sig) return 'stale';
  const ttlDays = identity.backend === 'host' ? TTL_DAYS : DOCKER_TTL_DAYS;
  if (ageDays(tool.seenAt) > ttlDays) return 'stale';
  return 'verified';
}

export interface RecallQuery {
  id?: string;
  ids?: string[];
  capability?: string;
  origin?: string;
}

export function recall(ctx: EnvContext, query?: RecallQuery): RecallResult {
  const store = loadStore(ctx);
  const capability = query?.capability;
  const currentOrigin = ctx.origin;
  const absentIds = new Set(Object.keys(store.absent));
  const deduped = new Map<string, RecallTool>();
  for (const [id, tool] of Object.entries(store.tools)) {
    if (query?.id && id !== query.id && !id.startsWith(`${query.id}@`)) continue;
    if (query?.ids && !query.ids.includes(id)) continue;
    if (query?.origin && tool.origin !== query.origin) continue;
    if (capability && !matchesCapability(id, capability)) continue;
    const pathExists = ctx.host.backend === 'host' ? fs.existsSync(tool.realpath) : null;
    const record: RecallTool = {
      ...tool,
      id,
      status: deriveStatus(ctx, tool),
      ageDays: ageDays(tool.seenAt),
      provides: providesFor(id),
      versionKnown: tool.version !== null,
      pathExists,
      verifiedAt: tool.source === 'probe' ? tool.seenAt : null,
      declaredAt: tool.declaredAt ?? (tool.source === 'user' ? tool.seenAt : null),
      discoveryFailed: absentIds.has(id) || absentIds.has(id.split('@')[0] ?? id),
      needsReconfirmation: Boolean(tool.pathRepaired || tool.wrapperTargetMissing || (tool.source === 'user' && tool.onPath === false) || absentIds.has(id) || absentIds.has(id.split('@')[0] ?? id)),
      foreign: isForeign(tool.origin, currentOrigin),
    };
    if (record.discoveryFailed && record.onPath === null) record.onPath = false;
    const key = `${record.path}\0${record.version ?? ''}`;
    const prior = deduped.get(key);
    const rank = (value: RecallTool) => (value.source === 'probe' ? 2 : 0) + (value.status === 'verified' ? 2 : value.status === 'repaired' ? 1 : value.status === 'unverified' ? 0 : -1);
    if (!prior || rank(record) > rank(prior)) deduped.set(key, record);
  }
  const tools = [...deduped.values()];
  const absent = Object.entries(store.absent)
    .filter(([id, value]) => (!query?.id || id === query.id || id.startsWith(`${query.id}@`)) && (!query?.ids || query.ids.includes(id)) && (!query?.origin || value.origin === query.origin) && !store.tools[id] && (id.includes('@') || !Object.keys(store.tools).some((key) => key.split('@')[0] === id)) && (!capability || matchesCapability(id, capability)))
    .map(([id, value]) => {
      const related = tools.find((tool) => tool.id === id || tool.id.split('@')[0] === id);
      const expiresAt = Math.min(
        value.expiresAt ?? Number.POSITIVE_INFINITY,
        value.seenAt + TTL_DAYS * 86_400_000,
      );
      const expired = Date.now() > expiresAt;
      const foreign = isForeign(value.origin, currentOrigin);
      const note = (store.notes ?? []).find((value) => value.text.toLowerCase().includes(id.toLowerCase()));
      const sentence = note?.text.split(/[;；。]|[,，]\s*|\.\s+/).find((part) => part.toLowerCase().includes(id.toLowerCase())) ?? note?.text;
      const hint = sentence?.trim();
      return {
        id,
        seenAt: value.seenAt,
        expiresAt,
        ageDays: ageDays(value.seenAt),
        origin: value.origin ?? null,
        foreign,
        reason: value.reason ?? (related ? (related.onPath === true ? 'absent-after-probe' : 'not-on-path') : 'not-found'),
        confidence: (expired ? 'stale' : foreign ? 'other-origin' : 'confirmed') as 'stale' | 'other-origin' | 'confirmed',
        scope: envKey(ctx),
        ...(hint ? { hint: hint.slice(0, 120) } : {}),
        actualId: value.actualId,
        actualVersion: value.actualVersion,
        expired,
      };
    });
  return { env: store.env, envKey: envKey(ctx), records: Object.keys(store.tools).length, tools, absent, notes: (store.notes ?? []).filter((note) => !query?.origin || note.origin === query.origin).map((note) => ({ ...note, foreign: isForeign(note.origin, currentOrigin) })) };
}

function mergeAlias(store: EnvStore, id: string, tool: EnvTool): boolean {
  for (const [key, existing] of Object.entries(store.tools)) {
    if (key === id) continue;
    if (existing.realpath !== tool.realpath || existing.version !== tool.version) continue;
    if (id.includes('@') && !key.includes('@')) {
      delete store.tools[key];
      return true;
    }
    if (!id.includes('@') && key.includes('@')) return false;
  }
  return true;
}

export function remember(ctx: EnvContext, input: {
  id: string;
  path: string;
  version?: string | null;
  env?: { JAVA_HOME?: string };
}): EnvTool {
  const tool = validateRecord(ctx, { ...input, source: 'user' });
  updateStore(ctx, (store) => {
    if (!store.tools[input.id] && Object.keys(store.tools).length >= MAX_TOOLS) {
      throw new KernelError('LIMIT', `environment memory limit reached (${MAX_TOOLS})`);
    }
    delete store.absent[input.id];
    delete store.absent[input.id.split('@')[0] ?? input.id];
    if (mergeAlias(store, input.id, tool)) store.tools[input.id] = tool;
  });
  return tool;
}

export function forget(ctx: EnvContext, id: string): boolean {
  let existed = false;
  updateStore(ctx, (store) => {
    existed = Object.keys(store.tools).some((key) => key === id || key.startsWith(`${id}@`)) ||
      Object.keys(store.absent).some((key) => key === id || key.startsWith(`${id}@`));
    deleteMatching(store, id);
  });
  return existed;
}

export function recordProbe(ctx: EnvContext, id: string, tool: Omit<EnvTool, 'source' | 'seenAt'>): EnvTool {
  let stored: EnvTool;
  updateStore(ctx, (store) => {
    delete store.absent[id];
    delete store.absent[id.split('@')[0] ?? id];
    const previous = store.tools[id];
    stored = {
      ...tool,
      version: tool.version ?? previous?.version ?? null,
      source: 'probe',
      pathSource: 'probe',
      versionSource: tool.version ? 'probe' : previous?.versionSource ?? (previous?.version ? previous.source : null),
      onPath: tool.onPath ?? true,
      declaredAt: previous?.declaredAt ?? (previous?.versionSource === 'user' ? previous.seenAt : undefined),
      origin: ctx.origin,
      seenAt: Date.now(),
    };
    if (mergeAlias(store, id, stored)) store.tools[id] = stored;
  });
  return stored!;
}

export function recordAbsent(ctx: EnvContext, id: string, reason?: string, actual?: { id: string; version?: string | null }): void {
  // A probe miss is evidence that discovery failed, not proof that a known
  // tool was removed. Keep the record; forget is the destructive operation.
  updateStore(ctx, (store) => {
    const base = id.split('@')[0] ?? id;
    const exact = store.tools[id];
    if (exact) {
      exact.onPath = false;
      delete store.absent[id];
      return;
    }
    if (!id.includes('@') && Object.keys(store.tools).some((key) => key.split('@')[0] === base)) return;
    const related = Object.keys(store.tools).some((key) => key === id || key.split('@')[0] === base);
    const defaultReason = related ? (id.includes('@') && !store.tools[id] ? 'major-mismatch' : 'not-on-path') : 'not-found';
    store.absent[id] = {
      seenAt: Date.now(),
      expiresAt: Date.now() + TTL_DAYS * 86_400_000,
      origin: ctx.origin,
      reason: reason ?? defaultReason,
      ...(actual ? { actualId: actual.id, actualVersion: actual.version ?? null } : {}),
    };
    for (const [key, tool] of Object.entries(store.tools)) {
      if (key === id) tool.onPath = false;
    }
  });
}

export interface NoteWrite {
  note: EnvNote;
  redacted: boolean;
}

export function recordNote(ctx: EnvContext, text: string): NoteWrite {
  const clean = text.replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 512);
  if (!clean) throw new KernelError('INVALID_REQUEST', 'note text is empty');
  const { text: safe, redacted } = redactSecrets(clean);
  const stored: EnvNote = { text: safe, seenAt: Date.now(), origin: ctx.origin };
  updateStore(ctx, (store) => {
    const notes = store.notes ?? [];
    if (!notes.some((note) => note.text === safe)) notes.push(stored);
    store.notes = notes.slice(-20);
  });
  return { note: stored, redacted };
}

export function doctorTools(ctx: EnvContext): Record<string, boolean> {
  const store = loadStore(ctx);
  return Object.fromEntries(Object.entries(store.tools).map(([id, tool]) => [id, deriveStatus(ctx, tool) === 'verified']));
}
