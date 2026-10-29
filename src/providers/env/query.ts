/** Budgeted record projection for `env_memory recall` tool responses. */
import { recall, type RecallQuery, type RecallResult, type RecallTool } from './store.js';
import type { EnvContext } from './context.js';

export interface ProjectedTool {
  id: string;
  path: string;
  version: string | null;
  status: RecallTool['status'];
  source: RecallTool['source'];
  onPath: boolean | null | undefined;
  ageDays: number;
  flags?: string[];
  wrapperCwd?: string;
}

export interface ProjectedAbsent {
  id: string;
  ageDays: number;
  reason: string;
  expired: boolean;
  confidence: RecallResult['absent'][number]['confidence'];
  scope: string;
  hint?: string;
  origin?: string;
  actualId?: string;
  actualVersion?: string | null;
}

export interface UnverifiedUserGroup {
  base: string;
  ids: string[];
  count: number;
}

export interface RecordsTruncation {
  truncated: true;
  omitted: number;
  truncation: { tools: number; notes: number; absent: number };
  omittedIds?: string[];
  trimmedNotes?: number;
  trimmedAbsent?: number;
}

export interface RecordsProjection extends Partial<RecordsTruncation> {
  env: RecallResult['env'];
  envKey: string;
  records: number;
  tools: ProjectedTool[];
  absent: ProjectedAbsent[];
  notes: RecallResult['notes'];
  unverifiedUser?: UnverifiedUserGroup[];
}

/** Higher = more urgent; problem tools sort first so trimming drops healthy noise last. */
function urgency(tool: RecallTool): number {
  if (tool.status === 'missing') return 4;
  if (tool.status === 'stale' || tool.status === 'repaired') return 3;
  if (tool.status === 'unverified' || tool.needsReconfirmation) return 2;
  return 1;
}

/**
 * Compact record view. Unfiltered views fold repeated unverified user
 * declarations into groups; the payload is then trimmed — low-confidence
 * tools, notes, absent entries, then any tool — until it fits `maxChars`.
 */
export function projectRecords(ctx: EnvContext, query: RecallQuery, maxChars: number): RecordsProjection {
  const result = recall(ctx, query);
  const filtered = query.id !== undefined || query.ids !== undefined || query.capability !== undefined || query.origin !== undefined;

  let notes = result.notes;
  if (filtered) {
    const terms = [query.id, ...(query.ids ?? []), query.capability]
      .filter((term): term is string => Boolean(term))
      .map((term) => term.toLowerCase());
    const matching = notes.filter((note) => terms.some((term) => note.text.toLowerCase().includes(term)));
    notes = (matching.length > 0 ? matching : notes).slice(0, 2);
  }

  const sortedTools = [...result.tools].sort((a, b) => urgency(b) - urgency(a) || b.ageDays - a.ageDays || a.id.localeCompare(b.id));
  const unverifiedUser = new Map<string, string[]>();
  if (!filtered) {
    for (const tool of sortedTools) {
      if (tool.status !== 'unverified' || tool.source !== 'user') continue;
      const base = tool.id.split('@')[0] ?? tool.id;
      const ids = unverifiedUser.get(base) ?? [];
      ids.push(tool.id);
      unverifiedUser.set(base, ids);
    }
  }
  const unverifiedUserGroups: UnverifiedUserGroup[] = [...unverifiedUser.entries()]
    .filter(([, ids]) => ids.length >= 2)
    .map(([base, ids]) => ({ base, ids, count: ids.length }));
  const foldedIds = new Set(unverifiedUserGroups.flatMap((group) => group.ids));

  const tools: ProjectedTool[] = sortedTools.filter((tool) => !foldedIds.has(tool.id)).map((tool) => {
    const flags = [
      tool.onPath === false ? 'offpath' : null,
      tool.wrapperTargetMissing || tool.pathRepaired ? 'wrapper-broken' : null,
      tool.needsReconfirmation && !tool.wrapperTargetMissing && !tool.pathRepaired ? 'reconfirm' : null,
      tool.version === null ? 'version-unknown' : null,
      tool.foreign ? 'foreign' : null,
    ].filter((flag): flag is string => Boolean(flag));
    return {
      id: tool.id,
      path: tool.path,
      version: tool.version,
      status: tool.status,
      source: tool.source,
      onPath: tool.onPath,
      ageDays: tool.ageDays,
      ...(flags.length ? { flags } : {}),
      ...(tool.wrapperCwd ? { wrapperCwd: tool.wrapperCwd } : {}),
    };
  });
  const absent: ProjectedAbsent[] = result.absent.map((item) => ({
    id: item.id,
    ageDays: item.ageDays,
    reason: item.reason,
    expired: item.expired,
    confidence: item.confidence,
    scope: item.scope,
    ...(item.hint ? { hint: item.hint } : {}),
    ...(item.origin ? { origin: item.origin } : {}),
    ...(item.actualId ? { actualId: item.actualId, actualVersion: item.actualVersion ?? null } : {}),
  }));

  const omittedIds: string[] = [];
  let trimmedNotes = 0;
  let trimmedAbsent = 0;
  while (JSON.stringify({ tools, absent, notes, unverifiedUser: unverifiedUserGroups }).length > maxChars) {
    const low = tools.findLastIndex((tool) => tool.status === 'unverified' || tool.status === 'stale');
    if (low >= 0) omittedIds.push(tools.splice(low, 1)[0]!.id);
    else if (notes.length > 0) { notes.pop(); trimmedNotes++; }
    else if (absent.length > 0) { absent.pop(); trimmedAbsent++; }
    else if (tools.length > 0) omittedIds.push(tools.pop()!.id);
    else break;
  }
  const omitted = omittedIds.length;

  return {
    env: result.env,
    envKey: result.envKey,
    records: result.records,
    tools,
    absent,
    notes,
    ...(unverifiedUserGroups.length ? { unverifiedUser: unverifiedUserGroups } : {}),
    ...(omitted || trimmedNotes || trimmedAbsent
      ? {
          truncated: true as const,
          omitted,
          truncation: { tools: omitted, notes: trimmedNotes, absent: trimmedAbsent },
          ...(omitted ? { omittedIds: omittedIds.slice(0, 8) } : {}),
          ...(trimmedNotes ? { trimmedNotes } : {}),
          ...(trimmedAbsent ? { trimmedAbsent } : {}),
        }
      : {}),
  };
}
