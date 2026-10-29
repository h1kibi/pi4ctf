/** Bounded, path-free environment summary for the prompt. */
import { recall, type RecallTool } from './store.js';
import type { EnvContext } from './context.js';
import { CAPABILITY_GROUPS } from './table.js';

const MAX_CHARS = 700;
const RULE = 'rule: recall before use; probe user records; actual output wins over memory.';
type CapabilityPolicy = {
  key: string;
  limit: number;
  matchRank: number;
  dropRank: number;
  tools: string[];
  aliases: string[];
};

// One table owns category order, display priority, cap, and drop order.
const CAPABILITY_POLICY: CapabilityPolicy[] = [
  { key: 'pwn', matchRank: 0, limit: 3, dropRank: 7, tools: CAPABILITY_GROUPS.pwn ?? [], aliases: ['pwn', 'debugger'] },
  { key: 'reverse', matchRank: 1, limit: 3, dropRank: 6, tools: CAPABILITY_GROUPS.reverse ?? [], aliases: ['reverse', 'reverse-engineering', 'decompiler'] },
  { key: 'web', matchRank: 2, limit: 3, dropRank: 5, tools: CAPABILITY_GROUPS.web ?? [], aliases: ['web'] },
  { key: 'net', matchRank: 3, limit: 2, dropRank: 1, tools: CAPABILITY_GROUPS.net ?? [], aliases: ['net'] },
  { key: 'crypto', matchRank: 4, limit: 2, dropRank: 2, tools: CAPABILITY_GROUPS.crypto ?? [], aliases: ['crypto'] },
  { key: 'forensics', matchRank: 5, limit: 3, dropRank: 4, tools: CAPABILITY_GROUPS.forensics ?? [], aliases: ['forensics', 'pcap', 'metadata'] },
  { key: 'java', matchRank: 7, limit: 2, dropRank: 3, tools: CAPABILITY_GROUPS.java ?? [], aliases: ['java', 'java-runtime', 'javac', 'jar'] },
  { key: 'android', matchRank: 6, limit: 3, dropRank: 0, tools: CAPABILITY_GROUPS.android ?? [], aliases: ['android'] },
  { key: 'misc', matchRank: 8, limit: 4, dropRank: 8, tools: CAPABILITY_GROUPS.misc ?? [], aliases: [] },
];
const CATEGORIES = CAPABILITY_POLICY.map((policy) => policy.key);
const CAP_DROP_ORDER = [...CAPABILITY_POLICY].sort((a, b) => a.dropRank - b.dropRank).map((policy) => policy.key);
const POLICY = new Map(CAPABILITY_POLICY.map((policy) => [policy.key, policy] as const));
const MATCH_ORDER = [...CAPABILITY_POLICY].sort((a, b) => a.matchRank - b.matchRank);

function oneLine(value: string): string {
  return value.replace(/[\r\n]/g, ' ').slice(0, 80);
}

function noteText(value: string): string {
  const text = value.replace(/[\r\n]+/g, ' ').trim();
  return text.length > 120 ? `${text.slice(0, 119)}...` : text;
}

function severity(tool: RecallTool): number {
  if (tool.status === 'missing') return 0;
  if (tool.status === 'repaired') return 1;
  if (tool.status === 'stale') return 2;
  if (tool.status === 'unverified') return 3;
  return 4;
}

function categoryForNames(names: Set<string>): string {
  for (const policy of MATCH_ORDER) {
    if (policy.aliases.some((name) => names.has(name)) || policy.tools.some((name) => names.has(name))) return policy.key;
    if (policy.key === 'java' && [...names].some((name) => name.startsWith('jdk@'))) return 'java';
  }
  return 'misc';
}

function categoryOf(tool: RecallTool): string {
  return categoryForNames(new Set([tool.id, ...tool.provides]));
}

function toolLine(tool: RecallTool): string {
  const markers = [
    tool.onPath === false ? 'offpath' : null,
    tool.wrapperTargetMissing || tool.pathRepaired ? 'wrapper-broken' : null,
    tool.needsReconfirmation && !tool.wrapperTargetMissing && !tool.pathRepaired ? 'reconfirm' : null,
    tool.version === null ? 'version-unknown' : null,
  ].filter((marker): marker is string => Boolean(marker));
  const suffix = markers.length ? ` [${markers.join(', ')}]` : '';
  return `- ${oneLine(tool.id)}: ${oneLine(tool.version ?? '?')} (${tool.source}, ${tool.ageDays}d, ${tool.status})${suffix}`;
}

export function envSummary(ctx: EnvContext): string {
  const result = recall(ctx);
  const anomalies = result.tools
    .filter((tool) => tool.status !== 'verified' || tool.needsReconfirmation || tool.discoveryFailed)
    .sort((a, b) => severity(a) - severity(b) || b.ageDays - a.ageDays);
  const offPath = result.absent.filter((item) => item.reason === 'not-on-path');
  const mismatch = result.absent.filter((item) => item.reason === 'major-mismatch');
  const notFound = result.absent.filter((item) => item.reason !== 'not-on-path' && item.reason !== 'major-mismatch');
  const recordNote = result.records !== result.tools.length ? ` (${result.records} records)` : '';
  const lines = [
    `## Environment memory (${oneLine(result.envKey)})`,
    `- ${RULE}`,
    `- known: ${result.tools.length} tools${recordNote}, ${notFound.length} absent, ${offPath.length} offpath, ${mismatch.length} mismatch`,
  ];
  const add = (line: string) => {
    if (lines.join('\n').length + line.length + 1 <= MAX_CHARS) {
      lines.push(line);
      return true;
    }
    return false;
  };

  const caps = new Map<string, string[]>();
  const affected = new Set<string>();
  for (const tool of anomalies) affected.add(categoryOf(tool));
  for (const item of [...mismatch, ...offPath]) {
    affected.add(categoryForNames(new Set([item.id, item.actualId ?? ''])));
  }
  const candidates = new Map<string, string[]>();
  for (const tool of result.tools) {
    if (tool.status !== 'verified' && tool.status !== 'repaired') continue;
    const category = categoryOf(tool);
    const marker = tool.status === 'repaired' && (tool.wrapperTargetMissing || tool.pathRepaired) ? ':wrapper-broken' : '';
    const wrapper = tool.status !== 'repaired' && (tool.wrapperPath || tool.wrapperCwd) ? '*' : '';
    const label = tool.status === 'repaired' ? `${tool.id}(repaired${marker})` : `${tool.id}${wrapper}`;
    const ids = candidates.get(category) ?? [];
    if (!ids.includes(label)) ids.push(label);
    candidates.set(category, ids);
  }
  for (const [category, ids] of candidates) {
    const priority = POLICY.get(category)?.tools ?? [];
    ids.sort((a, b) => {
      const ai = priority.findIndex((name) => a === name || a.startsWith(`${name}(`) || a.startsWith(`${name}*`));
      const bi = priority.findIndex((name) => b === name || b.startsWith(`${name}(`) || b.startsWith(`${name}*`));
      return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi) || a.localeCompare(b);
    });
    caps.set(category, ids.slice(0, POLICY.get(category)?.limit ?? 3));
  }
  const orderedCategories = [...CATEGORIES].sort((a, b) =>
    Number(affected.has(b)) - Number(affected.has(a)) || CATEGORIES.indexOf(a) - CATEGORIES.indexOf(b),
  );
  const capLine = orderedCategories
    .filter((category) => (caps.get(category) ?? []).length > 0)
    .slice(0, 9)
    .map((category) => `${category}: ${(caps.get(category) ?? []).join(', ')}`)
    .join(' | ');
  if (capLine) {
    let active = capLine.split(' | ');
    while (active.length > 0) {
      if (add(`- capabilities: ${active.join(' | ')}`)) break;
      const drop = CAP_DROP_ORDER.find((category) => active.some((part) => part.startsWith(`${category}:`)));
      if (!drop) break;
      active = active.filter((part) => !part.startsWith(`${drop}:`));
    }
  }

  if (mismatch.length) {
    const groups = new Map<string, typeof mismatch>();
    for (const item of mismatch) {
      const key = item.actualId ?? 'unknown';
      const items = groups.get(key) ?? [];
      items.push(item);
      groups.set(key, items);
    }
    const mismatchText = [...groups.entries()].slice(0, 4).map(([actualId, items]) => {
      const ids = items.slice(0, 6).map((item) => `${oneLine(item.id)}${item.expired ? ':expired' : ''}`).join(', ');
      const suffix = items.length > 6 ? `, +${items.length - 6}` : '';
      const version = items[0]?.actualVersion ? ` ${oneLine(items[0].actualVersion)}` : '';
      return `${ids}${suffix} -> have ${oneLine(actualId)}${version}`;
    }).join('; ');
    if (mismatchText) add(`- version-mismatch: ${mismatchText}`);
  }
  const formatAbsent = (items: typeof result.absent) =>
    items.slice(0, 4).map((item) => {
      const hint = item.hint && /wsl|docker|backend|cross/i.test(item.hint) ? '(cross-backend)' : '';
      return `${oneLine(item.id)}${hint}${item.expired ? ':expired' : ''}`;
    }).join(', ') + (items.length > 4 ? `, +${items.length - 4}` : '');
  if (notFound.length) add(`- absent: ${formatAbsent(notFound)}`);
  const notes = result.notes
    .slice()
    .sort((a, b) => Number(/gpu|driver|opencl|hashcat|cuda|rocm/i.test(b.text)) - Number(/gpu|driver|opencl|hashcat|cuda|rocm/i.test(a.text)))
    .slice(0, 1)
    .map((note) => noteText(note.text));
  if (notes.length) add(`- notes: ${notes.join('; ')}`);
  const unverifiedUser = new Map<string, RecallTool[]>();
  for (const tool of anomalies) {
    if (tool.status !== 'unverified' || tool.source !== 'user') continue;
    const base = tool.id.split('@')[0] ?? tool.id;
    const group = unverifiedUser.get(base) ?? [];
    group.push(tool);
    unverifiedUser.set(base, group);
  }
  const collapsedUnverified = new Set<string>();
  for (const group of unverifiedUser.values()) {
    if (group.length < 2) continue;
    const ids = group.slice(0, 6).map((tool) => tool.id).join(', ');
    const suffix = group.length > 6 ? `, +${group.length - 6}` : '';
    if (add(`- unverified-user: ${ids}${suffix} (${group.length})`)) {
      for (const tool of group) collapsedUnverified.add(tool.id);
    }
  }
  const stale = anomalies.filter((tool) => tool.status === 'stale');
  if (stale.length) {
    const shown = stale.slice(0, 6).map((tool) => `${oneLine(tool.id)}(${tool.ageDays}d)`);
    const suffix = stale.length > 6 ? `, +${stale.length - 6}` : '';
    add(`- stale: ${shown.join(', ')}${suffix}`);
  }
  const anomalyGroups = new Map<string, RecallTool[]>();
  for (const tool of anomalies.slice(0, 12)) {
    if (tool.status === 'repaired' && capLine.includes(`${tool.id}(repaired`)) continue;
    if (tool.status === 'stale' || collapsedUnverified.has(tool.id)) continue;
    const key = `${tool.version ?? ''}|${tool.source}|${tool.status}|${tool.ageDays}|${tool.onPath}|${tool.wrapperTargetMissing}|${tool.pathRepaired}|${tool.needsReconfirmation}`;
    const group = anomalyGroups.get(key) ?? [];
    group.push(tool);
    anomalyGroups.set(key, group);
  }
  for (const group of anomalyGroups.values()) {
    if (group.length === 1) {
      if (!add(toolLine(group[0]!))) break;
      continue;
    }
    const first = group[0]!;
    const line = toolLine({ ...first, id: group.slice(0, 4).map((tool) => tool.id).join(', ') });
    if (!add(line)) break;
  }
  if (lines.length === 3) lines.push('- no tools recorded');
  return lines.join('\n');
}
