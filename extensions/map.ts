/**
 * Human-only `/ctf map` control panel.
 *
 * Observes the current route state and lets the human steer it. Model tools
 * remain available separately; this module is not registered as a tool.
 */
import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { callRt } from "./shared.js";

interface MapClaim {
  id: string;
  state: string;
  claimType: string;
  text: string;
  refs?: string[];
}

interface MapNegative {
  id?: string;
  signature: string;
  failureClass: string;
  family?: string;
  transient: boolean;
  blockScope: string;
  expiresAt: number | null;
  unblockedAt?: number | null;
}

interface MapRecent {
  id: string;
  intentClass: string;
  exit: number | null;
  processFailure: string | null;
  target?: string | null;
}

interface MapData {
  status: {
    id?: string;
    status?: string;
    target?: { host?: string; port?: number; instanceId?: string } | null;
    counters?: Record<string, number>;
    flagAccepted?: boolean;
  };
  plan: { chain: string[]; next: string; preconditions: string[] };
  claims: MapClaim[];
  negatives: MapNegative[];
  recent: MapRecent[];
}

function isMapData(value: unknown): value is MapData {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  if (!('status' in value) || typeof value.status !== 'object' || value.status === null) return false;
  if (!('plan' in value) || typeof value.plan !== 'object' || value.plan === null) return false;
  if (!('claims' in value) || !Array.isArray(value.claims)) return false;
  if (!('negatives' in value) || !Array.isArray(value.negatives)) return false;
  if (!('recent' in value) || !Array.isArray(value.recent)) return false;
  const plan = value.plan;
  return 'next' in plan
    && typeof plan.next === 'string'
    && 'chain' in plan
    && Array.isArray(plan.chain)
    && 'preconditions' in plan
    && Array.isArray(plan.preconditions);
}

async function loadMap(root: string): Promise<MapData> {
  const res = await callRt("case.map", root, {});
  if (!res.ok) throw new Error(`case.map failed [${res.error?.code}]: ${res.error?.message}`);
  if (!isMapData(res.data)) throw new Error("case.map returned invalid data");
  return res.data;
}

function txTarget(data: MapData): string {
  const t = data.status.target;
  if (!t) return "(none)";
  return `${t.host ?? '?'}${t.port ? `:${t.port}` : ''}${t.instanceId ? ` #${t.instanceId}` : ''}`;
}

function summary(data: MapData): string {
  const counters = data.status.counters ?? {};
  const soft = data.negatives.filter((n) => n.transient && !n.unblockedAt);
  const hard = data.negatives.filter((n) => !n.transient);
  const lines = [
    `CASE ${data.status.id ?? '?'} [${data.status.status ?? '?'}] target=${txTarget(data)} flag=${data.status.flagAccepted ? 'accepted' : 'not accepted'}`,
    `BUDGET commands=${counters.command ?? 0}/30 restarts=${counters.restart ?? 0} continues=${counters.continue ?? 0}`,
    '',
    `PLAN next: ${data.plan.next || '(none)'}`,
    ...(data.plan.chain.length ? [`     chain: ${data.plan.chain.join(' -> ')}`] : []),
    ...(data.plan.preconditions.length ? [`     preconditions: ${data.plan.preconditions.join('; ')}`] : []),
    '',
    `OPEN CLAIMS (${data.claims.length})`,
    ...(data.claims.length
      ? data.claims.slice(0, 5).map((c) => `- ${c.id} [${c.state}] ${c.claimType}: ${c.text.slice(0, 80)}`)
      : ['- (none)']),
    '',
    `NEGATIVE soft=${soft.length} hard=${hard.length}`,
    ...(soft.slice(0, 4).map((n) => `- SOFT ${n.id ?? '?'} ${n.failureClass} ${n.signature.slice(0, 72)}`)),
    ...(hard.slice(0, 2).map((n) => `- HARD ${n.id ?? '?'} ${n.failureClass} ${n.signature.slice(0, 72)}`)),
    '',
    `RECENT (${data.recent.length})`,
    ...(data.recent.length
      ? data.recent.slice(0, 5).map((o) => `- ${o.id} ${o.intentClass} exit=${o.exit} failure=${o.processFailure ?? 'null'}`)
      : ['- (none)']),
  ];
  return lines.join('\n');
}

export async function ctfMap(ctx: ExtensionCommandContext, root: string): Promise<void> {
  while (true) {
    let data: MapData;
    try {
      data = await loadMap(root);
    } catch (err) {
      ctx.ui.notify(String(err), "error");
      return;
    }

    const choice = await ctx.ui.select(summary(data), [
      "Set plan",
      "Clear soft negative",
      "Handoff",
      "Refresh",
      "Exit",
    ]);
    if (!choice || choice === "Exit") return;

    if (choice === "Set plan") {
      const next = await ctx.ui.editor("Set next action", data.plan.next);
      if (next === undefined) continue;
      const res = await callRt("case.plan", root, {
        chain: data.plan.chain,
        next,
        preconditions: data.plan.preconditions,
      });
      ctx.ui.notify(
        res.ok ? "plan updated" : `case.plan failed [${res.error?.code}]: ${res.error?.message}`,
        res.ok ? "info" : "error",
      );
      continue;
    }

    if (choice === "Clear soft negative") {
      const soft = data.negatives.filter((n) => n.transient && !n.unblockedAt && n.id);
      if (soft.length === 0) {
        ctx.ui.notify("no live soft negative entries", "info");
        continue;
      }
      const labels = soft.map((n) => `${n.id} ${n.failureClass} ${n.signature.slice(0, 72)}`);
      const selected = await ctx.ui.select("Clear soft negative", [...labels, "Cancel"]);
      if (!selected || selected === "Cancel") continue;
      const index = labels.indexOf(selected);
      const target = soft[index];
      if (!target?.id) continue;
      const res = await callRt("case.clearNegatives", root, { id: target.id });
      ctx.ui.notify(
        res.ok ? `cleared ${target.id}` : `clear failed [${res.error?.code}]: ${res.error?.message}`,
        res.ok ? "info" : "error",
      );
      continue;
    }

    if (choice === "Handoff") {
      const res = await callRt("case.handoff", root, {});
      ctx.ui.notify(
        res.ok ? "handoff written" : `handoff failed [${res.error?.code}]: ${res.error?.message}`,
        res.ok ? "info" : "error",
      );
    }
  }
}
