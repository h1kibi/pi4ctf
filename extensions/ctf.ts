/**
 * pi4ctf — pi extension.
 *
 * Exposes the four verbs (run/session/claim/flag) as pi tools, injects the
 * kernel packet before user runs, and provides /ctf case commands.
 *
 * The kernel stays outside pi: this extension only translates tool calls to
 * the JSON protocol of dist/rt.js. It never writes .ctf/ state itself.
 */
import * as fs from "node:fs";
import * as path from "node:path";

import {
  DEFAULT_FLAG_FORMAT,
  hasProject,
  oracleLooksValid,
  scanChallenge,
} from "../dist/adapter/autoinit.js";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import {
  seenOutcomesByRoot, lastInjectedByRoot, PREFLIGHT_DONE, activeProjectFile, isCaseContainer,
  callRt, ensureAutoProject, findContainerRoot, findProjectRoot, refreshPreflight, sessions,
} from "./shared.js";
import { envMemoryTool } from "./tools/env.js";
import { deepseekSearchTool, deepseekFetchTool, deepseekVisionTool } from "./tools/external.js";

import { ctfInitTool, runTool, sessionTool, procTool, claimTool, flagTool } from "./tools/core.js";
import { casePlanTool, artifactIngestTool, casePreflightTool, caseClearNegativesTool, caseConfigureTool, caseEvidenceTool } from "./tools/case.js";
import { gdbTool } from "./tools/gdb.js";
import { buildWriteupPrompt, resolveWriteup } from "./writeup.js";
import { ctfMap } from "./map.js";

// /ctf command
// ---------------------------------------------------------------------------

function shellWords(input: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input))) out.push(m[1] ?? m[2] ?? m[3] ?? "");
  return out;
}

async function notifyRt(
  ctx: ExtensionContext,
  op: string,
  root: string,
  input: Record<string, unknown>,
): Promise<boolean> {
  try {
    const res = await callRt(op, root, input);
    if (res.ok) {
      ctx.ui.notify(`${op}: ${JSON.stringify(res.data ?? {}, null, 2).slice(0, 1800)}`, "info");
    } else {
      ctx.ui.notify(`${op} failed [${res.error?.code}]: ${res.error?.message}`, "error");
    }
    return res.ok;
  } catch (err) {
    ctx.ui.notify(String(err), "error");
    return false;
  }
}

function sendPrompt(pi: ExtensionAPI, ctx: ExtensionContext, prompt: string): void {
  const text = prompt.trim();
  if (!text) return;
  pi.sendUserMessage(text, ctx.isIdle() ? undefined : { deliverAs: "followUp" });
}

const timeTimers = new Map<string, NodeJS.Timeout>();

function clearTimeTimer(root: string): void {
  clearTimeout(timeTimers.get(root));
  timeTimers.delete(root);
}

function scheduleTimeTimer(pi: ExtensionAPI, root: string, atMs: number | null): void {
  clearTimeTimer(root);
  if (atMs === null) return;
  const delay = Math.max(0, atMs - Date.now());
  const timer = setTimeout(() => {
    timeTimers.delete(root);
    pi.sendUserMessage(
      "[PI4CTF TIME LIMIT] The human-set time limit has been reached. Do not issue new run or session commands. Report progress, blockers, and the next concrete step to the human, then wait.",
      { deliverAs: "followUp" },
    );
  }, delay);
  timer.unref();
  timeTimers.set(root, timer);
}

function ctfCommand(pi: ExtensionAPI): void {
  pi.registerCommand("ctf", {
    description: "pi4ctf case commands: init/status/handoff/map/restart/continue/min/configure/wp",
    handler: async (args, ctx) => {
      const words = shellWords(args.trim());
      const sub = (words.shift() ?? "help").toLowerCase();
      const cwdRoot = findProjectRoot(ctx.cwd);

      if (sub === "help" || sub === "") {
        ctx.ui.notify(
          [
            "/ctf init [flagFormat] [oracleRef] [host|docker] [category] [dockerImage] [target]",
            "/ctf status",
            "/ctf handoff",
            "/ctf map",
            "/ctf restart [caseId]",
            "/ctf continue [prompt]",
            "/ctf min:<minutes> [prompt]",
            "/ctf configure [flagFormat] [oracleRef] [host|docker] [dockerImage] [target]",
            "/ctf wp [template-file-or-folder] [output-file]",
          ].join("\n"),
          "info",
        );
        return;
      }

      if (sub === "init") {
        const challenge = ctx.cwd;
        const container = findContainerRoot(challenge);
        if (hasProject(container) && !isCaseContainer(container)) {
          ctx.ui.notify(`legacy project already exists at ${container}; use /ctf configure or move it aside`, "error");
          return;
        }
        if (isCaseContainer(container)) {
          const active = await callRt("case.activate", container, { challengeRoot: challenge });
          if (active.ok) {
            ctx.ui.notify(`case ${String(active.data?.caseId ?? "?")} already exists at ${challenge}; use /ctf restart <caseId>`, "info");
            return;
          }
          if (active.error?.code !== "NOT_FOUND") {
            ctx.ui.notify(`case activation failed [${active.error?.code}]: ${active.error?.message}`, "error");
            return;
          }
        }
        const flagFormat = words[0] ?? DEFAULT_FLAG_FORMAT;
        const oracleRef = words[1] ?? "../oracle.json";
        const backend = words[2] === "docker" ? "docker" : "host";
        const category = words[3] ?? "misc";
        const dockerImage = backend === "docker"
          ? (words[4] ?? process.env.PI4CTF_DOCKER_IMAGE ?? process.env.PI4CTF_PWN_IMAGE)
          : undefined;
        if (backend === "docker" && !dockerImage) {
          ctx.ui.notify("docker init requires an image: /ctf init ... docker <category> <image>", "error");
          return;
        }
        try {
          const res = await callRt("case.init", container, {
            challengeRoot: challenge,
            id: path.basename(challenge) || "ctf",
            title: path.basename(challenge) || "ctf",
            goal: "solve the challenge and validate the flag",
            category,
            flagFormat,
            backend,
            dockerImage,
            target: words[5],
            oracleRef,
            allowedHosts: ["*"],
          });
          if (res.ok) {
            const oraclePath = path.resolve(challenge, oracleRef);
            const oracleNote = !fs.existsSync(oraclePath)
              ? `\nWARNING: oracle not found at ${oraclePath}; flag layer 4 will reject an oracle created after init. Put the supplied oracle there before /ctf init.`
              : !oracleLooksValid(oraclePath)
                ? `\nWARNING: oracle at ${oraclePath} has no flag or 64-hex flagSha256; it is not pinned. Use case_configure after fixing it.`
                : "";
            const caseId = typeof res.data?.caseId === "string" ? res.data.caseId : "?";
            ctx.ui.notify(`initialized case ${caseId} at ${challenge}${oracleNote}`, "info");
            const pf = await callRt("case.preflight", container, {});
            if (pf.ok) {
              const count = Array.isArray(pf.data?.files) ? pf.data?.files.length : 0;
              ctx.ui.notify(`preflight: ${count} ELF file(s) -> .ctf/${caseId}/chal.json`, "info");
            }
          } else {
            ctx.ui.notify(`init failed [${res.error?.code}]: ${res.error?.message}`, "error");
          }
        } catch (err) {
          ctx.ui.notify(String(err), "error");
        }
        return;
      }

      const root = cwdRoot ?? (process.env.PI4CTF_ROOT ? path.resolve(process.env.PI4CTF_ROOT) : ctx.cwd);
      if (!hasProject(root)) {
        ctx.ui.notify(`no project at ${root}; run /ctf init`, "error");
        return;
      }

      if (sub.startsWith("min:")) {
        const match = /^min:(\d+)$/.exec(sub);
        if (!match) {
          ctx.ui.notify("usage: /ctf min:<minutes> [prompt]; use min:0 to clear", "error");
          return;
        }
        const minutes = Number(match[1]);
        const res = await callRt("case.time", root, { minutes });
        if (!res.ok) {
          ctx.ui.notify(`case.time failed [${res.error?.code}]: ${res.error?.message}`, "error");
          return;
        }
        const limit = res.data?.timeLimitAtMs;
        scheduleTimeTimer(pi, root, typeof limit === "number" ? limit : null);
        ctx.ui.notify(
          minutes === 0 ? "time limit cleared" : `time limit set: ${minutes} minute(s)`,
          "info",
        );
        sendPrompt(pi, ctx, words.join(" "));
        return;
      }

      switch (sub) {
        case "status": {
          const [status, diagnostics] = await Promise.all([
            callRt("project.status", root, {}),
            callRt("case.doctor", root, {}),
          ]);
          if (!status.ok) {
            ctx.ui.notify(`project.status failed [${status.error?.code}]: ${status.error?.message}`, "error");
            return;
          }
          ctx.ui.notify(
            JSON.stringify({
              ...status.data,
              diagnostics: diagnostics.ok ? diagnostics.data : { error: diagnostics.error },
            }, null, 2).slice(0, 3000),
            "info",
          );
          return;
        }
        case "handoff":
          await notifyRt(ctx, "case.handoff", root, {});
          return;
        case "map":
          await ctfMap(ctx, root);
          return;
        case "restart": {
          const caseId = words[0];
          // A fresh agent run must not inherit the previous rt bridge or its
          // live container sessions.
          await sessions.close();
          const res = await callRt("case.restart", root, caseId ? { caseId } : {});
          if (!res.ok) {
            ctx.ui.notify(`case.restart failed [${res.error?.code}]: ${res.error?.message}`, "error");
            return;
          }
          clearTimeTimer(root);
          seenOutcomesByRoot.delete(root);
          lastInjectedByRoot.delete(root);
          PREFLIGHT_DONE.delete(root);
          await refreshPreflight(ctx, root, true);
          const data = res.data ?? {};
          ctx.ui.notify(`case.restart: ${JSON.stringify(data, null, 2).slice(0, 1800)}`, "info");
          const handoff = typeof data.handoff === "string" ? data.handoff.trim() : "";
          if (handoff) {
            sendPrompt(
              pi,
              ctx,
              `[PI4CTF RESTART HANDOFF]\n${handoff}\n[END PI4CTF RESTART HANDOFF]\n\nResume this case from the handoff. Re-check the current target and files before running.`,
            );
          }
          return;
        }
        case "continue": {
          const prompt = words.join(" ").trim();
          const res = await callRt("case.continue", root, {});
          if (!res.ok) {
            ctx.ui.notify(`case.continue failed [${res.error?.code}]: ${res.error?.message}`, "error");
            return;
          }
          ctx.ui.notify(`case.continue: ${JSON.stringify(res.data ?? {})}`, "info");
          clearTimeTimer(root);
          sendPrompt(pi, ctx, prompt);
          return;
        }
        case "configure":
          await notifyRt(ctx, "case.configure", root, {
            flagFormat: words[0],
            oracleRef: words[1],
            backend: words[2] === "host" || words[2] === "docker" ? words[2] : undefined,
            dockerImage: words[3],
            target: words[4],
          });
          await refreshPreflight(ctx, root, true);
          return;
        case "wp": {
          let caseId = path.basename(root) || "ctf";
          try {
            const file = JSON.parse(fs.readFileSync(activeProjectFile(root), "utf8")) as { id?: unknown; caseId?: unknown };
            if (typeof file.caseId === "string" && file.caseId.length > 0) caseId = file.caseId;
            else if (typeof file.id === "string" && file.id.length > 0) caseId = file.id;
          } catch {
            // Keep the directory name if project.json is unreadable.
          }
          try {
            const target = resolveWriteup(root, caseId, words[0], words[1]);
            const handoff = await callRt("case.handoff", root, {});
            if (!handoff.ok) {
              ctx.ui.notify(`writeup handoff failed [${handoff.error?.code}]: ${handoff.error?.message}`, "error");
            }
            const prompt = buildWriteupPrompt({ root, caseId, target });
            ctx.ui.notify(`writeup: ${target.templateRel} -> ${target.outputRel}`, "info");
            sendPrompt(pi, ctx, prompt);
          } catch (err) {
            ctx.ui.notify(String(err), "error");
          }
          return;
        }
        default:
          ctx.ui.notify(`unknown /ctf subcommand: ${sub}; try /ctf help`, "error");
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Extension entry
// ---------------------------------------------------------------------------

export default function pi4ctf(pi: ExtensionAPI): void {
  pi.registerTool(envMemoryTool);
  pi.registerTool(ctfInitTool);
  pi.registerTool(runTool);
  pi.registerTool(sessionTool);
  pi.registerTool(procTool);
  pi.registerTool(gdbTool);
  pi.registerTool(claimTool);
  pi.registerTool(flagTool);
  pi.registerTool(casePlanTool);
  pi.registerTool(artifactIngestTool);
  pi.registerTool(casePreflightTool);
  pi.registerTool(caseClearNegativesTool);
  pi.registerTool(deepseekSearchTool);
  pi.registerTool(deepseekFetchTool);
  pi.registerTool(caseConfigureTool);
  pi.registerTool(caseEvidenceTool);
  pi.registerTool(deepseekVisionTool);
  ctfCommand(pi);

  // Create a minimal project before the first agent run if the user forgot
  // /ctf init. The kernel still enforces flag/oracle rules; auto-init only
  // makes run/session/claim/flag available and records its origin.
  pi.on("session_start", async (_event, ctx) => {
    const root = await ensureAutoProject(ctx);
    if (!root) return;
    // Refresh every startup: old chal.json files predate ignore rules and
    // can keep core dumps/temp patch outputs in the packet.
    await refreshPreflight(ctx, root);
    const status = await callRt("project.status", root, {});
    const at = status.ok && typeof status.data?.timeLimitAtMs === "number" ? status.data.timeLimitAtMs : null;
    scheduleTimeTimer(pi, root, at);
  });

  // Inject the kernel packet before each user-initiated run. Custom
  // notifications skip this so we do not repeat stale context.
  pi.on("before_agent_start", async (event, ctx) => {
    // Custom-triggered runs (notifications) must not re-inject the packet.
    if (event.messageType === "custom") return;
    const root = await ensureAutoProject(ctx);
    if (!root || !hasProject(root)) {
      if (scanChallenge(ctx.cwd).hasMarker) {
        return {
          message: {
            customType: "ctf-context",
            content: "[PI4CTF] No .ctf project; auto-init was skipped (PI4CTF_AUTO_INIT=0 or a guarded directory). Run /ctf init before challenge work.",
            display: true,
          },
        };
      }
      return;
    }
    try {
      const seen = seenOutcomesByRoot.get(root) ?? new Set<string>();
      const res = await callRt("case.context", root, {
        seenOutcomes: [...seen].slice(-200),
      });
      if (!res.ok) return;
      const packet = typeof res.data?.packet === "string" ? res.data.packet.trim() : "";
      if (!packet || packet === lastInjectedByRoot.get(root)) return;
      lastInjectedByRoot.set(root, packet);
      const ids = Array.isArray(res.data?.outcomeIds) ? (res.data.outcomeIds as unknown[]).map(String) : [];
      for (const id of ids) seen.add(id);
      seenOutcomesByRoot.set(root, seen);
      return {
        message: {
          customType: "ctf-context",
          content: `[PI4CTF KERNEL CONTEXT]\n${packet}\n[END PI4CTF KERNEL CONTEXT]`,
          display: false,
        },
      };
    } catch (err) {
      ctx.ui.notify(`context injection failed: ${err instanceof Error ? err.message : String(err)}`, "error");
    }
  });

  pi.on("session_shutdown", async () => {
    seenOutcomesByRoot.clear();
    lastInjectedByRoot.clear();
    PREFLIGHT_DONE.clear();
    for (const root of [...timeTimers.keys()]) clearTimeTimer(root);
    await sessions.close();
  });
}
