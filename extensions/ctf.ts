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
  PACKAGE_ROOT, RT_PATH, seenOutcomesByRoot, lastInjectedByRoot, PREFLIGHT_DONE,
  callRt, ensureAutoProject, findProjectRoot, refreshPreflight, sessions,
} from "./shared.js";
import { envMemoryTool } from "./tools/env.js";
import { deepseekSearchTool, deepseekFetchTool, deepseekVisionTool } from "./tools/external.js";

import { ctfInitTool, runTool, sessionTool, procTool, claimTool, flagTool } from "./tools/core.js";
import { casePlanTool, caseRestartTool, caseCloseTool, artifactIngestTool, casePreflightTool, caseClearNegativesTool, caseConfigureTool, caseEvidenceTool } from "./tools/case.js";

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
): Promise<void> {
  try {
    const res = await callRt(op, root, input);
    if (res.ok) {
      ctx.ui.notify(`${op}: ${JSON.stringify(res.data ?? {}, null, 2).slice(0, 1800)}`, "info");
    } else {
      ctx.ui.notify(`${op} failed [${res.error?.code}]: ${res.error?.message}`, "error");
    }
  } catch (err) {
    ctx.ui.notify(String(err), "error");
  }
}

function ctfCommand(pi: ExtensionAPI): void {
  pi.registerCommand("ctf", {
    description: "pi4ctf case commands: init/status/context/handoff/doctor/preflight/plan/restart/close/complete/configure",
    handler: async (args, ctx) => {
      const words = shellWords(args.trim());
      const sub = (words.shift() ?? "help").toLowerCase();
      const cwdRoot = findProjectRoot(ctx.cwd);

      if (sub === "help" || sub === "") {
        ctx.ui.notify(
          [
            "/ctf init [flagFormat] [oracleRef] [host|docker] [category] [dockerImage] [target]",
            "/ctf status",
            "/ctf context",
            "/ctf handoff",
            "/ctf doctor",
            "/ctf preflight",
            "/ctf plan <next>",
            "/ctf restart",
            "/ctf close [completed|failed|stopped]",
            "/ctf clear-soft",
            "/ctf configure [flagFormat] [oracleRef] [host|docker] [dockerImage] [target]",
            "/ctf complete",
            "/ctf debug",
          ].join("\n"),
          "info",
        );
        return;
      }

      if (sub === "init") {
        const root = ctx.cwd;
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
          const res = await callRt("project.init", root, {
            id: path.basename(root) || "ctf",
            title: path.basename(root) || "ctf",
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
            const oraclePath = path.resolve(root, oracleRef);
            const oracleNote = !fs.existsSync(oraclePath)
              ? `\nWARNING: oracle not found at ${oraclePath}; flag layer 4 will reject an oracle created after init. Put the supplied oracle there before /ctf init.`
              : !oracleLooksValid(oraclePath)
                ? `\nWARNING: oracle at ${oraclePath} has no flag or 64-hex flagSha256; it is not pinned. Use case_configure after fixing it.`
                : "";
            ctx.ui.notify(`initialized ${root}${oracleNote}`, "info");
            const pf = await callRt("case.preflight", root, {});
            if (pf.ok) {
              const count = Array.isArray(pf.data?.files) ? pf.data?.files.length : 0;
              ctx.ui.notify(`preflight: ${count} ELF file(s) -> .ctf/chal.json`, "info");
            }
          } else {
            ctx.ui.notify(`init failed [${res.error?.code}]: ${res.error?.message}`, "error");
          }
        } catch (err) {
          ctx.ui.notify(String(err), "error");
        }
        return;
      }

      if (sub === "debug") {
        ctx.ui.notify(
          JSON.stringify(
            { execPath: process.execPath, rt: RT_PATH, packageRoot: PACKAGE_ROOT, cwd: ctx.cwd },
            null,
            2,
          ),
          "info",
        );
        return;
      }

      const root = cwdRoot ?? (process.env.PI4CTF_ROOT ? path.resolve(process.env.PI4CTF_ROOT) : ctx.cwd);
      if (!fs.existsSync(path.join(root, ".ctf", "project.json"))) {
        ctx.ui.notify(`no project at ${root}; run /ctf init`, "error");
        return;
      }

      switch (sub) {
        case "status":
          await notifyRt(ctx, "project.status", root, {});
          return;
        case "context":
          await notifyRt(ctx, "case.context", root, {});
          return;
        case "handoff":
          await notifyRt(ctx, "case.handoff", root, {});
          return;
        case "doctor":
          await notifyRt(ctx, "case.doctor", root, {});
          return;
        case "preflight":
          await notifyRt(ctx, "case.preflight", root, {});
          lastInjectedByRoot.delete(root);
          return;
        case "complete":
          await notifyRt(ctx, "case.complete", root, {});
          return;
        case "plan": {
          const next = words.join(" ").trim();
          await notifyRt(ctx, "case.plan", root, { chain: [], next, preconditions: [] });
          return;
        }
        case "restart":
          await notifyRt(ctx, "case.restart", root, {});
          return;
        case "close":
          await notifyRt(ctx, "case.close", root, { status: words[0] });
          return;
        case "clear-soft":
          await notifyRt(ctx, "case.clearNegatives", root, {});
          return;
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
  pi.registerTool(claimTool);
  pi.registerTool(flagTool);
  pi.registerTool(casePlanTool);
  pi.registerTool(caseRestartTool);
  pi.registerTool(caseCloseTool);
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
  });

  // Inject the kernel packet before each user-initiated run. Custom
  // notifications skip this so we do not repeat stale context.
  pi.on("before_agent_start", async (event, ctx) => {
    // 0.84's runtime may still carry messageType for custom-triggered runs;
    // its d.ts exposes prompt/images instead. Be tolerant of both.
    const messageType = (event as typeof event & { messageType?: "user" | "custom" }).messageType;
    if (messageType === "custom") return;
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
    } catch {
      // Context injection is best effort; tool calls will surface kernel errors.
    }
  });

  pi.on("session_shutdown", async () => {
    seenOutcomesByRoot.clear();
    lastInjectedByRoot.clear();
    PREFLIGHT_DONE.clear();
    await sessions.close();
  });
}
