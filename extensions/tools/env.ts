/** env_memory tool: host/docker/image tool inventory. */
import * as path from "node:path";
import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { RootParam, callRt, failure, findProjectRoot, responseResult } from "../shared.js";

export const envMemoryTool = defineTool({
  name: "env_memory",
  label: "CTF environment memory",
  description:
    "Remember tool locations, versions, and short environment notes for the current host/docker/wsl environment, or a Docker image via image=name. No challenge solutions. recall before using a remembered tool; probe user records before relying on them; actual command output wins.",
  promptSnippet: "Recall or update the current environment's tool memory",
  promptGuidelines: [
    "Use env_memory recall before asking the user where a tool is installed. Default recall is the bounded summary; use records:true only when you need individual paths.",
    "Use env_memory capability=<group> (pwn/reverse/web/net/crypto/forensics/java/android/misc) to inspect a class without pulling all records. Use env_memory probe to discover generic tools in the current backend; pass image=<name> to probe a Docker image without changing the project backend; it does not consume a run slot. Without ids it probes the built-in table plus previously recorded tools; unknown ids use a generic PATH probe. The built-in table covers jdk/python/gdb/jadx/ghidra.",
    "Use env_memory remember only for user-confirmed paths/versions; probe is the only way to write probe evidence.",
    "Store tool metadata and short environment facts only. Never store flags, writeups, payloads, or solution steps.",
  ],
  parameters: Type.Object({
    action: Type.Union([
      Type.Literal("recall"),
      Type.Literal("probe"),
      Type.Literal("refresh"),
      Type.Literal("remember"),
      Type.Literal("forget"),
      Type.Literal("note"),
    ]),
    id: Type.Optional(Type.String({ description: "Tool id, e.g. jdk@8 or jadx" })),
    capability: Type.Optional(Type.String({ description: "Capability alias, e.g. java-runtime" })),
    origin: Type.Optional(Type.String({ description: "Filter recall by record origin, e.g. env or test" })),
    ids: Type.Optional(Type.Array(Type.String(), { description: "Probe/recall/forget ids" })),
    image: Type.Optional(Type.String({ description: "Docker image whose environment should be probed/recalled" })),
    detailed: Type.Optional(Type.Boolean({ description: "Return full provenance/signature records" })),
    records: Type.Optional(Type.Boolean({ description: "Return compact tool rows; default returns the bounded summary" })),
    maxChars: Type.Optional(Type.Number({ description: "Max compact records payload; default 2000, or 20000 with records:true" })),
    includeSummary: Type.Optional(Type.Boolean({ description: "Include the packet-style summary; default false" })),
    path: Type.Optional(Type.String({ description: "Absolute tool path for remember" })),
    version: Type.Optional(Type.String({ description: "Observed version for remember" })),
    text: Type.Optional(Type.String({ description: "Short environment fact for note, e.g. GPU/driver/ICD" })),
    env: Type.Optional(Type.Object({
      JAVA_HOME: Type.Optional(Type.String({ description: "Absolute JAVA_HOME ancestor of path" })),
    })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = params.root
        ? path.resolve(ctx.cwd, params.root)
        : findProjectRoot(ctx.cwd) ?? path.resolve(ctx.cwd);
      const res = await callRt("env.memory", root, {
        action: params.action,
        id: params.id,
        capability: params.capability,
        origin: params.origin,
        ids: params.ids,
        image: params.image,
        detailed: params.detailed,
        records: params.records,
        maxChars: params.maxChars,
        includeSummary: params.includeSummary,
        path: params.path,
        version: params.version,
        text: params.text,
        env: params.env,
      });
      return responseResult(res, "env.memory");
    } catch (err) {
      return failure(err);
    }
  },
});

