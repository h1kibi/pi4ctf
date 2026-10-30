/** Structured GDB/MI helper. The kernel owns the live GDB process; this tool
 *  only translates actions over the persistent rt session bridge. */
import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { RootParam, failure, rootFor, sessionResult, sessions } from "../shared.js";

const Action = Type.Union([
  Type.Literal("start"),
  Type.Literal("list"),
  Type.Literal("kill"),
  Type.Literal("attach"),
  Type.Literal("run"),
  Type.Literal("continue"),
  Type.Literal("step"),
  Type.Literal("next"),
  Type.Literal("stepi"),
  Type.Literal("nexti"),
  Type.Literal("finish"),
  Type.Literal("break"),
  Type.Literal("delete"),
  Type.Literal("list-breakpoints"),
  Type.Literal("context"),
  Type.Literal("regs"),
  Type.Literal("backtrace"),
  Type.Literal("stack"),
  Type.Literal("mem"),
  Type.Literal("raw"),
  Type.Literal("interrupt"),
], { description: "GDB action" });

export const gdbTool = defineTool({
  name: "gdb",
  label: "CTF GDB",
  description:
    "Drive a persistent GDB/MI debugger through pi4ctf: start/attach, breakpoints, continue/step, stop context, registers, stack, memory, and guarded raw GDB commands. Uses the case backend: host gdb or Docker image with SYS_PTRACE.",
  promptSnippet: "Debug a pwn binary with a persistent GDB session",
  promptGuidelines: [
    "Use gdb for pwn debugging instead of launching gdb through bash; keep one debugger session per binary.",
    "Start with action=start, then action=break, action=run, and action=context. context returns registers/backtrace/disassembly in one call.",
    "action=attach needs an existing session id and a pid; Docker attach targets a pid inside the debugger container, not the host.",
    "raw is a guarded escape hatch and blocks shell/python/source/dump/restore; do not use it to bypass the kernel boundary.",
    "Docker images must contain gdb; the helper overrides the image entrypoint with gdb and disables .gdbinit with --nx.",
    "Close the session with action=kill when done.",
  ],
  parameters: Type.Object({
    action: Action,
    id: Type.Optional(Type.String({ description: "GDB session id, e.g. g0001" })),
    binary: Type.Optional(Type.String({ description: "Binary path below the challenge root, or workspace/... for the case workspace" })),
    cwd: Type.Optional(Type.String({ description: "GDB working directory; workspace or a subpath maps to the case workspace" })),
    args: Type.Optional(Type.Array(Type.String({ description: "Inferior arguments; set before run" }))),
    pid: Type.Optional(Type.Number({ description: "PID to attach to inside the GDB backend" })),
    location: Type.Optional(Type.String({ description: "Breakpoint symbol, address, or file:line" })),
    condition: Type.Optional(Type.String({ description: "GDB breakpoint condition" })),
    number: Type.Optional(Type.Number({ description: "Breakpoint number for delete" })),
    address: Type.Optional(Type.Union([Type.String(), Type.Number()], { description: "Memory address/expression (decimal or 0xhex)" })),
    length: Type.Optional(Type.Number({ description: "Memory bytes, 1-16384; default 256" })),
    command: Type.Optional(Type.String({ description: "Raw GDB command for action=raw" })),
    root: RootParam,
  }),
  executionMode: "sequential",
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const payload: Record<string, unknown> = { root, action: params.action };
      for (const key of ["id", "binary", "cwd", "args", "pid", "location", "condition", "number", "address", "length", "command"] as const) {
        const value = params[key];
        if (value !== undefined) payload[key] = key === "address" ? String(value) : value;
      }
      const res = await sessions.request("gdb", payload);
      return sessionResult(res, `gdb.${params.action}`);
    } catch (err) {
      return failure(err);
    }
  },
});
