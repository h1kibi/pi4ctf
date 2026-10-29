/** Shared pi4ctf extension runtime: rt bridge, sessions, auto-init, result adapters. */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { fileURLToPath } from "node:url";
import { Type } from "typebox";
import {
  autoInitSpec,
  hasProject,
  readJsonFile,
  shouldAutoInit,
} from "../dist/adapter/autoinit.js";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PACKAGE_ROOT = path.resolve(HERE, "..");
export const RT_PATH = process.env.PI4CTF_RT ?? path.join(PACKAGE_ROOT, "dist", "rt.js");
// Installed pi may be a standalone binary (pi.exe), not node. The kernel is
// JS, so always launch it with node; allow an explicit override for odd PATHs.
export const NODE_BIN =
  process.env.PI4CTF_NODE ??
  (/^node(\.exe)?$/i.test(path.basename(process.execPath)) ? process.execPath : "node");
const RT_TIMEOUT_MS = 15 * 60_000;
const MAX_RT_OUTPUT = 2 * 1024 * 1024;

// pi's bash tool and the kernel must expose the same proxy view. The host may
// provide HTTP(S)_PROXY without NO_PROXY; add the loopback bypass once here so
// both channels inherit it.
const DEFAULT_NO_PROXY = "localhost,127.0.0.1,::1";
if (!process.env.NO_PROXY) process.env.NO_PROXY = DEFAULT_NO_PROXY;
if (!process.env.no_proxy) process.env.no_proxy = DEFAULT_NO_PROXY;
export const seenOutcomesByRoot = new Map<string, Set<string>>();
export const lastInjectedByRoot = new Map<string, string>();

interface RtError {
  code: string;
  message: string;
  details?: unknown;
}

interface RtResponse {
  ok: boolean;
  op?: string;
  data?: Record<string, unknown>;
  error?: RtError;
}

export function findProjectRoot(start: string): string | null {
  let cur = path.resolve(start);
  for (let i = 0; i < 12; i++) {
    if (fs.existsSync(path.join(cur, ".ctf", "project.json"))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Auto-init
// ---------------------------------------------------------------------------
//
// pi4ctf is often installed globally. Auto-init must therefore be conservative:
// a normal source checkout must not grow a .ctf/ directory just because pi was
// opened there. `PI4CTF_AUTO_INIT=1` forces it (still refuses $HOME/package
// root); `PI4CTF_AUTO_INIT=0` disables it. Otherwise only recognizable CTF
// material triggers it.

const AUTO_INIT_DONE = new Map<string, "done" | "failed">();
export const PREFLIGHT_DONE = new Set<string>();
export async function refreshPreflight(ctx: ExtensionContext, root: string, force = false): Promise<void> {
  if (!force && PREFLIGHT_DONE.has(root)) return;
  PREFLIGHT_DONE.add(root);
  try {
    const pf = await callRt("case.preflight", root, {});
    if (pf.ok) {
      lastInjectedByRoot.delete(root);
      const files = Array.isArray(pf.data?.files) ? pf.data.files.length : 0;
      const libc = Array.isArray(pf.data?.libc) ? pf.data.libc.length : 0;
      ctx.ui.notify(`preflight: ${files} ELF file(s), ${libc} libc candidate(s) -> .ctf/chal.json`, "info");
    }
  } catch {
    // Preflight is best effort; a missing toolchain must not block the case.
  }
}

export async function ensureAutoProject(ctx: ExtensionContext): Promise<string | null> {
  const configured = process.env.PI4CTF_ROOT ? path.resolve(process.env.PI4CTF_ROOT) : null;
  const existing = configured ?? findProjectRoot(ctx.cwd);
  if (existing && hasProject(existing)) return existing;
  const root = configured ?? path.resolve(ctx.cwd);
  if (!shouldAutoInit(root) || AUTO_INIT_DONE.get(root) === "failed") return null;
  if (hasProject(root)) return root;
  if (AUTO_INIT_DONE.get(root) === "done") return root;
  const spec = autoInitSpec(root);
  try {
    const res = await callRt("project.init", root, spec);
    if (!res.ok) {
      if (hasProject(root)) return root;
      AUTO_INIT_DONE.set(root, "failed");
      ctx.ui.notify(`pi4ctf auto-init failed [${res.error?.code}]: ${res.error?.message}`, "error");
      return null;
    }
    AUTO_INIT_DONE.set(root, "done");
    ctx.ui.notify(
      `pi4ctf auto-initialized ${root} (backend=${String(spec.backend)}, category=${String(spec.category)}); use /ctf configure to change it`,
      "info",
    );
    const proj = readJsonFile(path.join(root, ".ctf", "project.json"));
    if (proj?.oracleHash === null) {
      ctx.ui.notify(
        "no valid oracle pinned; run/session/claim work, but flag layer 4 will reject until you place a target-bound oracle and run /ctf configure",
        "warning",
      );
    }
    await refreshPreflight(ctx, root);
    return root;
  } catch (err) {
    AUTO_INIT_DONE.set(root, "failed");
    ctx.ui.notify(`pi4ctf auto-init failed: ${err instanceof Error ? err.message : String(err)}`, "error");
    return null;
  }
}

export function rootFor(ctx: ExtensionContext, explicit?: string): string {
  const root = explicit
    ? path.resolve(ctx.cwd, explicit)
    : process.env.PI4CTF_ROOT
      ? path.resolve(process.env.PI4CTF_ROOT)
      : findProjectRoot(ctx.cwd) ?? ctx.cwd;
  if (!fs.existsSync(path.join(root, ".ctf", "project.json"))) {
    throw new Error(
      `no pi4ctf project at ${root}; run /ctf init first (or set PI4CTF_ROOT)`,
    );
  }
  return root;
}

export function ensureRt(): void {
  if (!fs.existsSync(RT_PATH)) {
    throw new Error(
      `pi4ctf kernel not built: ${RT_PATH} is missing; run "npm run build" in ${PACKAGE_ROOT}`,
    );
  }
}

/** Run one rt JSON request. The kernel returns exactly one JSON object. */
export async function callRt(
  op: string,
  root: string,
  input: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<RtResponse> {
  ensureRt();
  const { promise, resolve, reject } = Promise.withResolvers<RtResponse>();
  {
    const child = spawn(
      NODE_BIN,
      [RT_PATH, "--op", op, "--root", root, "--input", JSON.stringify(input)],
      {
        cwd: root,
        env: process.env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );

    let stdout = "";
    let stderr = "";
    let overflow = false;
    let settled = false;

    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      fn();
    };

    const abort = () => {
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      finish(() => reject(new Error(`${op} aborted`)));
    };

    const append = (which: "out" | "err", chunk: Buffer) => {
      const text = chunk.toString("utf8");
      if (which === "out") stdout += text;
      else stderr += text;
      if (stdout.length + stderr.length > MAX_RT_OUTPUT) {
        overflow = true;
        try {
          child.kill();
        } catch {
          /* ignore */
        }
      }
    };

    child.stdout.on("data", (d: Buffer) => append("out", d));
    child.stderr.on("data", (d: Buffer) => append("err", d));
    child.stdout.on("error", () => {});
    child.stderr.on("error", () => {});

    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      finish(() => reject(new Error(`${op} timed out after ${RT_TIMEOUT_MS}ms`)));
    }, RT_TIMEOUT_MS);
    timer.unref?.();

    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) {
      abort();
      return promise;
    }

    child.on("error", (err) => {
      finish(() => reject(new Error(`${op} spawn failed: ${err.message}`)));
    });

    child.on("close", (code) => {
      finish(() => {
        if (overflow) {
          reject(new Error(`${op} output exceeded ${MAX_RT_OUTPUT} bytes`));
          return;
        }
        const line = stdout
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean)
          .pop();
        if (!line) {
          reject(
            new Error(
              `${op} returned no JSON (exit=${code})${stderr ? `: ${stderr.slice(0, 800)}` : ""}`,
            ),
          );
          return;
        }
        try {
          resolve(JSON.parse(line) as RtResponse);
        } catch {
          reject(
            new Error(
              `${op} returned non-JSON: ${line.slice(0, 500)}${stderr ? `; stderr: ${stderr.slice(0, 500)}` : ""}`,
            ),
          );
        }
      });
    });
  }
  return promise;
}

export function failure(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text" as const, text: `CTF_ERROR: ${message}` }],
    details: { error: message },
    isError: true,
  };
}

export function jsonResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    details: { value },
    ...(isError ? { isError: true } : {}),
  };
}

export function responseResult(res: RtResponse, op: string) {
  if (!res.ok) {
    const err = res.error ?? { code: "INTERNAL", message: "unknown kernel error" };
    return {
      content: [
        {
          type: "text" as const,
          text: `${op} failed [${err.code}]: ${err.message}${err.details ? `\n${JSON.stringify(err.details, null, 2)}` : ""}`,
        },
      ],
      details: res as unknown as Record<string, unknown>,
      isError: true,
    };
  }
  return {
    content: [{ type: "text" as const, text: JSON.stringify(res.data ?? {}, null, 2) }],
    details: res.data ?? {},
  };
}

export function sessionResult(res: Record<string, unknown>, op: string) {
  if (res.ok !== true) return responseResult(res as unknown as RtResponse, op);
  return {
    content: [{ type: "text" as const, text: JSON.stringify(res, null, 2) }],
    details: res,
  };
}

// ---------------------------------------------------------------------------
// Persistent session bridge: one `rt --session` child, sequential requests.
// ---------------------------------------------------------------------------

interface SessionWaiter {
  resolve: (msg: Record<string, unknown>) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

export class SessionBridge {
  private child: ChildProcessWithoutNullStreams | null = null;
  private rl: readline.Interface | null = null;
  private waiters: SessionWaiter[] = [];
  private tail: Promise<unknown> = Promise.resolve();
  private openIds = new Set<string>();
  private stderr = "";
  private closing = false;

  private ensure(): void {
    if (this.child) return;
    ensureRt();
    this.closing = false;
    this.stderr = "";
    const child = spawn(NODE_BIN, [RT_PATH, "--session"], {
      cwd: PACKAGE_ROOT,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams;
    this.child = child;
    this.rl = readline.createInterface({ input: child.stdout });
    this.rl.on("line", (line) => this.onLine(line));
    child.stderr.on("data", (d: Buffer) => {
      this.stderr += d.toString("utf8");
      if (this.stderr.length > 4000) this.stderr = this.stderr.slice(-4000);
    });
    child.stdin.on("error", () => {});
    child.stdout.on("error", () => {});
    child.stderr.on("error", () => {});
    child.on("error", (err) => this.fail(new Error(`session bridge failed: ${err.message}`)));
    child.on("close", () => {
      if (!this.closing) {
        this.fail(new Error(`session bridge exited${this.stderr ? `: ${this.stderr}` : ""}`));
      }
    });
  }

  private fail(err: Error): void {
    this.child = null;
    this.rl?.close();
    this.rl = null;
    const pending = this.waiters.splice(0);
    for (const w of pending) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  private onLine(line: string): void {
    const waiter = this.waiters.shift();
    if (!waiter) return;
    clearTimeout(waiter.timer);
    try {
      const msg = JSON.parse(line) as Record<string, unknown>;
      if (msg.ok === true && typeof msg.id === "string") {
        if (msg.exited === true) this.openIds.delete(msg.id);
        else this.openIds.add(msg.id);
      }
      waiter.resolve(msg);
    } catch {
      waiter.reject(new Error(`session bridge non-JSON: ${line.slice(0, 300)}`));
    }
  }

  private once(op: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.ensure();
    const { promise, resolve, reject } = Promise.withResolvers<Record<string, unknown>>();
    const timer = setTimeout(() => {
      const idx = this.waiters.findIndex((w) => w.timer === timer);
      if (idx >= 0) this.waiters.splice(idx, 1);
      reject(new Error(`session ${op} timed out`));
    }, RT_TIMEOUT_MS);
    timer.unref?.();
    this.waiters.push({ resolve, reject, timer });
    this.child?.stdin.write(JSON.stringify({ op, ...payload }) + "\n");
    return promise;
  }

  request(op: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const next = this.tail.then(() => this.once(op, payload));
    this.tail = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  async close(): Promise<void> {
    const child = this.child;
    if (!child) return;
    this.closing = true;
    for (const id of [...this.openIds]) {
      try {
        await this.request("close", { id });
      } catch {
        /* best effort */
      }
      this.openIds.delete(id);
    }
    try {
      child.stdin.end();
      child.kill();
    } catch {
      /* already gone */
    }
    this.child = null;
    this.rl?.close();
    this.rl = null;
  }
}

export const sessions = new SessionBridge();

// ---------------------------------------------------------------------------

export const RootParam = Type.Optional(
  Type.String({ description: "Project root; defaults to PI4CTF_ROOT or nearest .ctf/" }),
);
