/** Core verb and case-control tools. */
import * as fs from "node:fs";
import * as path from "node:path";
import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { DEFAULT_FLAG_FORMAT, oracleLooksValid } from "../../dist/adapter/autoinit.js";
import { RootParam, callRt, failure, refreshPreflight, rootFor, responseResult, sessionResult, sessions } from "../shared.js";

export const ctfInitTool = defineTool({
  name: "ctf_init",
  label: "CTF initialize project",
  description:
    "Initialize a pi4ctf project explicitly when auto-init was skipped (Java/archive-only challenges, guarded directory, or PI4CTF_AUTO_INIT=0). Prefer auto-init; use this instead of calling the low-level rt CLI.",
  promptSnippet: "Initialize a pi4ctf project in the current challenge directory",
  promptGuidelines: [
    "Use ctf_init only when there is no .ctf/project.json; otherwise use case_configure.",
    "Put the oracle outside the challenge workspace and before init; an oracle created later is not trusted.",
    "For Java/web challenges, pass category web/rev and a dockerImage with the matching JDK when needed.",
  ],
  parameters: Type.Object({
    flagFormat: Type.Optional(Type.String({ description: "Flag regex; defaults to the generic CTF shape" })),
    oracleRef: Type.Optional(Type.String({ description: "Relative oracle path outside the challenge root; default ../oracle.json" })),
    backend: Type.Optional(Type.Union([Type.Literal("host"), Type.Literal("docker")], { description: "Execution backend; default host" })),
    category: Type.Optional(Type.String({ description: "pwn/web/crypto/rev/forensics/misc; default misc" })),
    dockerImage: Type.Optional(Type.String({ description: "Docker image; required for docker unless PI4CTF_DOCKER_IMAGE is set" })),
    target: Type.Optional(Type.String({ description: "host[:port] or URL" })),
    allowedHosts: Type.Optional(Type.Array(Type.String(), { description: "allowedHosts patterns; loopback is always allowed; default *" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = params.root ? path.resolve(ctx.cwd, params.root) : path.resolve(ctx.cwd);
      if (fs.existsSync(path.join(root, ".ctf", "project.json"))) {
        throw new Error(`project already exists at ${root}; use case_configure`);
      }
      const backend = params.backend ?? "host";
      const dockerImage = params.dockerImage ?? process.env.PI4CTF_DOCKER_IMAGE ?? process.env.PI4CTF_PWN_IMAGE;
      if (backend === "docker" && !dockerImage) {
        throw new Error("ctf_init backend=docker requires dockerImage (or PI4CTF_DOCKER_IMAGE)");
      }
      const oracleRef = params.oracleRef ?? "../oracle.json";
      const res = await callRt("project.init", root, {
        id: path.basename(root) || "ctf",
        title: path.basename(root) || "ctf",
        goal: "solve the challenge and validate the flag",
        category: params.category ?? "misc",
        flagFormat: params.flagFormat ?? DEFAULT_FLAG_FORMAT,
        backend,
        dockerImage: backend === "docker" ? dockerImage : undefined,
        target: params.target,
        oracleRef,
        allowedHosts: params.allowedHosts?.length ? params.allowedHosts : ["*"],
      });
      if (res.ok) {
        const oraclePath = path.resolve(root, oracleRef);
        const notes: string[] = [];
        if (!fs.existsSync(oraclePath)) notes.push(`oracle not found at ${oraclePath}; flag will be unverified until it exists`);
        else if (!oracleLooksValid(oraclePath)) notes.push(`oracle at ${oraclePath} has no flag or 64-hex flagSha256; flag will be unverified`);
        await refreshPreflight(ctx, root, true);
        if (notes.length) res.data = { ...(res.data ?? {}), warnings: notes };
      }
      return responseResult(res, "ctf_init");
    } catch (err) {
      return failure(err);
    }
  },
});

export const runTool = defineTool({
  name: "run",
  label: "CTF run",
  description:
    "Execute a bounded command or a kernel-owned probe batch through pi4ctf. Supports target/env/synthetic; returns JSON text with ProcessOutcome/item fields and artifacts; parse before accessing fields.",
  promptSnippet: "Run a bounded CTF command and return a traceable JSON outcome",
  promptGuidelines: [
    "Use run for challenge commands; do not use bash for the same purpose.",
    "After run, use the returned artifact/shaped output as evidence; never assert a Fact from memory.",
    "For a multi-probe matrix, pass probes (max 16); kernel executes/classifies each probe and items are Fact-eligible.",
  ],
  parameters: Type.Object({
    argv: Type.Optional(Type.Array(Type.String({ description: "Executable and arguments" }))),
    concurrency: Type.Optional(Type.Number({ description: "Probe concurrency 1-4; default 1" })),
    probes: Type.Optional(Type.Array(Type.Object({
      label: Type.Optional(Type.String()),
      http: Type.Optional(Type.Object({
        method: Type.Optional(Type.String()),
        url: Type.String(),
        headers: Type.Optional(Type.Record(Type.String(), Type.String())),
        body: Type.Optional(Type.String()),
        bodyB64: Type.Optional(Type.String()),
        bodyFile: Type.Optional(Type.String({ description: "File body; relative to project root; content hash enters route signature" })),
        followRedirects: Type.Optional(Type.Boolean()),
        cookieJar: Type.Optional(Type.Boolean()),
        raw: Type.Optional(Type.Boolean()),
        insecure: Type.Optional(Type.Boolean()),
        timeoutMs: Type.Optional(Type.Number()),
      })),
      argv: Type.Optional(Type.Array(Type.String())),
      command: Type.Optional(Type.String()),
      cwd: Type.Optional(Type.String()),
      timeoutMs: Type.Optional(Type.Number()),
      stdin: Type.Optional(Type.String()),
    }), { description: "Kernel-executed probe batch (1-16); mutually exclusive with argv/command" })),
    command: Type.Optional(Type.String({ description: "Shell command; bash -lc" })),
    cwd: Type.Optional(Type.String({ description: "Relative working directory below the project root" })),
    timeoutMs: Type.Optional(Type.Number({ description: "Kernel timeout, <=600000" })),
    stdin: Type.Optional(Type.String({ description: "Bounded stdin" })),
    env: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Extra environment; target HOST/PORT/TARGET are injected first" })),
    target: Type.Optional(Type.Union([
      Type.String({ description: "host[:port] or URL" }),
      Type.Object({
        host: Type.String(),
        port: Type.Optional(Type.Number()),
        protocol: Type.Optional(Type.String()),
        instanceId: Type.Optional(Type.String()),
        url: Type.Optional(Type.String()),
      }, { description: "Structured target" }),
    ], { description: "Target override; defaults to project.target" })),
    skipTargetCheck: Type.Optional(Type.Boolean({ description: "Skip the TCP reachability gate (target started inside this run)" })),
    targetTimeoutMs: Type.Optional(Type.Number({ description: "Target TCP check timeout 100-30000ms; default 2000" })),
    synthetic: Type.Optional(Type.Boolean({ description: "Mark this run as dry-run/synthetic evidence" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      if (params.probes && params.probes.length > 0) {
        if (params.argv || params.command) throw new Error("probes cannot be combined with argv/command");
      } else {
        if (params.argv && params.argv.length === 0) throw new Error("run argv must not be empty");
        if (!params.argv && !params.command) throw new Error("run requires argv, command, or probes");
      }
      const res = await callRt(
        "run",
        root,
        {
          argv: params.argv,
          probes: params.probes,
          concurrency: params.concurrency,
          command: params.command,
          cwd: params.cwd,
          timeoutMs: params.timeoutMs,
          stdin: params.stdin,
          env: params.env,
          target: params.target,
          skipTargetCheck: params.skipTargetCheck,
          targetTimeoutMs: params.targetTimeoutMs,
          synthetic: params.synthetic,
        },
        signal,
      );
      return responseResult(res, "run");
    } catch (err) {
      return failure(err);
    }
  },
});

export const sessionTool = defineTool({
  name: "session",
  label: "CTF session",
  description:
    "Open/write/read/resize/close a persistent interactive process through the pi4ctf kernel. Use for gdb, nc, python, and other interactive targets.",
  promptSnippet: "Drive a persistent interactive CTF session",
  promptGuidelines: [
    "Use session for interactive programs; run/read the returned increments.",
    "Close sessions when done; the kernel enforces a per-project cap.",
  ],
  parameters: Type.Object({
    op: Type.Union([
      Type.Literal("open"),
      Type.Literal("write"),
      Type.Literal("read"),
      Type.Literal("resize"),
      Type.Literal("close"),
    ]),
    argv: Type.Optional(Type.Array(Type.String())),
    data: Type.Optional(Type.String()),
    id: Type.Optional(Type.String()),
    timeoutMs: Type.Optional(Type.Number()),
    cols: Type.Optional(Type.Number()),
    rows: Type.Optional(Type.Number()),
    root: RootParam,
  }),
  executionMode: "sequential",
  async execute(_toolCallId, params, signal, _onUpdate, ctx) {
    try {
      if (signal?.aborted) throw new Error("session aborted");
      if (params.op === "open") {
        const root = rootFor(ctx, params.root);
        if (!params.argv || params.argv.length === 0) throw new Error("session open requires argv");
        const res = await sessions.request("open", { root, argv: params.argv });
        return sessionResult(res, "session.open");
      }
      if (!params.id) throw new Error(`session ${params.op} requires id`);
      const payload: Record<string, unknown> = { id: params.id };
      if (params.data !== undefined) payload.data = params.data;
      if (params.timeoutMs !== undefined) payload.timeoutMs = params.timeoutMs;
      if (params.cols !== undefined) payload.cols = params.cols;
      if (params.rows !== undefined) payload.rows = params.rows;
      const res = await sessions.request(params.op, payload);
      return sessionResult(res, `session.${params.op}`);
    } catch (err) {
      return failure(err);
    }
  },
});

export const procTool = defineTool({
  name: "proc",
  label: "CTF process read",
  description:
    "Read bounded /proc observations from a live pi4ctf session: maps, unique libs, or memory bytes at an address. Host sessions use /proc/<pid>; docker sessions read PID 1 in the tracked container. Observation only; artifact_ingest can promote it into the claim chain.",
  promptSnippet: "Read a live session's maps/libs/memory through /proc",
  promptGuidelines: [
    "Use proc on a session id (s0001), never an arbitrary host pid.",
    "mem requires address (decimal or 0xhex) and optional length <=16384; mapped pages only.",
    "proc output is an observation, not a Fact; ingest the artifact if you need a quote.",
  ],
  parameters: Type.Object({
    session: Type.String({ description: "Session id, e.g. s0001" }),
    action: Type.Union([Type.Literal("maps"), Type.Literal("libs"), Type.Literal("mem")]),
    address: Type.Optional(Type.Union([Type.String(), Type.Number()], { description: "Memory address; decimal or 0xhex" })),
    length: Type.Optional(Type.Number({ description: "Memory bytes, 1-16384; default 256" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("proc", root, {
        session: params.session,
        action: params.action,
        address: params.address,
        length: params.length,
      });
      return responseResult(res, "proc");
    } catch (err) {
      return failure(err);
    }
  },
});

export const claimTool = defineTool({
  name: "claim",
  label: "CTF claim",
  description:
    "Submit an evidence-backed claim to the kernel. Quotes must exactly match a shaped artifact span; the kernel decides Fact/Negative.",
  promptSnippet: "Submit a quote-anchored claim for kernel verification",
  promptGuidelines: [
    "Never submit a claim without a quote from a real artifact.",
    "Use claimType observed/interpreted/differential/time-based.",
    "If the kernel rejects, read the reason and submit new evidence; do not repeat the same signature.",
  ],
  parameters: Type.Object({
    claimType: Type.String({ description: "observed | interpreted | differential | time-based" }),
    text: Type.String({ description: "Claim text, <=2KB" }),
    quotes: Type.Array(
      Type.Object({
        shapedRef: Type.String(),
        span: Type.Optional(Type.Object({ start: Type.Number(), end: Type.Number() })),
        text: Type.String(),
      }),
    ),
    refs: Type.Array(Type.String({ description: "ProcessOutcome ids" })),
    probe: Type.Optional(
      Type.Object({
        purpose: Type.String(),
        expect: Type.String(),
        falsifier: Type.String(),
      }),
    ),
    predicate: Type.Optional(Type.String()),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("claim", root, {
        claimType: params.claimType,
        text: params.text,
        quotes: params.quotes,
        refs: params.refs,
        probe: params.probe,
        predicate: params.predicate,
      });
      return responseResult(res, "claim");
    } catch (err) {
      return failure(err);
    }
  },
});

export const flagTool = defineTool({
  name: "flag",
  label: "CTF flag",
  description:
    "Submit a flag candidate for four-layer validation (format/provenance/evidence/oracle). Requires an accepted Fact or claim id.",
  promptSnippet: "Validate a flag through format, provenance, evidence, and oracle",
  promptGuidelines: [
    "Only call flag after the flag string appears in a stored artifact and a verified Fact/accepted claim exists.",
    "Pass evidenceRefs=[factId or claimId]; never invent a flag.",
  ],
  parameters: Type.Object({
    value: Type.String({ description: "Flag candidate" }),
    evidenceRefs: Type.Optional(Type.Array(Type.String())),
    sourceRef: Type.Optional(Type.String()),
    targetTimeoutMs: Type.Optional(Type.Number({ description: "Target liveness timeout 100-30000ms; default 2000" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("flag", root, {
        value: params.value,
        evidenceRefs: params.evidenceRefs ?? [],
        sourceRef: params.sourceRef,
        targetTimeoutMs: params.targetTimeoutMs,
      });
      return responseResult(res, "flag");
    } catch (err) {
      return failure(err);
    }
  },
});

