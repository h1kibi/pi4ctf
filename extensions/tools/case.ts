/** Case helper tools. */
import { Type } from "typebox";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { RootParam, callRt, failure, lastInjectedByRoot, refreshPreflight, rootFor, responseResult } from "../shared.js";

export const casePlanTool = defineTool({
  name: "case_plan",
  label: "CTF plan",
  description: "Set the case plan (next action, optional chain/preconditions) in the kernel packet.",
  parameters: Type.Object({
    next: Type.String({ description: "Next concrete action" }),
    chain: Type.Optional(Type.Array(Type.String())),
    preconditions: Type.Optional(Type.Array(Type.String())),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.plan", root, {
        chain: params.chain ?? [],
        next: params.next,
        preconditions: params.preconditions ?? [],
      });
      return responseResult(res, "case.plan");
    } catch (err) {
      return failure(err);
    }
  },
});

export const caseRestartTool = defineTool({
  name: "case_restart",
  label: "CTF restart",
  description:
    "Start a fresh 30-execution budget after LIMIT, preserving artifacts, claims, facts, and the negative ledger. Audited and capped.",
  parameters: Type.Object({ root: RootParam }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.restart", root, {});
      return responseResult(res, "case.restart");
    } catch (err) {
      return failure(err);
    }
  },
});

export const caseCloseTool = defineTool({
  name: "case_close",
  label: "CTF close",
  description: "Close the case as failed or stopped. Completed is reserved for case_complete, which requires a verified Fact. Runs are rejected after close.",
  parameters: Type.Object({
    status: Type.Optional(Type.String({ description: "failed | stopped (completed is rejected; use case_complete)" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.close", root, { status: params.status });
      return responseResult(res, "case.close");
    } catch (err) {
      return failure(err);
    }
  },
});

export const artifactIngestTool = defineTool({
  name: "artifact_ingest",
  label: "CTF artifact ingest",
  description:
    "Copy an external evidence file (webhook capture, downloaded response, /tmp log) into .ctf/artifacts and create a synthetic outcome/observation, so claim quotes and flag provenance can use it. The case oracle and .ctf/ are refused. synthetic=true marks dry-run evidence.",
  parameters: Type.Object({
    path: Type.String({ description: "File path, absolute or relative to the project root" }),
    name: Type.Optional(Type.String({ description: "Artifact stem; defaults to a generated name" })),
    transform: Type.Optional(Type.Union([Type.Literal("hex"), Type.Literal("base64")], { description: "Decode source bytes into a derived artifact; source hash is recorded" })),
    synthetic: Type.Optional(Type.Boolean({ description: "Mark this artifact as dry-run/synthetic" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("artifact.ingest", root, {
        path: params.path,
        name: params.name,
        transform: params.transform,
        synthetic: params.synthetic,
      });
      return responseResult(res, "artifact.ingest");
    } catch (err) {
      return failure(err);
    }
  },
});

export const casePreflightTool = defineTool({
  name: "case_preflight",
  label: "CTF preflight",
  description:
    "Scan the challenge root for ELF/libc and identify non-ELF formats, writing .ctf/chal.json. Root files are unclassified; only workspace/ and includeBuild output dirs are generated; no mtime/suffix guessing; both requested dirs are scanned before the root; returns rootFiles/generated arrays. Static only; no exploit strategy.",
  promptSnippet: "Collect static challenge metadata into .ctf/chal.json",
  promptGuidelines: [
    "Run case_preflight after init or when the challenge directory changes.",
    "Put generated binaries/screenshots/unpacked output in workspace/ or build/; root files are unclassified attachments.",
    "Use its build-id/libc metadata to select the matching runtime; do not assume a writeup offset.",
  ],
  parameters: Type.Object({
    includeWorkspace: Type.Optional(Type.Boolean({ description: "Also scan workspace/ (agent-generated files); default ignores it" })),
    includeBuild: Type.Optional(Type.Boolean({ description: "Also scan build/out/dist/target/obj/__pycache__/screenshots/shots as generated" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.preflight", root, { includeWorkspace: params.includeWorkspace, includeBuild: params.includeBuild });
      if (res.ok) lastInjectedByRoot.delete(root);
      return responseResult(res, "case.preflight");
    } catch (err) {
      return failure(err);
    }
  },
});

export const caseClearNegativesTool = defineTool({
  name: "case_clear_negatives",
  label: "CTF clear soft negatives",
  description:
    "Clear transient/soft negative-ledger entries without resetting the command budget. Hard blocks are kept.",
  parameters: Type.Object({ root: RootParam }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.clearNegatives", root, {});
      return responseResult(res, "case.clearNegatives");
    } catch (err) {
      return failure(err);
    }
  },
});


export const caseConfigureTool = defineTool({
  name: "case_configure",
  label: "CTF configure project",
  description:
    "Repair flagFormat, oracleRef, dockerImage, and/or target, then pin the current oracle file contents. Validates target reachability and oracle binding. Backend and allowedHosts are user decisions; use /ctf configure for those.",
  parameters: Type.Object({
    flagFormat: Type.Optional(Type.String({ description: "Regex; omit to keep current" })),
    oracleRef: Type.Optional(Type.String({ description: "Relative oracle path; omit to keep current" })),
    dockerImage: Type.Optional(Type.String({ description: "Docker image; only applies when the case already uses docker" })),
    target: Type.Optional(Type.Union([
      Type.String({ description: "host[:port] or URL" }),
      Type.Object({
        host: Type.String(),
        port: Type.Optional(Type.Number()),
        protocol: Type.Optional(Type.String()),
        instanceId: Type.Optional(Type.String()),
        url: Type.Optional(Type.String()),
      }),
    ])),
    targetTimeoutMs: Type.Optional(Type.Number({ description: "Target TCP check timeout 100-30000ms; default 2000" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.configure", root, {
        flagFormat: params.flagFormat,
        oracleRef: params.oracleRef,
        dockerImage: params.dockerImage,
        target: params.target,
        targetTimeoutMs: params.targetTimeoutMs,
      });
      if (res.ok) await refreshPreflight(ctx, root, true);
      return responseResult(res, "case.configure");
    } catch (err) {
      return failure(err);
    }
  },
});

export const caseEvidenceTool = defineTool({
  name: "case_evidence",
  label: "CTF read evidence",
  description:
    "Read a bounded, UNTRUSTED_DATA-wrapped excerpt of a parent outcome or child evidence item. Accepts cmd-0001 or cmd-0001.0003; supports grep/context/maxMatches, head/tail, or offset/limit; a probe-batch parent returns children, and grep on it searches all children.",
  parameters: Type.Object({
    ref: Type.String({ description: "cmd-0001 or cmd-0001.0003" }),
    stream: Type.Optional(Type.String({ description: "stdout | stderr (default stdout)" })),
    offset: Type.Optional(Type.Number({ description: "Character offset; default 0" })),
    limit: Type.Optional(Type.Number({ description: "Max 16384; default 2048" })),
    grep: Type.Optional(Type.String({ description: "Regex to search the shaped artifact; returns matches + context" })),
    context: Type.Optional(Type.Number({ description: "Context lines per grep match, 0-5; default 0" })),
    maxMatches: Type.Optional(Type.Number({ description: "Max grep matches 1-100; default 20" })),
    head: Type.Optional(Type.Number({ description: "First N lines instead of offset/limit" })),
    tail: Type.Optional(Type.Number({ description: "Last N lines instead of offset/limit" })),
    root: RootParam,
  }),
  async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
    try {
      const root = rootFor(ctx, params.root);
      const res = await callRt("case.evidence", root, {
        ref: params.ref,
        stream: params.stream,
        offset: params.offset,
        limit: params.limit,
        grep: params.grep,
        context: params.context,
        maxMatches: params.maxMatches,
        head: params.head,
        tail: params.tail,
      });
      return responseResult(res, "case.evidence");
    } catch (err) {
      return failure(err);
    }
  },
});

