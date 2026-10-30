# ADR 0002 — Exec / Observation contract, two-stage failure classification

- Status: proposed (debate exchange round 3; pending prototype)
- Date: 2026-10-24
- Context: `exchange/omp/2610241242`, `exchange/zcode/2610241236`, `docs/adr/0001-grounded-belief.md`

## Context

ADR 0001 让 Fact 从 Observation/Hypothesis 推导，但 `run/exec` 如果直接判语义失败，会有两类错误：

1. **错误阻断**：`timeout` / `no-output` 进入 negative ledger 后永久硬阻断，服务恢复也无法重试。
2. **错误放行**：`curl` 返回 500/403/429、exit=0，若 exec 判 `failureClass=null`，路线持续“成功”烧预算，永远不触发签名门。

同时，`parsed` 字段如果放进 exec，exec 会变成题型解析器；如果不给 parsed 字段溯源，模型 quote 与 parsed 事实无法对账。

## Decision

### 1. Three stages

```text
Stage A: exec -> ProcessOutcome
  id, argvTemplate, target, intentClass, exit, durationMs,
  stdout.raw/shaped, stderr.raw/shaped, ts,
  processFailure: timeout | nonzero-exit | no-output-when-expected | null

Stage B: capability -> Observation
  contract: expectOutput?, expectedStatus?, schemaId?, commandClass?
  parsed fields + semanticFailure:
    schema-mismatch | probe-contradicted | server-error | client-blocked | null

Stage C: predicate/ledger -> final
  Fact / Negative / rejected
```

Rules:

- `exec` does not judge semantics; `ProcessOutcome` is not an Observation.
- `contract` is data owned by the capability; the model cannot choose a weaker contract for a known `commandClass`.
- Generic `run` has no contract → `semanticFailure=unknown`; it cannot produce a Fact without a verifier.
- Negative ledger write happens in Stage C, not at exec return.
- Both stages emit events; the event stream can replay the classification.

### 2. Parsed provenance

Each parsed field carries:

```json
{ "value": 500, "shapedRef": "artifacts/cmd-0021.log", "span": { "start": 120, "end": 123 } }
```

- `span` is a character offset in shaped text, not a line number; works for minified output.
- Hypothesis `quotes[]` uses the same span format; code checks `quote == shaped[start:end]`.
- Parsed fields and quotes can cross-check: a quote claiming `500` must match `http.status=500`.

### 3. Shaped and signature are frozen contracts

- `shape@1` is deterministic; any change requires a new golden fixture and a parser semver bump.
- Parsers read shaped, not raw; quotes anchor shaped.
- stdout/stderr are separate; quote expansion never crosses streams.
- `signature@1` normalization is its own spec + fixture: which argv values become `<v:n>`, which remain literal.

### 3.2 Differential A/A

- DifferentialObservation is produced by the capability layer; baseline and probe are both `ProcessOutcome`.
- Baseline/probe `argvTemplate` must be identical except declared `<v:n>` slots.
- A/A gate: baseline vs baseline before claiming a difference; unstable A/A → no differential evidence.
- time-based: even number >=6 (>=3 runs per side), clean outcomes, every outcome on the project's declared target, median; thresholds frozen in predicate fixture.
- Deterministic fast path: only if predicate declares `deterministic=true` and A/A variance is 0; cache key is `(signature, envFingerprint, predicateSemver)`. `signature` already includes target/intentClass. Stochastic/time-based never skip A/A.

### 4. Negative ledger v2

```json
{
  "signature": "...",
  "attempts": 3,
  "lastAttemptAt": "2026-10-24T12:20:00+08:00",
  "failureClass": "timeout|nonzero-exit|no-output|schema-mismatch|probe-contradicted|server-error|client-blocked|command-not-found",
  "transient": true,
  "condemnedBy": "p-http-status@1.0.0",
  "unblockOn": "ttl|env_change|probe|probe_version",
  "expiresAt": "2026-10-24T12:30:00+08:00",
  "blockScope": "route|case",
  "artifactRef": "...",
  "route": "i0004"
}
```

Rules:

- Hard block only when `transient=false`.
- `transient` is code-owned, based on `commandClass + failureClass + probe`.
- `probe_version` unblocks when a newer predicate version exists; write `unblocked` event.
- Per-class retry policy:
  - `timeout` / expected `no-output`: TTL 10m + jitter;
  - `server-error` (5xx): 30s → 2m → 5m;
  - `client-blocked` (403/429/WAF): exponential backoff + jitter; canary before retry; escalate `blockScope` if the block worsens;
  - `schema-mismatch` / `probe-contradicted`: permanent unless `probe_version` / `env_change`.
- `blockScope` defaults to `route`; only cross-route deterministic failures escalate to `case`.
- `unblocked: {signature, reason}` is auditable; no silent unblock.

### 5. Environment change producer

`env.probe` produces `env_change` only when:

- target fingerprint changes: banner/version, port liveness, TLS cert, key headers;
- two consecutive probes, ≥30s apart, agree on the change;
- the change is not caused by the agent's own exploit command (debounce/stability window).

`env_change` is an event; the signature gate consumes it.

### 6. Wrong flag is a flag-ledger event, not a signature block

- Rejected flags go to `flags.jsonl` as `flag.rejected` with value hash, source, oracle.
- Same flag value is blocked at case scope; different flag values are not.
- Only oracle-passing flags become accepted; `flag.txt` only after four layers.

### 7. Exchange positions

`meta.json` may carry exactly:

```json
"positions": "converged|divergent",
"unresolved": ["stable-slug"]
```

- Self-reported, never the sole stop condition.
- Missing = divergent.
- Stop: both latest positions converged + unresolved empty + human confirmation, or round limit.

## Consequences

- `run` returns a `ProcessOutcome`, not a Fact.
- Capability layer applies contract + parser and emits `Observation`.
- `case.verify`/predicate consumes `Observation` and writes Fact/Negative.
- `exec.ts` is the first implementation; fixtures cover shaping, process failure, provenance, and no-output contracts.
- ADR 0001's negative ledger section is superseded by §4 here.

## Acceptance

- Shaping idempotent: `shape(shape(x)) == shape(x)`.
- Five process failure classes covered with zero model involvement.
- Success-disguised HTTP 500/403/429 fixture produces `semanticFailure`, not `null`.
- Quote span == shaped slice for every fixture; parsed field provenance matches the same span.
- Same signature, different target: no block.
- Timeout signature: soft block, expires; after TTL/probe/env_change, unblocked event.
- Wrong flag: case-scope block only for same value; different value retried.
- All artifacts hashed; secret scan zero hits (except explicit decoy fixture).

## Open questions

- Default contract registry by commandClass vs explicit capability contract: safety vs magic.
- Env stability window: 30s / two probes enough? 60s?
- Does `server-error` ever deserve a route-scope hard block after N attempts?
- How to audit `probe_version` unblock without re-running the original exploit?

## References

- `exchange/omp/2610241242/content.md`
- `exchange/zcode/2610241236/content.md`
- `docs/adr/0001-grounded-belief.md`
- `debate/design-v2-outline.md`
