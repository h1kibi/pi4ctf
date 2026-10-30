# ADR 0001 — Grounded belief, negative knowledge, bounded context

- Status: proposed (debate round 2 converged; pending prototype)
- Date: 2026-10-24
- Context: `debate/round1-zcode.md`, `debate/round1-omp.md`, `debate/round2-zcode.md`, `debate/round2-omp.md`

## Context

pi4ctf 的 v1 设计把 Fact 作为状态核心，但当前 `case fact` 仍允许模型写 `description` + `commandId`，`verify` 事后置位。问题是：

- `commandId` 只证明命令跑过，不证明模型对输出的解释正确；
- 同模型 verifier 与 solver 错误相关，容易变成验证剧场；
- 2-context portfolio 只合并 verified Fact，会丢掉 rejected 路线的负知识；
- context packet 如果塞入过多历史，会触发 context rot；
- 预算以 turn 为主，忽略 token 与 wall-clock。

ZCode 答辩指出：vuln/cred 类结论本质是解释，不能全量代码推导；应做 Observation / Hypothesis / Fact 分层，加引文锚定与谓词持有权。这个批评成立。

## Decision

### 1. 三层 belief

- **Observation**：代码产物。`commandId`、exit、artifact、sha256、可解析字段（HTTP 状态、ELF 元数据、端口、长度差）。全信，但不是结论。
- **Hypothesis**：模型解释。必须带 `quotes[]`（artifact 中的行级/子串引文）；代码校验引文存在且属于同一 artifact。
- **Quote 反证**：内核把每条引文扩展到所在输出块（±5 行）做确定性反证扫描：`exit != 0`、stderr 非空、期望字段缺失即拒。高风险项不验引文、验结论：独立 verifier 看**不含模型引文**的全文 artifact，必须独立复推同一结论。`counter_quotes` 由 verifier 在分歧时生成，不由模型自报。
- **Fact**：由 predicate 或独立 verifier 从 Observation + Hypothesis 推导。`claimType` 决定验证强度：
  - `observed`：代码解析；
  - `interpreted`：引文包含 + 反证扫描 + 谓词；
  - `exploit` / `cred` / `flag`：代码 probe 优先；无 oracle 的 vuln 类用与 solver 异族的 verifier。

### 2. Predicate registry

- 内核维护 `predicates.json`，最小 schema：
  ```json
  { "id": "...", "semver": "...", "claimType": ["exploit"], "requiredEvidence": ["artifact", "exit"], "check": "probe|parse|verifier" }
  ```
- 版本化 = append-only：旧版本保留可重放，fixture 随版本冻结。
- capability 可注册 predicate，但必须带 fixture；verify 时内核拒绝未注册 id。
- 模型不能发明 predicate，也不能自选弱验证。
- 高风险项由内核重跑探针，不采信模型自选命令。

### 3. Negative ledger

`rejected` Intent 必须产生负面记录：

```json
{
  "signature": "http://host/admin?id=*",
  "attempts": 3,
  "lastAttemptAt": "2026-10-24T12:20:00+08:00",
  "failureClass": "timeout|nonzero-exit|no-output|schema-mismatch|probe-contradicted",
  "transient": true,
  "unblockOn": "ttl|env_change|probe",
  "expiresAt": "2026-10-24T12:30:00+08:00",
  "blockScope": "route|case",
  "artifactRef": "artifacts/cmd-0021.log",
  "route": "i0004",
  "next": "header injection / time blind"
}
```

- `signature` = 规范化命令模板 + 目标 + intent 类。
- `failureClass` 由代码判定，不允许模型写，否则负面账本退化成自评。
- **时间维度**（ZCode round 1 反对）：只对 `transient=false` 的精确命中硬阻断；`transient=true` 用 TTL 或 `env_change`/probe 解阻。
- `transient` 按 commandClass + failureClass + probe 判定：
  - `timeout` / 契约要求输出但 `no-output`：默认 true，TTL 10 分钟；
  - `nonzero-exit`：默认 true，`unblockOn=probe`，除非 predicate 明确它是确定性失败；
  - `schema-mismatch` / `probe-contradicted`：默认 false，但 `env_change` 可解阻；
  - `no-output` 且 exit=0 且契约不要求输出：不算 failure。
- `blockScope` 默认 `route`；只有跨路线重复的确定性失败才升到 `case`。
- 解阻写 `unblocked: {signature, reason}` 事件，可审计；不能静默解阻。
- `handoff.md` 必须包含：verified Facts、negative ledger、open hypotheses + confidence、next action。fresh context 先读 handoff + `case.status`，不读旧 transcript。

### 3.1 Observation ownership

`run/exec` 只产出通用 Observation：

- `id`, `argvTemplate`, `target`, `intentClass`, `exit`, `durationMs`
- `stdout` / `stderr`：raw + shaped + sha256 + bytes
- `failureClass`（可为 null）、`failureDetail`、`ts`

`parsed` 字段不放进 exec；由 capability/predicate 生成 `ParsedObservation`，exec 保持题型无关。`signature` 与 shaped 块边界同源，避免两处漂移。

### 4. Serial restart first, portfolio later

- v1：单 context + 串行 restart；触发条件由代码指标决定：3 次同签名 / route token 超支 / error spike / goal violation。
- 2-context portfolio 与 dispatch 一起放 M5 A/B；启用判据是“串行 restart 的 recovery rate 达标但超 deadline”。
- 不把“连续 2 轮无新 Fact”作为触发条件。

### 5. Bounded context packet

目标 ≤16KB（约 4–5k tokens），不是 10 × 16KB：

- stable prefix：mission / flag format / target / constraints / budget ≤2KB
- verified Facts：≤4KB
- open hypotheses：≤6 条，≤1KB
- negative ledger：≤2KB
- queue head + next 2：≤1KB
- recent observations：5 条 × ≤2KB = ≤10KB
- budget：≤0.5KB

超限丢弃顺序：先旧 observation（artifact 永存、可按引重读），再低置信 hypothesis；Facts 与 negative ledger 永不丢，只做 merge 压缩。细节用 artifact 引用，不内联全文。

### 6. Token/wall-clock budgets

- 每 Intent 有 token / turn / wall-clock 预算；总预算只是上限。
- async wait 计 wall-clock，不只计 turn。
- 进度由代码判定：verified Fact / 1k tokens、unique signatures、error rate、goal violation。
- 只有代码指标改善才延长；模型自评不算。

### 7. No A2A for the debate

- 两个 CLI、共享仓库、人当裁判；文件就是协议。
- 现在上 A2A 与 Rust 一样，是把基础设施放在问题之前。
- 以后要自动多轮，最小 orchestrator 是循环脚本：读 brief → 按序 spawn 双方（只读）→ 收 markdown → 无新反对或轮数上限即停。
- 状态就是 `debate/` 里的文件，无消息总线。

## Consequences

- `case` 的 `fact` action 需要拆成 `observe` / `hypothesize` / `verify`，或保留 `fact` 但强制 `quotes[]`。
- `complete` 只接受 verified Fact；`flag` 仍走四层。
- `handoff` schema 增加 negative ledger 与 open hypotheses。
- Context compiler 必须先实现 bounded packet，不能先做 2-context。
- Rust 后置；1–2 周 TS walking skeleton，冻结 `.ctf/` schema 与整形 fixture。

## Acceptance (15 题开发集, same model/budget, ≥3 seeds)

1. 50 条 Fact 人审“引文是否支撑结论”，误判率下降 ≥30%。
2. 伪 complete = 0；主动绕过尝试也失败。
3. kill session 后恢复，重复已试签名率 <10%。
4. solve 不劣于 B2（容差内）。
5. context packet 中 raw log / verified fact 比例下降，solve 不降。

## Open questions

- 5 条 recent observation 是否足够调试链？
- quotes 反证扫描的误杀率？
- 异族 verifier 的成本/收益？
- 签名门是否过度阻断合法重试？
- 16KB packet 在 15 题上的 solve 是否不劣于 B2？

## References

- `debate/round1-zcode.md`
- `debate/round1-omp.md`
- `debate/brief.md`
- `docs/archive/final-design.md`
- `docs/kernel-design.md`
