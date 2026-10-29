# pi4ctf Design v2

> Status: **历史归档**。机制面曾被 [`design-v2-core.md`](design-v2-core.md) 收紧；当前施工基线是 [`../design.md`](../design.md)。
> 本文保留完整研究与细节，不再作为施工依据。
>
> **One ledger. One compiler. One loop. Three tools.**
>
> 代码拥有 belief，模型只提案；上下文是投影，不是日志；挑战材料默认不可信。

---

## 0. 与 v1 的变化

v2 不是加功能，而是把 v1 的隐含假设收紧：

| v1 | v2 |
|---|---|
| Fact 由模型写 + commandId | Observation 代码产出；Hypothesis 带 quote；Fact 由 predicate/verifier 推导 |
| exec 直接判失败 | 两阶段：exec 只判进程级；capability 判语义；predicate 写账本 |
| 签名门永久阻断 | transient / TTL / env_change / probe_version / 一次性重试票 |
| Fact/negative “永不丢，merge 压缩” | store 永不丢；packet 只放 digest，丢 digest 不丢 Fact |
| ±5 行引文 | shaped block + 字符 span |
| packet 与 handoff 两套结构 | 一个 compiler；handoff = packet + resume 指针 |
| 16KB 当真理 | token 预算；bytes 只是代理 |
| 默认单 context | 串行 restart 先做；2-context 后置 A/B |
| Rust 先行 | TS walking skeleton 先做；冻结契约后再 Rust |

---

## 1. 分层

```text
pi host
  └─ adapter: 3 tools, skill, TUI, hooks
       └─ kernel (TS prototype → Rust later)
            ├─ ledger: ProcessOutcome / Observation / Hypothesis / Fact / Negative / Intent / Flag
            ├─ context compiler: bounded packet + resume
            ├─ exec / session / jobs
            ├─ predicate + command-contract registries
            └─ flag + memory
       └─ .ctf/ (events, artifacts, projections)
  └─ host / WSL2 / external tools / MCP
```

原则：

- kernel 不做推理、不调用 LLM；只做状态、执行、证据、投影。
- adapter 不写状态；只做 schema、prompt 注入、TUI。
- skill 只做策略；不执行命令。
- external tools 不可信；通过 `run`/`session` 或 capability 接入。

---

## 2. 核心循环

```text
Frame
  mission + context packet + one active Intent
    ↓
Predict
  action + expected observation + falsifier
    ↓
Act
  run / session
    ↓
Observe
  ProcessOutcome -> Observation (contract + parser)
    ↓
Classify
  process failure vs semantic failure
    ↓
Reconcile
  match -> Fact; mismatch -> Negative / rejected
    ↓
Re-anchor
  goal / budget / drift check -> next Intent or restart
```

这不是“Reason → Explore”的软循环；每次动作都带预测，每次观察都能证伪。

---

## 3. 数据模型

### 3.1 ProcessOutcome（exec 产出，不是 Fact）

```json
{
  "id": "cmd-0021",
  "argvTemplate": ["curl", "-s", "http://host/<v:1>"],
  "target": "host:80",
  "intentClass": "http-probe",
  "exit": 0,
  "durationMs": 412,
  "stdout": { "raw": "artifacts/cmd-0021.stdout.raw", "shaped": "artifacts/cmd-0021.stdout.log", "sha256": "...", "bytes": 1200 },
  "stderr": { "raw": "artifacts/cmd-0021.stderr.raw", "shaped": "artifacts/cmd-0021.stderr.log", "sha256": "...", "bytes": 0 },
  "processFailure": null,
  "ts": "2026-10-24T12:00:00+08:00"
}
```

`processFailure`: `timeout | nonzero-exit | no-output-when-expected | null`。exec 不判语义。

### 3.2 Observation（capability 产出）

```json
{
  "id": "obs-0021",
  "process": "cmd-0021",
  "contract": "contract-http@1.0.0",
  "parsed": {
    "http.status": { "value": 500, "shapedRef": "artifacts/cmd-0021.stdout.log", "span": { "start": 120, "end": 123 } }
  },
  "semanticFailure": "server-error",
  "failureDetail": "status=500"
}
```

- `parsed` 每个字段带 `{value, shapedRef, span}`；span 是字符偏移，不是行号。
- `semanticFailure`: `schema-mismatch | probe-contradicted | server-error | client-blocked | null`。

### 3.3 Hypothesis

```json
{
  "id": "h0004",
  "text": "/admin 存在 boolean blind SQLi",
  "quotes": [
    { "shapedRef": "artifacts/cmd-0011.stdout.log", "span": { "start": 40, "end": 96 } }
  ],
  "confidence": 0.6
}
```

- quote 文本必须等于 `shaped[start:end]`；否则拒绝。
- quote 只证“文本存在”，不证“结论成立”；结论归 Fact。

### 3.4 Fact

```json
{
  "id": "f0012",
  "claimType": "differential",
  "predicate": "http.length_delta@1.0.0",
  "value": { "baseline": 800, "probe": 1200, "delta": 400 },
  "observationRefs": ["obs-0021", "obs-0022"],
  "status": "verified",
  "condemnedBy": null
}
```

`claimType`: `observed | interpreted | differential | exploit | cred | flag`。

### 3.5 DifferentialObservation

```json
{
  "id": "diff-0003",
  "baseline": "obs-0021",
  "probe": "obs-0022",
  "controlledBy": "http.param:<v:1>",
  "delta": [
    { "field": "length", "baselineVal": 800, "probeVal": 1200, "baselineRef": "...", "probeRef": "..." }
  ],
  "aaGate": { "stable": true, "runs": 2, "variance": 0 }
}
```

- baseline/probe 的 `argvTemplate` 必须相同，只差声明的 `<v:n>` 槽。
- A/A 门：先跑 baseline vs baseline；不稳定 → 不产生 differential 证据。
- time-based：每侧 ≥3 次取中位数；阈值冻结在 predicate fixture。
- 确定性快路径：predicate 声明 `deterministic=true` 且 A/A 方差 0 时，A/A 结果按 `(signature, envFingerprint, predicateSemver)` 缓存 10 分钟。`signature` 已包含 target/intentClass，不要再重复 target；predicate 版本变化必须使缓存失效。

### 3.6 NegativeEntry

```json
{
  "signature": "http://host/admin?id=<v:1>|host:80|http-sqli",
  "attempts": 3,
  "lastAttemptAt": "2026-10-24T12:20:00+08:00",
  "failureClass": "client-blocked",
  "transient": true,
  "condemnedBy": "contract-http@1.0.0",
  "unblockOn": "ttl|env_change|probe|probe_version",
  "expiresAt": "2026-10-24T12:30:00+08:00",
  "blockScope": "route",
  "artifactRef": "artifacts/cmd-0021.log",
  "route": "i0004"
}
```

- 硬阻断只对 `transient=false`。
- `transient` 由 commandClass + failureClass + probe 判定。
- per-class retry：timeout TTL 10m；5xx 30s→2m→5m；403/429/WAF 指数退避 + jitter + canary；schema/probe permanent 但 `probe_version`/`env_change` 可重评。
- `blockScope` 默认 route；跨路线确定性失败才升 case。
- `unblocked: {signature, reason}` 事件可审计。

### 3.7 Intent

```json
{
  "id": "i0004",
  "hypothesisId": "h0004",
  "prediction": "true/false 响应长度差 > 10%",
  "falsifier": "两者长度一致或都 403",
  "budget": { "tokens": 12000, "turns": 6, "wallClockSec": 600 },
  "state": "active"
}
```

### 3.8 Flag

- `flags.jsonl`：candidate / recorded / submitted / accepted / rejected。
- rejected 只存 hash + source + oracle；同值 case 级阻断。
- accepted 明文只在内核提交通道内存在；不落 artifact、不进 packet。
- 四层：格式 → 溯源 → oracle → 去重/decoy。

### 3.9 SessionObservation

```json
{
  "id": "sess-obs-001",
  "session": "s1",
  "seq": 42,
  "block": "artifacts/session-s1.log:block-42",
  "state": "alive|exited",
  "parsed": { "prompt": true, "bytes": 120 }
}
```

v1 预留接口；M2 实现交互题 observation。

---

## 4. 两阶段分类与契约

```text
Stage A: exec -> ProcessOutcome
Stage B: capability -> Observation (contract + parser)
Stage C: predicate/ledger -> Fact / Negative / rejected
```

### R1 / R2

- **R1 证据期望**：capability 声明什么算成功、产出什么证据；模型可影响，但每次覆盖写 `contract.override`。
- **R2 危险检测**：5xx / 403 / 429 / WAF 从 parsed 状态字段**无条件**派生，归内核；不依赖声明。
- 弱于注册表下限的 contract **钳制到下限**，写 `contract.clamped`；N 次 clamp 计入 restart 指标。
- generic `run` 无 contract → `semanticFailure=unknown` → 必须 verifier。

`command-contracts.json` 与 `predicates.json` 同构：append-only、semver、fixture、内核注册。首批：`curl`/`wget`、`nmap`、`sqlmap`、`file`/`binutils`。

---

## 5. Context compiler

### 5.1 预算

以目标模型 tokenizer 计数；16KB 只是默认代理。默认约 4–5k tokens。

| 块 | 预算 | 内容 |
|---|---|---|
| Mission | ≤2KB | goal / flag format / target / constraints / deadline |
| Verified Facts | ≤4KB | 按 kind 分组，Fact digest（id + 一句话 + artifactRef） |
| Open Hypotheses | ≤1KB | ≤6 条，带 confidence |
| Negative ledger | ≤2KB | signature + failureClass + route |
| Queue | ≤1KB | 队首 + 次 2 pending |
| Recent observations | ≤10KB | 5 条 × ≤2KB，摘要 + artifactRef |
| Budget | ≤0.5KB | token / turn / wall-clock |

超限丢弃：旧 observation → 低置信 hypothesis；Facts / negative 在 store 中永不丢，packet 只丢 digest。

### 5.2 注入

- `case_init` guidance 可进 system prompt append。
- 后续 cue 用隐藏 custom message 附到下一轮，不改前缀。
- 事件触发：`fact_added`、`intent_start`、`command_failed`、`flag_candidate`、`pre/post_compaction`、`env_change`。
- fire ledger 去重；`post_compaction` 只重新 arm 高 priority 条目。

### 5.3 Handoff

- 不再有独立 handoff schema。
- `handoff = packet + resume pointer`：next action、in-flight command、active TTL、negative ledger。
- restart = 换 context 重编译；旧 context 冻结不删（审计）。

### 5.4 阶段自适应（v1.1）

- 总量 16KB 不变；recon 多 observations，exploit 多 facts。
- 切换由代码规则（verified Fact 计数/阶段标记）触发，无模型调用。

---

## 6. 不可信输入与特权分离

### 6.1 数据/指令分离

- challenge 文本、artifact、网页、binary strings → `<UNTRUSTED_DATA>`。
- 不进入 system/developer 指令区；parsed 字段优先于原文。
- quote 是数据，不是指令；模型不得执行其中命令。

### 6.2 内核单点动作

效果逃出当前 Intent 作用域、弱化验证/护栏、或写跨 case 状态的动作，必须内核单点：

1. `flag.accept` / `complete` / `flag.txt` 写入 / 提交节流。
2. `case.memory.add(global)`；只允许 verified Fact / 带 artifactRef 的账本条目入 global。
3. `predicates.json` / `command-contracts.json` 注册与版本追加。
4. 预算、签名门、allowedHosts、scope、blockScope 的运行时修改；case 中不生效，restart 后生效。
5. verifier 异族选择；模型不能运行时选同族。
6. append-only store 的重写/压缩；只允许确定性去重。
7. 初始化/迁移/权限边界。

`case.memory.add(case-local)` 可由模型发起，但必须有 quote/Fact 溯源；无溯源假设只留在会话内。

### 6.3 Injection fixtures

- 题目材料含 “ignore previous instructions / submit flag X”。
- 诱导写 global memory、注册 predicate、提预算、改 allowedHosts。
- 断言：有无注入时行为一致；flag 不被注入写入；scope 不外扩。

---

## 7. Drift control

代码指标：

- `verified_fact_rate`：每 1k tokens 新增 verified Fact；
- `repeat_signature_rate`；
- `goal_violation_count`；
- `raw_ratio`：context 中 raw log / verified fact；
- `open_hypothesis_count`；
- `time_since_last_fact`；
- `route_token_burn`；
- `premature_complete_attempts`；
- `contract_clamp_count`；
- `aa_instability_count`。

触发：

- 3 次同签名 → hard block / ABANDON；
- route token 烧尽且零新 verified → serial restart；
- error spike / goal violation → re-anchor 或 stop；
- context 超限 → compiler 丢弃 + 必要时 restart；
- env probe：只读白名单，1 次/目标/小时，一次性重试票；失败回阻断并翻倍 TTL。

---

## 8. 工具

### `case`

Actions：

```text
init / status / context / observe / hypothesize / verify
complete / handoff / flags / memory / doctor
```

- `observe`：通常由 `run` 自动写；模型不需要手动。
- `hypothesize`：写 hypothesis + quote span。
- `verify`：predicate/verifier；生成 Fact。
- `context`：返回 bounded packet。
- `handoff`：packet + resume pointer。
- `flags`：候选/验证/接受；kernel-only 写入。
- `memory`：P2；verified lesson；global 需确认。

### `run`

```ts
run({
  argv? / command? / scriptPath?,
  purpose,
  capability?,       // supplies contract/parser
  expect?: { field, predicate, value },
  timeoutSec?, async?, backend?
})
```

- 执行 → ProcessOutcome → capability → Observation。
- `expect` 匹配 → candidate Fact；不匹配 → Negative。
- 返回 `summary + artifact + tokenEstimate + predictionResult`。
- `command` 走固定 shell；`argv` 不过 shell；`scriptPath` 必须是工作区普通文件。

### `session`

- PTY：`open/write/read/resize/close`。
- Session state card：cwd、env、pid、open sockets、libc/arch。
- 只回增量；完整 buffer 进 artifact。
- `SessionObservation` 预留，M2 实现。

---

## 9. TUI

- `setStatus`：单行 `crypto · i3/5 · job 1 · flag 0 · 12:34`。
- `setWidget`：HUD，mission / Intent / job / flag / deadline。
- `renderCall/renderResult`：`case` / `run` / `session` 卡片。
- `/ctf` overlay：Case / Queue / Facts / Hypotheses / Negative / Artifacts / Env。
- 只读；headless 无影响；用 pi TUI，不自建 renderer。

---

## 10. Memory（P2）

- 文件型 verified lesson；默认 off；project 可开；global 显式。
- cue 驱动注入；2KB；provenance/staleness/fire ledger。
- 不做 embedding/SQLite/后台 LLM；lesson >500 再评估 FTS5。
- 只存条件 + insight + 证据；不存 flag/transcript。

---

## 11. Kernel / Rust

- 先 TS walking skeleton；冻结：
  - 事件 schema、artifact 命名、shape@1、signature@1、predicate/contract semver。
- Rust 后置；只下沉 PTY、process group、artifact、job、flag。
- Rust 必须过同一套 fixture；TS 与 Rust 不双实现。

---

## 12. 评测

### 12.1 集合

- 15 题开发集：调参、消融。
- cybench 静态锚 10 题：web 3 / crypto 3 / forensics 2 / rev 2 / misc 0；FST 3 easy / 4 mid / 2 harder / 1 hardest；manifest 钉死。
- cybench 交互锚 5 题：M2 SessionObservation 后；pwn 2 / rev 3。
- CTFTiny 50：发布评测。
- live CTF：外部复核。

### 12.2 基线

- B0：裸模型 + skill。
- B1：3 工具 + 线性 route board。
- B2：+ free-text facts。
- B3：+ grounded Observation/Hypothesis/Fact。
- B4：+ differential/A-A。
- B5：+ negative ledger / transient gate。
- B6：+ context compiler / serial restart。
- B7：+ 2-context / UCT（后置）。
- C0：full history；C1：compiled packet；C2：packet + restart；C3：2-context。

### 12.3 指标

solve、false Fact、false flag、repeat signature、drift rate、recovery rate、tokens-to-solve、wall-clock-to-solve、packet tokens、quote-support error、premature complete、injection pass rate、contract clamp count。

- 同模型/预算/3 seeds；外部锚用分类别解决率，不拿 10 题子集直接比 40 题聚合。
- B1 playbook 早测：M2 后静态锚上带/不带 playbook。
- 负控制：随机 Fact、stale negative、注入 fixture、错误 libc。

---

## 13. 里程碑

| 阶段 | 交付 | 验收 |
|---|---|---|
| M0 | ledger/store、事件流、artifact、state | 原子写；重放一致 |
| M1 | exec/ProcessOutcome、shape、Observation、contract | 整形幂等；两阶段分类 |
| M2 | session/SessionObservation、differential/A-A、flag | 交互题；A/A 门；flag 四层 |
| M3 | context compiler/packet、handoff、adapter 3 tools | 16KB/token 预算；cache |
| M4 | loop/e2e、negative ledger、serial restart | 1 题端到端；恢复 |
| M5 | TUI、injection fixtures、kernel-only gates | 交互可用；注入行为一致 |
| M6 | 15 题 A/B、cybench 静态锚、playbook 早测 | 数据报告 |
| M7 | CTFTiny 50、Rust 下沉、性能 | 发布门槛 |

---

## 14. 风险与非目标

风险：

- 契约/谓词过度“魔法”：用 append-only + fixture + clamp 事件压。
- A/A 成本：确定性快路径 + 缓存；stochastic 不跳过。
- tokenizer 不一致：目标模型计数；bytes 只代理。
- 注入仍可能影响模型：特权分离 + 内核单点 + fixture；不能只靠 prompt。
- cybench 子集小：分类别对照 + 钉 manifest，不刷聚合。
- 3 工具但 `case` 很胖：内部 action handler 拆分，公开面保持 3。
- TS 原型漂移：冻结 schema/fixture，Rust 过同一套。

非目标：

- 不默认 2-context / swarm / A2A。
- 不先写 Rust。
- 不做全局 vector memory / 后台 LLM consolidation。
- 不做 31 工具 / 插件市场。
- 不做 auto-submit / 通用安全 Harness。

---

## 15. 第一版 walking skeleton

顺序：

1. `ledger/store.ts`：JSONL 事件 + append-only + hash。
2. `run/exec.ts`：child_process + raw/shaped + ProcessOutcome。
3. `ledger/shape.ts`：shape@1 + signature@1 + fixture。
4. `ledger/predicates.ts` + `command-contracts.json`：R1/R2、clamp。
5. `context/packet.ts`：token 预算、块、丢弃序。
6. `restart/handoff.ts`：packet + resume + negative ledger。
7. `flag/ledger.ts`：四层、decoy、throttle。
8. `adapter`：3 工具、prompt 注入、TUI。
9. `eval`：15 题 + cybench 静态锚。

第一交付验收：

- shape 幂等；5 类 process failure；HTTP 500/403/429 不被当成功；
- quote span == shaped slice；parsed provenance 一致；
- 同签名不同 target 不互相阻断；timeout 软阻断可解；
- 伪 complete=0；注入 fixture 行为一致；
- packet ≤ 预算；Facts/negative 在 store 不丢。

---

## 16. 来源

- `exchange/omp/2610241212..1253`、`exchange/zcode/2610241221..1248`
- `debate/round1-*`、`debate/round2-*`、`debate/design-v2-outline.md`
- `docs/adr/0001-grounded-belief.md`、`docs/adr/0002-exec-observation-contract.md`
- cybench `arXiv:2408.08926`；EnIGMA `arXiv:2409.16165`；Context Rot (Chroma 2025)；Anthropic context engineering (2025)；ExpeL `arXiv:2308.10144`；LATS `arXiv:2310.04406`；OWASP GenAI LLM Top 10 2025。
