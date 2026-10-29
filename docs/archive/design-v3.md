# pi4ctf Design v3

> **施工基线（2026-10-24 冻结）。** 本文合并五轮辩论、less-is-more 审计与 ARTEX 源码审计的结论；旧文档保留为历史/研究。
>
> **已被 [`design.md`](../design.md) 统一取代**；本文的 4 动词 / 5 机制 / 4 记录是统一设计的内核来源。
>
> **4 动词 · 5 机制 · 4 记录。**
>
> 代码拥有 belief，模型只提案；上下文是投影，不是日志；挑战材料默认不可信。

---

## 0. 定位

pi4ctf 不是通用安全 Harness，也不是 CTF 平台。

它是一个跑在 pi 上的 **CTF 解题内核**：

- 用最小概念集，把 CTF 解题变成可验证、可恢复、可评测的证据循环；
- pi 负责推理、工具调用与 UI；
- kernel 负责状态、执行、证据、上下文投影；
- 工具/环境/TUI/Rust 都是后置实现层。

一句话：

> **一个 ledger、一个 compiler、一个 loop、四个动词。**

---

## 1. 设计原则

1. **代码拥有 belief**：Observation 由代码产生；claim 必须带 quote；Fact 由 predicate/verifier 推导。
2. **Context 是投影**：store 永不丢；packet 只放 digest；handoff = packet + resume。
3. **不可信是默认值**：挑战材料进 `<UNTRUSTED_DATA>`；flag/complete/global memory/scope 变更内核单点。
4. **概念少，不是工具少**：4 动词、5 机制、4 记录；`case` 是内部 API。
5. **复杂度必须证明收益**：没有 fixture 或 A/B 的机制默认 later。
6. **先验知识优先**：playbook/演示是数据，不是第六个机制。
7. **终止条件外置**：flag/oracle、deadline、budget、negative ledger、route drift，不靠模型自评。

---

## 2. 整体架构

```text
pi host
  └─ adapter
       ├─ 4 verbs: run / session / claim / flag
       ├─ skill
       ├─ TUI（later）
       └─ hooks: tool_call / prompt 注入
            │ JSON
            ▼
       kernel（先 TS，后 Rust）
       ├─ exec + shape@1 + signature@1
       ├─ ledger: ProcessOutcome / claim / Fact / NegativeEntry
       ├─ context compiler
       ├─ claim verifier
       └─ flag
            │
            ▼
       .ctf/：events、artifacts、projections
            │
            ▼
       host / WSL2 / 外部工具 / MCP
```

分工：

- kernel 不做推理、不调用 LLM；
- adapter 不写状态；
- skill 只做策略；
- 外部工具不可信，通过 `run`/`session` 接入。

---

## 3. 四个动词

| 动词 | 职责 |
|---|---|
| `run` | 执行命令，返回 ProcessOutcome，自动产出 Observation |
| `session` | PTY 交互，返回 SessionObservation |
| `claim` | 提交解释/断言 + quotes，内核自动验证 |
| `flag` | 提交 flag 候选，内核四层验证 |

`case` 不是模型工具，是内部 API：

- `init / status / context / handoff / doctor` 由 adapter/kernel 调；
- packet 由 adapter 注入；
- restart/handoff 由代码指标触发；
- `complete` 由内核从 verified Fact 判定；
- `flag` 只是申请，不是写入。

---

## 4. 核心循环

```text
Frame        mission + packet + open claims
  ↓
Predict      choose claim / probe + expected observation + falsifier
  ↓
Act          run / session
  ↓
Observe      ProcessOutcome → classify → Observation
  ↓
Reconcile    claim → accepted | rejected
  ↓
Re-anchor    plan / budget / drift → next claim or restart
```

**claim 是工作单元**：一个 claim 既可以是“这里可能有 SQLi”，也可以是“这个 offset 应该能拿到 shell”。  
open claims 构成队列；不需要单独的 Intent 记录。

七步 loop **只存在于 compiler 内部编排**；Frame/Predict/Reconcile 不持久化，不引入 cue/fire ledger。

---

## 5. 四类记录

### 5.1 ProcessOutcome

exec 产出，只有进程事实：

```json
{
  "id": "cmd-0021",
  "argvTemplate": ["curl", "-s", "http://host/<v:1>"],
  "target": "host:80",
  "intentClass": "http-probe",
  "canonicalKey": "http|signature@1:curl -s http://host/<v:1>|shaped:sha256:...",
  "exit": 0,
  "durationMs": 412,
  "stdout": { "raw": "...", "shaped": "...", "sha256": "...", "bytes": 1200 },
  "stderr": { "raw": "...", "shaped": "...", "sha256": "...", "bytes": 0 },
  "processFailure": null,
  "ts": "..."
}
```

- `processFailure`: `timeout | nonzero-exit | no-output-when-expected | null`。
- `canonicalKey = commandClass + signature@1(含 <v:n> 载荷槽) + shapedHash`；模型不能自定义。
- differential / time-based 两条腿豁免合并；去重只作用于 packet/recent 列表与计数，不删 store 行。
- Observation 是 `classify(ProcessOutcome)` 的派生视图，不单独存一条记录。

### 5.2 claim

```json
{
  "id": "c0012",
  "claimType": "differential",
  "text": "boolean blind：true/false 响应长度不同",
  "quotes": [
    { "shapedRef": "artifacts/cmd-0021.stdout.log", "span": { "start": 40, "end": 96 } }
  ],
  "refs": ["cmd-0021", "cmd-0022"],
  "probe": {
    "purpose": "比较 true/false 响应长度",
    "expect": "delta > 10%",
    "falsifier": "两者长度一致或都 403"
  },
  "state": "proposed|checking|accepted|rejected",
  "signature": "differential|...|cmd-0021,cmd-0022"
}
```

- quote 文本必须等于 `shaped[start:end]`。
- accepted → Fact；rejected → NegativeEntry。
- 同一 signature 只有引用新 artifactRef/span 才允许重交；否则硬阻断。
- claim 是队列单元；open claims 进入 packet。

### 5.3 Fact

```json
{
  "id": "f0012",
  "claimId": "c0012",
  "claimType": "differential",
  "predicate": "http.length_delta@1.0.0",
  "classifiedBy": "classify@1",
  "value": { "baseline": 800, "probe": 1200, "delta": 400 },
  "observationRefs": ["cmd-0021", "cmd-0022"],
  "canonicalKey": "http|signature@1:curl ...|shaped:sha256:...",
  "status": "verified"
}
```

### 5.4 NegativeEntry

```json
{
  "signature": "...",
  "attempts": 3,
  "failureClass": "timeout|nonzero-exit|no-output|schema-mismatch|probe-contradicted|client-blocked|server-error",
  "transient": true,
  "expiresAt": "2026-10-24T12:30:00+08:00",
  "artifactRef": "...",
  "route": "c0012"
}
```

实现只做两件事：

- TTL 过期可重评；
- 确定性失败硬阻断。

高级解阻（env.probe、probe_version、一次性票、blockScope）later；schema 可留，不实现。

---

## 6. 执行与分类

不是三个子系统，是两个函数：

```text
exec(cmd) -> ProcessOutcome
classify(cmdClass, shaped) -> fields + semanticFailure
```

- `classify` 是 capability 的函数属性，不是运行时注册表。
- R2 危险检测（5xx/403/429/WAF）是内核 10 行状态码表；模型不能传 `expectedStatus` 放宽。
- generic `run` 无 classify → `semanticFailure=unknown` → 必须 verifier。
- fixture 随 capability 代码走；code review 即治理。
- 不建 `command-contracts.json` 运行时注册表。

---

## 7. Claim 自动验证

```text
proposed -> checking -> accepted | rejected
```

- 便宜谓词：内核同步判定。
- 高风险/无谓词：异族 verifier；模型不能选验证强度。
- `checking` 可异步；packet 显示 pending claims。
- rejected → NegativeEntry；accepted → Fact。
- claim 只处理解释，不处理 observation；Observation 由 `run`/`session` 自动产出。

---

## 8. Context compiler

### 8.1 Packet

默认约 4–5k tokens（16KB 代理）：

| 块 | 预算 |
|---|---|
| Mission：goal / flag format / target / constraints / deadline | ≤2KB |
| Verified Facts digest（id + 一句话 + artifactRef） | ≤4KB |
| Open claims | ≤1KB |
| Negative ledger（最小） | ≤2KB |
| Plan：当前多步链 / 下一步 / 前置条件 | ≤1KB |
| Recent outcomes：5 ×2KB | ≤10KB |
| Budget + playbook digest | ≤0.5KB |

- store 永不丢；packet 只丢 digest。
- 超限先丢旧 observation，再丢低置信 claim；Facts/negative/plan 不丢。
- `plan` 是 packet 块，不是新记录；跨 reset 由 `progress.md` / resume 指针保留。

### 8.2 Handoff

- `handoff = packet + resume pointer`。
- resume：next action、in-flight command、active TTL、open claims。
- restart = 重编译；旧 context 冻结不删。

### 8.3 注入

- `case_init` guidance 可进 system prompt；
- 后续用隐藏 custom message；
- 不维护 cue/fire ledger；只在 revision 变化时重编译。

---

## 9. Session

- PTY：open/write/read/resize/close。
- SessionObservation 是 session 的输出形态，不是独立记录。
- state card：cwd/env/pid/open sockets/libc/arch。
- 只回增量；完整 buffer 进 artifact。
- pwn/rev 交互题不能后置。

---

## 10. 安全横切

- 挑战材料 `<UNTRUSTED_DATA>`；parsed 优先；quote 是数据不是指令。
- kernel-only：`flag` 写入、`complete`、global memory、scope/budget/guardrail 变更。
- 注入 fixture：假 flag、ignore instructions、写 global memory、扩 allowedHosts、直写 flag。
- `tool_call` hook 校验 goal contract；越界阻断并审计。
- 没有 `goal_met` 工具；完成由代码判定。

---

## 11. 从 ARTEX 借的三个插槽

### P0：canonicalKey / 去重

- 模型提交原始 observation；
- 代码按 `canonicalKey = commandClass + signature@1(载荷槽) + shapedHash` 去重；
- differential / time-based 两条腿豁免合并；
- 去重只作用于 packet/recent 列表与计数，不删 store 行；
- 不新增记录类型，只加字段；
- 收益：减少重复扫描、重复 Fact、重复 packet。

### P1：plan scratchpad

- packet 的 `plan` 块：当前多步链、前置 Fact、下一步；
- 跨 context reset 保留；
- 不是新记录类型。

### P1/P2：lossless cold digest

- 只在长题 packet 超限明显时启用；
- 冷分支 → digest，`covers` 成员；成员不删除；
- `content_version` + signature 复用；commit 前 liveness recheck；
- `expand_digest` 按需还原；
- 不默认引入 LLM compactor；先确定性 digest，再 A/B。

**不借**：Go/Postgres/Next.js、38 张表、3 worker、双图调度、`goal_met`、5 小时/4.5 亿 token 的比赛架构。

## 11.5 解题能力优先（冻结后）

机制面 4/5/4 不动；冻结之后先做能力面：

> v4 已把顺序改为：模型 → CTF sandbox → 卡/case → first contact gate → session → race/browser；本节保留为历史。

### 提升 solve 的前 5 干预

1. backbone 模型升档；
2. playbook 首批 10 卡；
3. 5 题 first contact；
4. session 做实；
5. browser capability。

模型是最大 delta，但 first contact 是 gate：先撞真实 artifact，再做模型矩阵。

### P0-a 先见真实题目

- 5 题 dev：crypto / web / pwn / rev / forensics 各 1；
- 先让 `shape@1` / `signature@1` 撞真实 artifact；
- 验收：整形幂等、原子 artifact、processFailure 四态、quote span。

### P0-b playbook 内容工程

最小 schema：

```json
{
  "id": "web-blind-sqli-length",
  "category": "web",
  "trigger": { "tech": ["php", "mysql"], "signals": ["id parameter", "boolean difference"] },
  "toolchain": ["run: baseline", "run: true/false payload", "claim: differential"],
  "verify": { "claimType": "differential", "predicate": "http.length_delta", "minDelta": "10%" },
  "deadEnds": [{ "signature": "union-select", "failureClass": "client-blocked" }],
  "evidence": { "source": "writeup|case|human", "refs": ["..."], "verifiedBy": "case|human" },
  "stats": { "used": 0, "success": 0, "fail": 0 }
}
```

来源：

1. 官方/公开 writeup 蒸馏（人工审、可引用、不复制长文）；
2. 人工沉淀；
3. 跑题后只从 verified trace + 代码 failureClass 提取，不读原始 transcript；候选卡需验证。

质量门：必须有 trigger/toolchain/verify/deadEnds；无 verify 不算 card；每类 ≤10、总 ≤50；**playbook digest ≤2KB（top 3）**；Budget 块 ≤0.5KB 单独计；不存 flag/secret/IP。

验收：带/不带 playbook 的 15 题 A/B；没有提升就不默认注入。

### P0-c 模型选型

- 角色：`backbone`（Reason/claim/exploit）、`verifier`（异族、独立供应商）；v1 不设 `cheap` 角色；
- 不硬编码模型名；用 provider/role 配置；
- fallback：429/529、额度不足；
- 评估矩阵：model × solve × cost × latency；
- verifier 族由配置决定，模型不能运行时选。

### P1 / P2

- P1-a session 做实：pwn/rev 交互、增量读、state card；
- P1-b browser 进设计：作为 `run` 的 capability 或外部 MCP，不新增第五动词；父级只暴露高层能力；
- P2 并发表达：race condition 需要并行请求/会话，later 加 `parallel` capability，不动 4 动词。

**不引入**：cue/fire ledger、cold digest、多 worker；先跑 5 题，再谈这些。

---

## 12. 评测

- 15 题开发集。
- cybench 静态 10 题（FST 分档，manifest 钉死）。
- 基线：B0 裸模型 + skill；B2 free-text claim；B3 grounded claim；B6 packet/restart。
- 指标：solve、false Fact、false flag、repeat signature、recovery、tokens-to-solve、wall-clock、quote-support error、injection pass。
- later：CTFTiny 50、cybench 交互 5、B0–B7/C0–C3、TUI、memory。

---

## 13. 里程碑

| 阶段 | 交付 |
|---|---|
| M0 | JSONL ledger、ProcessOutcome、shape@1/signature@1 |
| M1 | exec + classify、claim 状态机、最小 NegativeEntry；**5 题 first contact** |
| M2 | context compiler、packet、plan/handoff；**playbook schema + 首批卡片** |
| M3 | session/SessionObservation、flag 四层；browser 只留 capability 槽 |
| M4 | 4 动词 adapter、15 题 + cybench 静态锚；model selection 矩阵 |
| later | TUI、memory、CTFTiny、交互锚、cold digest、transient 全家桶、并发 |

第一交付：

1. `run/exec.ts` + raw/shaped + 原子 artifact；
2. `shape@1` / `signature@1` + fixture；
3. `ledger/store.ts` + claim/negative；
4. `context/packet.ts` + plan；
5. `flag`；
6. 4 动词 adapter。

---

## 14. 风险与非目标

风险：

- claim 作为工作单元是否够表达多步链？用 plan 块补；A/B。
- parser/fixture 太弱会漏 schema 伪装；需要 golden。
- TTL + 确定性硬阻断可能仍有振荡；高级解阻 later。
- packet 16KB 可能丢长尾；cold digest later。
- 4 动词是否优于 3 工具；用 action-selection error 证明。

非目标：

- 不默认多 worker / A2A / swarm；
- 不先写 Rust；
- 不做 Postgres/Next.js 平台；
- 不做全局 vector memory / 后台 LLM consolidation；
- 不做 31 工具 / 插件市场；
- 不做 auto-submit / 通用安全 Harness。

---

## 15. 一句话

**v3 是 ARTEX 的“状态机纪律” + omp 的“上下文纪律” + ZCode 的“claim/验证” + pi4ctf 的 less-is-more：4 动词、5 机制、4 记录，先跑 15 题，再谈图、TUI、Rust。**
