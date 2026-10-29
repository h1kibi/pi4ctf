# pi4ctf v2-core

> **历史归档。** v2 的机制层被收紧到 5 个；当前施工基线是 [`../design.md`](../design.md)。
> `design-v2.md` 保留为完整研究，机制面以本文为准，但两者都不再作为施工依据。
>
> **4 动词 · 5 机制 · 4 记录。**
>
> 代码拥有 belief，模型只提案；上下文是投影，不是日志；挑战材料默认不可信。

---

## 0. 审计结论

v2 全量方案在工具表面是 less is more，在机制表面不是：

- 9 类记录、2 个注册表、4 层门、3 套上下文机制、评测动物园。
- 治理膨胀，能力单薄；最大的杠杆（playbook/演示、session、packet）反而没有被优先做。

v2-core 的原则：

1. **先验知识/演示 > 接口设计 > 负知识 > 治理细节。**
2. 无消融证据的治理机制默认 later；安全边界豁免。
3. 每个保留机制必须有 fixture 或 A/B。

---

## 1. 四个动词

模型面只有四个工具：

| 动词 | 职责 |
|---|---|
| `run` | 执行命令；返回 ProcessOutcome；自动产出 Observation |
| `session` | PTY 交互；返回 SessionObservation |
| `claim` | 提交解释/断言 + quotes；内核自动验证 |
| `flag` | 提交 flag 候选；内核四层验证/写入 |

`case` 不是第五个工具，是**内部 API**：

- `init / status / context / handoff / doctor` 由 adapter/kernel 调用；
- context packet 由 adapter 注入，模型读状态，不查状态；
- handoff/restart 由代码指标触发，模型无权请求；
- `complete` 由内核从 verified Fact 判定，`flag` 只是提交申请。

这样 4 动词完整覆盖，不再出现“3 工具但 `case` 有 10 个 action”的假 less。

---

## 2. 五个机制

1. **exec**：child_process/PTY + `shape@1` + `signature@1`。
2. **ledger**：JSONL append-only + 最小 NegativeEntry。
3. **context compiler**：packet + handoff=重编译。
4. **claim + 自动验证**：便宜谓词同步判；高风险/无谓词走异族 verifier。
5. **session**：PTY + SessionObservation。

安全横切（不计入五机制，成本近零、缺位不可逆）：

- `<UNTRUSTED_DATA>` wrapper；
- kernel-only：`flag` 写入、`complete`、global memory、scope/budget/guardrail 变更；
- 注入 fixture。

Playbook/演示是**数据**，随 packet 进入，不是机制。

---

## 3. 四类记录

### ProcessOutcome

```json
{
  "id": "cmd-0021",
  "argvTemplate": ["curl", "-s", "http://host/<v:1>"],
  "target": "host:80",
  "intentClass": "http-probe",
  "exit": 0,
  "durationMs": 412,
  "stdout": { "raw": "...", "shaped": "...", "sha256": "...", "bytes": 1200 },
  "stderr": { "raw": "...", "shaped": "...", "sha256": "...", "bytes": 0 },
  "processFailure": null,
  "ts": "..."
}
```

`processFailure`: `timeout | nonzero-exit | no-output-when-expected | null`。exec 不判语义。

### claim

```json
{
  "id": "c0012",
  "claimType": "differential",
  "text": "boolean blind：true/false 响应长度不同",
  "quotes": [{ "shapedRef": "...", "span": { "start": 40, "end": 96 } }],
  "refs": ["cmd-0021", "cmd-0022"],
  "state": "proposed|checking|accepted|rejected",
  "signature": "differential|...|cmd-0021,cmd-0022"
}
```

- quote 文本必须等于 `shaped[start:end]`。
- rejected 写 NegativeEntry；accepted 写 Fact。
- 同一 signature 只有引用新 artifactRef/span 才允许重交；否则硬阻断。

### Fact

```json
{
  "id": "f0012",
  "claimId": "c0012",
  "claimType": "differential",
  "predicate": "http.length_delta@1.0.0",
  "value": { "baseline": 800, "probe": 1200, "delta": 400 },
  "observationRefs": ["cmd-0021", "cmd-0022"],
  "status": "verified"
}
```

### NegativeEntry

```json
{
  "signature": "...",
  "attempts": 3,
  "failureClass": "timeout|nonzero-exit|no-output|schema-mismatch|probe-contradicted|client-blocked|server-error",
  "transient": true,
  "expiresAt": "2026-10-24T12:30:00+08:00",
  "artifactRef": "...",
  "route": "i0004"
}
```

实现只做两件事：

- `ttl` 过期可重评；
- 确定性失败硬阻断。

其他（condemnedBy、probe_version、env.probe、一次性票、blockScope）later；schema 保留，不实现。

---

## 4. 执行与分类

不是三个子系统，是两个函数：

```text
exec(cmd) -> ProcessOutcome        // 纯进程事实
classify(cmdClass, shaped) -> fields + semanticFailure
```

- `classify` 是 capability 的函数属性，不是运行时注册表。
- R2 危险检测（5xx/403/429/WAF）是内核 10 行状态码表；模型不能传 `expectedStatus` 放宽。
- generic `run` 无 classify → `semanticFailure=unknown` → 必须 verifier。
- `command-contracts.json` 删除；fixture 随 capability 代码走，code review 即治理。

---

## 5. Context compiler

### packet

默认约 4–5k tokens（16KB 代理）：

| 块 | 预算 |
|---|---|
| Mission：goal / flag format / target / constraints / deadline | ≤2KB |
| Verified Facts digest（id + 一句话 + artifactRef） | ≤4KB |
| Open claims | ≤1KB |
| Negative ledger（最小） | ≤2KB |
| Queue：队首 + 次 2 个 pending | ≤1KB |
| Recent observations：5 ×2KB | ≤10KB |
| Budget + playbook digest | ≤0.5KB |

- store 永不丢；packet 只丢 digest。
- 超限先丢旧 observation，再丢低置信 claim。
- 不维护 cue/fire ledger；只在 `fact_added`/`command_failed`/`claim_rejected` 的 revision 变化时重编译。

### handoff

`handoff = packet + resume pointer`（next action、in-flight command、TTL）；restart = 重编译。没有独立 handoff schema。

### 注入

- `case_init` guidance 可进 system prompt；
- 后续用隐藏 custom message；
- prompt cache 前缀不重写。

---

## 6. Claim 自动验证

```text
proposed -> checking -> accepted | rejected
```

- 便宜谓词：内核同步判定。
- 高风险/无谓词：异族 verifier；模型不能选验证强度。
- `checking` 可异步；packet 显示 pending claims；模型不阻塞。
- rejected → NegativeEntry；accepted → Fact。
- `claim` 只处理解释，不处理 observation；Observation 由 `run`/`session` 自动产出。

---

## 7. Session

- PTY：open/write/read/resize/close。
- SessionObservation 是 session 的输出形态，不是独立记录类型。
- state card：cwd/env/pid/open sockets/libc/arch。
- 只回增量；完整 buffer 进 artifact。
- pwn/rev 交互题的核心；不能后置到“以后再说”。

---

## 8. 安全横切

- 挑战材料 `<UNTRUSTED_DATA>`；parsed 优先；quote 是数据不是指令。
- kernel-only：`flag` 写入、`complete`、global memory、scope/budget/guardrail 变更。
- 注入 fixture：假 flag、ignore instructions、写 global memory、扩 allowedHosts、直写 flag。
- `tool_call` hook 校验 goal contract；越界阻断并审计。

---

## 9. 评测（v2-core 最小）

- 15 题开发集。
- cybench 静态 10 题（FST 分档，manifest 钉死）。
- 基线：B0 裸模型 + skill；B2 free-text claim；B3 grounded claim；B6 packet/restart。
- 指标：solve、false Fact、false flag、repeat signature、recovery、tokens-to-solve、wall-clock、quote-support error、injection pass。
- CTFTiny 50、cybench 交互 5、B0–B7/C0–C3、TUI、memory 全部 later。

---

## 10. 里程碑

| 阶段 | 交付 |
|---|---|
| M0 | JSONL ledger、ProcessOutcome、shape@1/signature@1 |
| M1 | exec + classify、claim 状态机、最小 NegativeEntry |
| M2 | context compiler、packet、handoff |
| M3 | session/SessionObservation、flag 四层 |
| M4 | 4 动词 adapter、15 题 + cybench 静态锚 |
| later | TUI、memory、CTFTiny、交互锚、transient 全家桶 |

第一交付：

1. `run/exec.ts` + raw/shaped + 原子 artifact；
2. `shape@1` / `signature@1` + fixture；
3. `ledger/store.ts` + claim/negative；
4. `context/packet.ts`；
5. `flag`；
6. 4 动词 adapter。

验收：

- shape 幂等；processFailure 四态零模型；
- 500/403/429 不被当成功；
- quote span == shaped slice；
- 同 claim 拒后重交硬阻断；
- 伪 complete=0；注入 fixture 行为一致；
- packet 预算；store 不丢。

---

## 11. 砍掉的与保留的

### 砍掉/后置

- `cue/fire ledger`；`command-contracts.json` 注册表；`contract.override/clamp` 治理；
- `DifferentialObservation` 独立类型（改两条 Observation + predicate）；
- transient 全家桶（env.probe/一次性票/probe_version/blockScope）；
- TUI、memory、stage-adaptive packet、CTFTiny、交互锚、B0–B7/C0–C3。

### 保留（不砍）

- session（交互题）；
- packet/compiler；
- ledger + negative；
- claim 的 quote 锚定；
- playbook/演示数据；
- untrusted wrapper + kernel-only flag + 注入 fixture。

---

## 12. 一句话

**v2-core 不是“更少的功能”，而是“更少的概念”：4 动词、5 机制、4 记录；先验知识和 session 优先，治理细节后置。**
