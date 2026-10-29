# pi4ctf 统一设计

> **统一施工基线（2026-10-24）。** 合并 v3 内核与 v4 能力层，取代 v1–v4 的施工排序；旧文档保留为历史。
>
> **一个二进制 · 四个动词 · 一个循环。**
>
> **4 动词 / 5 机制 / 4 记录。**
>
> 代码拥有 belief，模型只提案；上下文是投影，不是日志；挑战材料默认不可信。

---

## 0. 问题与目标

### 0.1 问题

CTF agent 的失败通常不是“不会跑命令”，而是：

1. **把猜测当事实**：模型说“这里有 SQLi”，但没有可复查的证据；
2. **上下文腐烂**：长题里旧观察、错误路线、重复尝试淹没真正有用的信息；
3. **环境不对**：工具缺失、架构不匹配、没有浏览器/并发，导致题目根本不是“推理失败”；
4. **识别失败**：连漏洞类型都没认出来，后面的执行能力没有机会发挥；
5. **不可恢复**：命令超时、session 撕裂、上下文重启后从头再来；
6. **评测自欺**：静态题被 writeup 污染，把检索命中当成 solve。

### 0.2 目标

> **在可验证、可恢复的前提下，把 CTF solve rate 拉起来。**

不是做通用安全 Harness，不是做 CTF 平台，不是做多 agent 框架。

### 0.3 非目标

- 不做 daemon、数据库、通用 planner；
- 不默认多 worker / A2A / swarm；
- 不做 triad/角色动物园；
- 不做向量长期记忆；
- 不做 TUI；
- 不自动提交 flag；
- 不把 playbook 当第六机制；
- 不把 race 当第五动词。

---

## 1. 设计原则

1. **代码拥有 belief**：Observation 由代码产生；claim 必须带 quote；Fact 由 predicate/verifier 推导。
2. **Context 是投影**：store 永不丢；packet 只放 digest；handoff = packet + resume。
3. **不可信是默认值**：挑战材料进 `<UNTRUSTED_DATA>`；flag/complete/global memory/scope 变更内核单点。
4. **概念少，不是工具少**：4 动词、5 机制、4 记录；`case` 是内部 API。
5. **复杂度必须证明收益**：没有 fixture 或 A/B 的机制默认 later。
6. **先验知识优先**：playbook/case 是数据，不是第六个机制。
7. **终止条件外置**：flag/oracle、deadline、budget、negative ledger、route drift，不靠模型自评。
8. **先解题，再治理**：模型、环境、识别、case 的优先级高于再加验证层。

---

## 2. 总体架构

```text
pi host
  └─ extensions/ctf.ts
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
       Kali sandbox / external tools / MCP
```

分工：

- **pi**：推理、工具调用、UI；
- **kernel**：状态、执行、证据、上下文投影；
- **adapter**：只接线，不写状态；
- **providers**：宿主/用户级环境事实（`env_memory`、镜像探测）在 `src/providers/`，不进入 kernel；kernel 只接收已渲染的环境摘要。

当前 TS 实现的 adapter 采用静态 handler 分层，不引入动态注册表：

```text
src/adapter/protocol.ts       JSON seam、kernel-only gate、显式 op 路由
src/adapter/policy.ts         budget、target recovery、negative route policy
src/adapter/handlers/case.ts  project/case/evidence/proc/preflight 编排
src/adapter/handlers/run.ts   run、probe、scope、route gate 编排
src/adapter/handlers/claim.ts claim 提交与同步 verifier 编排
src/adapter/handlers/flag.ts  target gate 与四层 flag 编排
src/adapter/handlers/env.ts   env provider 的协议适配
src/adapter/helpers.ts        root、结果、evidence、doctor 辅助
```

`protocol.ts` 只拥有外部协议 seam；handler 可以编排 kernel/provider，但不改变
四个动词、状态不变量或 kernel 的事实所有权。
- **skill**：策略；
- **sandbox / MCP**：不可信外部环境。

施工顺序：**先 TS kernel + fixtures，行为冻结后移植 Rust `rt`**。目标形态是单二进制，但不是第一天的形态。

---

## 3. 四个动词

| 动词 | 职责 |
|---|---|
| `run` | 在 sandbox 中执行命令，返回 `ProcessOutcome`，自动产出 Observation |
| `session` | 持久 PTY；gdb/nc/python；只回增量 |
| `claim` | 提交解释/断言 + quotes，内核自动验证 |
| `flag` | 提交 flag 候选；内核四层验证 |

`case` 的核心 op 仍是内部 API；只读/配置 helper 作为模型工具暴露：

- `init / status / context / handoff / doctor` 由 adapter/kernel 调；
- packet 由 adapter 注入；
- restart/handoff 由代码指标触发；
- `complete` 由内核从 verified Fact 判定；
- `flag` 只是申请，不是写入。

辅助工具（不新增动词）：`case_preflight` 生成 ELF/libc + 非 ELF 静态元数据，`case_evidence`
读 artifact（支持 grep/head/tail），`/ctf doctor`（内部 `case.doctor`）返回 host 工具 digest，`proc` 读 live
session 的 `/proc`，`case_configure` 修 flagFormat/oracle/backend/target；均不占用执行预算。

新增**模型面**动作必须用 15 题 A/B 证明；能力扩展走 `rt` 子命令 / capability / SDK，不新增动词。

---

## 4. 五个机制

### 4.1 执行与分类

```text
exec(cmd) -> ProcessOutcome
classify(cmdClass, shaped) -> fields + semanticFailure
```

- `exec` 在 sandbox 内执行；默认不跑宿主裸环境；
- `shape@1` 去 ANSI、折叠重复、保留错误/命中行；
- `signature@1` 含 `<v:n>` 载荷槽；
- `canonicalKey = commandClass + signature@1 + shapedHash`；
- differential / time-based 两条腿豁免合并；
- 去重只作用于 packet/recent 与计数，不删 store 行；
- `classify` 是 capability 的函数属性，不是运行时注册表；
- 危险状态码（5xx/403/429/WAF）由内核状态码表判定，模型不能放宽。

### 4.2 Ledger 与四类记录

**ProcessOutcome**：进程事实。

```json
{
  "id": "cmd-0021",
  "argvTemplate": ["curl", "-s", "http://host/<v:1>"],
  "target": "host:80",
  "intentClass": "http-probe",
  "canonicalKey": "http|signature@1:curl -s http://host/<v:1>|shaped:sha256:...",
  "exit": 0,
  "durationMs": 412,
  "stdout": {"raw":"...", "shaped":"...", "sha256":"...", "bytes":1200},
  "stderr": {"raw":"...", "shaped":"...", "sha256":"...", "bytes":0},
  "processFailure": null,
  "ts": "..."
}
```

`processFailure`：`timeout | nonzero-exit | no-output-when-expected | null`。

**claim**：解释/断言 + quote。

```json
{
  "id": "c0012",
  "claimType": "differential",
  "text": "boolean blind：true/false 响应长度不同",
  "quotes": [{"shapedRef":"artifacts/cmd-0021.stdout.log","span":{"start":40,"end":96}}],
  "refs": ["cmd-0021","cmd-0022"],
  "probe": {"purpose":"比较响应长度","expect":"delta > 10%","falsifier":"长度一致或都 403"},
  "state": "proposed|checking|accepted|rejected",
  "signature": "differential|...|cmd-0021,cmd-0022"
}
```

- quote 文本必须等于 `shaped[start:end]`；
- accepted → Fact；rejected → NegativeEntry；
- 同一 signature 只有引用新 artifact/span 才能重交，否则硬阻断；
- claim 是队列单元；open claims 进 packet。

**Fact**：被谓词验证的结论。

```json
{
  "id": "f0012",
  "claimId": "c0012",
  "claimType": "differential",
  "predicate": "http.length_delta@1.0.0",
  "classifiedBy": "classify@1",
  "value": {"baseline":800,"probe":1200,"delta":400},
  "observationRefs": ["cmd-0021","cmd-0022"],
  "canonicalKey": "...",
  "status": "verified"
}
```

**NegativeEntry**：死路。

```json
{
  "signature": "...",
  "attempts": 3,
  "failureClass": "timeout|nonzero-exit|no-output|schema-mismatch|probe-contradicted|client-blocked|server-error|tty-required",
  "transient": true,
  "expiresAt": "2026-10-27T12:30:00+08:00",
  "artifactRef": "...",
  "route": "c0012"
}
```

实现只做两件事：TTL 过期可重评；确定性失败硬阻断。高级解阻 later。

### 4.3 Context compiler

默认 packet 约 4–5k tokens（16KB 代理）：

| 块 | 预算 |
|---|---|
| Mission：goal / flag format / target / constraints / deadline | ≤2KB |
| Verified Facts digest（id + 一句话 + artifactRef） | ≤4KB |
| Open claims | ≤1KB |
| Negative ledger（最小） | ≤2KB |
| Plan：当前多步链 / 下一步 / 前置条件 | ≤1KB |
| Recent outcomes：5 ×2KB | ≤10KB |
| Budget + playbook digest | ≤0.5KB |

- store 永不丢；packet 只丢 digest；
- 超限先丢旧 observation，再丢低置信 claim；Facts/negative/plan 不丢；
- `plan` 是 packet 块，不是新记录；跨 reset 由 `progress.md` / resume 指针保留；
- `handoff = packet + resume`；
- restart = 重编译；旧 context 冻结不删。

### 4.4 Claim verifier

```text
proposed -> checking -> accepted | rejected
```

- 便宜谓词：内核同步判定；
- 当前只注册 cheap predicate（`probe`/`parse`）；没有 `check:"verifier"` 谓词，异族
  verifier **未接入**。接入前提：出现无确定性谓词的 claim 类型，且 15 题 A/B 证明收益；
- `checking` 可异步；packet 显示 pending claims；
- rejected → NegativeEntry；accepted → Fact；
- claim 只处理解释，不处理 observation；Observation 由 `run`/`session` 自动产出。

### 4.5 Flag

四层：

1. **格式**：匹配题目 flag format；
2. **来源**：带 artifact/provenance；
3. **证据链**：关联 verified Fact / claim；
4. **Oracle**：CTFd / 题目 oracle 验证。

任一层失败即拒绝；`complete` 只认 verified Fact。flag 只是申请，不是写入。

---

## 5. 能力层

### 5.1 模型

- 单 agent 内 planner/executor **同模型**；强 backbone；
- verifier：异族，仅用于无便宜谓词的 claim；
- 不设 `cheap` 角色；
- fallback：429/529 → 退避 ≤2 → backbone 同族降档；verifier 只能降同族且 claim 降级 `interpreted`、不产 Fact；
- 不硬编码型号；provider/role 配置；
- 选型看等成本：Claude 4.5 Opus 59% @ $2.12/solve；Gemini 3 Pro 52% @ $0.43/solve。

### 5.2 Kali sandbox（P0）

- `kali-rolling` 派生**单镜像**；digest 钉死；
- `run`/`session` 默认在容器内；
- 挑战材料挂 `/challenge` 只读，工作区 `/challenge/workspace` 可写；
- 服务通过 Docker bridge / `host.docker.internal` 可达；
- 不默认挂宿主文件系统；不默认联网；
- 不默认执行宿主二进制。

最小工具集：

- pwn：pwntools、gdb + GEF（pwnlab）、one_gadget、ropper、ROPgadget、checksec、patchelf；
- crypto：sage、pycryptodome、RsaCtfTool、z3、gmpy2、cado-nfs；
- web：sqlmap、ffuf、seclists、hashcat、jwt-tool；
- rev：radare2、ghidra-headless、binutils、ltrace、strace；
- forensics：binwalk、volatility3、stegseek、exiftool、tshark、sleuthkit；
- 通用：python3、gcc、git、jq、curl、nc。

工具发现：

- 构建期从包清单生成 `toolbox digest`（≤0.5KB），只描述镜像；
- 用户环境工具由 host 侧 `env_memory` 记录，不把镜像 digest 当作用户工具表；
- 不调用 LLM；
- 比 category tips 更稳：Kali 的“隐含引导”被代码化。

### 5.3 卡 + case

**卡**：索引与死路，不写技术建议。

```json
{
  "id": "web-blind-sqli-length",
  "category": "web",
  "trigger": {"tech":["php","mysql"],"signals":["id parameter","boolean difference"]},
  "deadEnds": [{"signature":"union-select","failureClass":"client-blocked"}],
  "verify": {"claimType":"differential","predicate":"http.length_delta"},
  "evidence": {"refs":["writeup:..."],"verifiedBy":"case|human"},
  "stats": {"used":0,"success":0,"fail":0}
}
```

刻意不含 `toolchain` 建议文本。理由：Kali + category tips 实测 −12pp；建议文本会过约束。卡只负责“何时想起”和“别再走死路”。

**case**：具体命令片段。

```json
{
  "id": "case-web-blind-sqli-01",
  "category": "web",
  "trigger": {"tech":["php","mysql"],"signals":["id parameter"]},
  "snippet": "curl ... baseline / true / false; compare length",
  "citation": "writeup:...",
  "verifiedBy": "human|case",
  "excluded": false
}
```

- 每技术 2–3 条；
- 只在执行期注入；
- 带引用；
- 不存 flag/secret/IP；
- 排除 dev/cybench 同源 writeup；
- 评测期禁 web 检索。

注入门：

- 离线标注 50 对（任务，检索）；
- `precision@3 ≥ 0.6` 才允许注入；30 对太少，报告置信区间；
- 默认关；
- 带/不带 A/B；无提升就只保留 deadEnds；
- playbook digest ≤2KB（top 3），Budget 块 ≤0.5KB 单独计。

首批 20 卡：

1. web 盲注长度差分；
2. web PHP filter chain；
3. crypto RSA Fermat；
4. crypto AES ECB/padding oracle；
5. pwn cyclic → ret2win；
6. pwn format string leak；
7. rev UPX + ghidra headless；
8. rev ltrace/gdb key-check；
9. forensics pcap HTTP objects + creds；
10. forensics binwalk/strings carving；
11. web SSTI `{{7*7}}` 差分；
12. web JWT alg=none/弱密钥；
13. web 盲命令注入 time-based；
14. crypto XOR crib drag；
15. crypto ECDSA nonce 复用；
16. pwn ret2libc；
17. pwn 栈迁移；
18. rev angr 符号求解；
19. forensics volatility 进程/凭据；
20. forensics DNS 外传解码。

### 5.4 5 题 first contact（gate）

每类 1 题，中等难度，容器化，有公开 writeup（供 case 蒸馏；评测期禁检索）：

- web：盲注；
- crypto：RSA 分解；
- pwn：ret2win；
- rev：UPX；
- forensics：pcap。

验收地基，不以 solve 论英雄：

- 镜像两次构建同 digest；
- `shape@1` 幂等 100%；
- processFailure 四态对人工金标 100%；
- quote 全部可锚 span；
- 逐题标注“识别失败/执行失败”；
- 失败判定：幂等破、kill 后撕裂、>1 题被缺工具阻塞。

记录 baseline solve，但不作为 gate fail。

### 5.5 Session

- PTY：open/write/read/resize/close；
- `SessionObservation` 是 session 的输出形态，不是独立记录；
- state card：cwd/env/pid/open sockets/libc/arch；
- 只回增量；完整 buffer 进 artifact；
- 环形缓冲最近 N 次交换，随 session 输出附带，不占 packet 16KB；
- pwn/rev 交互题不能后置。

> **W1 施工例外**：TS walking skeleton 的 session 是 pipe-only，`resize` 为 no-op；
> 真 PTY（ConPTY/Unix）随 Rust 移植交付。W1 不把 pwn/rev 的 session 能力算完成。

### 5.6 Race（可选，不默认）

- 外层 adapter 启动 3 个独立 solver；
- 每个 solver 自己的 case/store/container；
- 共享同一 challenge 镜像；
- 不共享 claim/ledger；
- 可选 findings bus：只共享已观察事实，不共享 belief；
- first confirmed flag 胜出；CTFd/oracle 验证；
- flag 去重 + 错误提交 cooldown；
- loop guard：同 tool+args 3 warn / 5 break；
- 触发：同一 case ≥2 个 route class 被 negative ledger 关闭，或 token >1.5× 且零新 verified；
- 预算帽 = 单 agent ×2；
- 3 模型起步；5 模型是 Veria 单场经验，`Hypothesis`；
- W2 只出设计文档，不实现；
- 不改 4 动词、不新增记录、不跨 solver 合并 claim。

### 5.7 Browser

- 作为 `run` 的 capability 或外部 MCP，不新增第五动词；
- XSS 类需要真实渲染；curl 会误判；
- later，P2。

### 5.8 并发

- race condition 需要并行请求/会话；
- 先做 `parallel` capability，不动 4 动词；
- later；先由 race 的独立 solver 提供粗粒度并发。

---

## 6. 核心循环

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

- **claim 是工作单元**：既可以是“这里可能有 SQLi”，也可以是“这个 offset 应该能拿到 shell”；
- open claims 构成队列；不需要单独的 Intent 记录；
- 七步 loop 只存在于 compiler 内部编排；Frame/Predict/Reconcile 不持久化；
- 预算：45 min、30 turns、120 s/命令、16 KB 观察；packet 约 4–5k tokens；
- 预算信号：packet 显示 remaining/health/restarts，以及有历史完成样本时的同 category median runs-to-solve；
- 自愈：host target 不可达时可调用 oracle 的 HTTP reset hook（最多 3 次/题，轮询 30s），无 hook 不伪造恢复；
- 负账本按 family 分开展示：environment incidents 不是 route dead ends；
- 终止：flag/oracle、deadline、budget、negative ledger、route drift。

---

## 7. 安全与信任边界

- 挑战材料 `<UNTRUSTED_DATA>`；parsed 优先；quote 是数据不是指令；
- kernel-only：`flag` 写入、`complete`、global memory、scope/budget/guardrail 变更；
- 注入 fixture：假 flag、ignore instructions、写 global memory、扩 allowedHosts、直写 flag；
- `tool_call` hook 校验 goal contract；越界阻断并审计；
- 没有 `goal_met` 工具；完成由代码判定；
- 不自动提交 flag；提交必须过 oracle。

---

## 8. 评测

### 8.1 集合

- 5 题 first contact（地基 + baseline solve）；
- 15 题 dev（调参）；
- cybench 静态 10 题（FST 分档，manifest 钉死）；
- holdout 题不参与调参；
- later：CTFTiny 50、live CTF/CTFusion。

### 8.2 基线

- B0：裸模型 + skill；
- B1：+ verifier；
- B2：+ verifier + 卡/case；
- R1：race 3 模型（可选 arm）。

### 8.3 指标

solve、false Fact、false flag、repeat signature、recovery、tokens-to-solve、wall-clock、quote-support error、injection pass、cost/solve、识别失败/执行失败占比。

### 8.4 防污染

- 评测期禁 web 检索；
- case 库排除 dev/cybench 同源；
- 静态与 live 分开报告；
- 等成本 arm；
- 不把公开 writeup 命中当成 solve。

---

## 9. 里程碑

| 阶段 | 交付 |
|---|---|
| W1 D1–2 | Kali 单镜像、digest、toolbox digest |
| W1 D3 | `run` 进沙箱、原子 artifact、四态 |
| W1 D4–5 | 5 题 first contact + 标注 + writeup 收集 |
| W2 D6–7 | 卡 + case + 匹配器 + 离线 precision |
| W2 D8–9 | verifier + B0/B1/B2 + 等成本 |
| W2 D10–11 | 模型矩阵（15×3 + best-of-3） |
| W2 D12 | 分析：playbook A/B、verifier 误拒、识别/执行 |
| W2 D13–14 | session 缓冲、deadEnds 回写、race 设计文档（不实现） |

第一交付：

1. `run/exec.ts` + raw/shaped + 原子 artifact；
2. `shape@1` / `signature@1` + fixture；
3. `ledger/store.ts` + claim/negative；
4. `context/packet.ts` + plan；
5. `flag`；
6. 4 动词 adapter。

回退阀：

- 整形幂等 <100% → 冻结新增，先修地基；
- B2−B0 < +1 题 → 卡/case 降级参考数据；
- verifier 对已接受 claim 误拒 ≥10% → 先修谓词；
- case precision@3 <0.6 → 不注入，只留 deadEnds；
- race 每美元 solve 低于单 agent → 不做。

---

## 10. 风险与取舍

| 风险 | 取舍 |
|---|---|
| claim 作为工作单元是否够表达多步链 | plan 块补；A/B |
| parser/fixture 太弱会漏 schema 伪装 | golden fixture；code review |
| TTL + 确定性硬阻断可能振荡 | 高级解阻 later |
| packet 16KB 可能丢长尾 | cold digest later |
| 4 动词是否优于 3 工具 | action-selection error 证明 |
| case 检索精度不够 | 默认关；precision 门；只留 deadEnds |
| race 成本高 | 可选；×2 帽；每美元 solve 比较 |
| Kali 镜像大 | digest 钉死；最小集；CI 缓存 |
| 静态 benchmark 污染 | 禁检索；holdout；live 外验 |
| 模型 nondeterminism | 3 seeds；等成本；报告置信区间 |

---

## 11. 相对旧版的变更

1. **P0 增加 Kali 单镜像 sandbox + zero-LLM toolbox digest**；
2. **playbook 改为卡 + case 混合**：卡只做 trigger/deadEnds/verify，case 执行期注入；precision 门；默认关；防同源；
3. **race 可选升级**：代码触发、3 模型、×2 帽、first confirmed flag；W2 只设计；
4. **单 agent 同模型**；verifier 异族仅限无谓词 claim；砍 cheap；
5. **评测**：holdout + 等成本 arm + 禁检索；静态/live 分开。

内核 4/5/4 不变。统一方案不是新架构，是把内核与能力层合成一份施工文档。

---

## 12. 通过标准

方案通过后，第一周只做三件事：

1. Kali 镜像可重复构建；
2. `run` 在沙箱内产出可复查的 `ProcessOutcome`；
3. 5 题 first contact 跑通并标注识别/执行失败。

第二周才做卡/case、verifier、模型矩阵。

**如果第一周三件事做不成，方案不进入第二周。**
