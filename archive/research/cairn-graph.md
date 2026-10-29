# Cairn / TCH 图机制分析与采纳 v0.1

> 来源：`oritera/Cairn`（AGPLv3）与 TCH 腾讯云黑客松智能渗透挑战赛复盘。
> 只借鉴**设计思想**，不复制 AGPL 代码/提示词；我们的实现独立编写。

---

## 0. 结论

Cairn 的核心不是“多 Agent 分工”，而是：

> **把未知路径问题建模成一张从 origin 到 goal 的 Fact/Intent 图。**
> 图是唯一共享状态；Agent 只做 OODA；没有固定角色；没有直接通信。

这比我们之前的“路由板 + 单循环”更本质：

- 路由板只有当前 3 条线；Cairn 保留了**完整因果链**。
- 路由板会覆盖/丢历史；Cairn 的 Fact 只增不改。
- 路由板是“计划”；Cairn 的 Intent 是“可认领的探索边”。
- 路由板难以并行；Cairn 用 claim/lease 天然支持多 worker。

**采纳**：把 `route board` 升级为 **单 agent 的 Fact/Intent 图**，仍然 3 个工具、一个循环。
**不采纳**：Server/Dispatcher/容器/Web UI 那一整套重型运行时；v1 用文件图 + 单 agent。

---

## 1. Cairn 是什么

- 通用状态空间搜索：origin 已知、goal 明确、路径未知。
- 渗透/CTF 只是第一个验证场景。
- 比赛结果：610 队、1345 人；**54/54 唯一 AK**；公开资料对最终名次有 3/4 名不同表述，受动态计分与开局并发影响。
- 成本：5 天约 **7692 元**、**10.9 亿 tokens**；边际收益递减；第 4 天 0 flag，第 5 天注入人类意图后 AK。
- 设计口号：**Less Is More**；反对传统多 Agent 分工；反对通识 Skill/RAG 堆叠；复杂留给工程实现。

---

## 2. 三个原语

| 原语 | 是什么 | 不是什么 |
|---|---|---|
| **Fact** | 已确认的客观发现；图节点 | 不是计划、不是猜测、不是原始日志 |
| **Intent** | 从一个或多个 Fact 出发的探索方向；图边 | 不是角色、不是任务分配单 |
| **Hint** | 人类判断/态势提示；图外输入 | 不是事实、不参与因果 |

### Fact

- 只增不改，永久保留。
- 描述是“结论提炼”，不是原始输出；长数据放文件，Fact 里引用路径。
- 状态变化用**新 Fact** 表达，例如“shell 断了”是新的 Fact，不是修改旧 Fact。
- 特殊 Fact：`origin`、`goal`。

### Intent

- `from` 可以是多个 Fact → **超边**，保留“多个事实共同支撑一次探索”的因果。
- 状态：
  - open：已声明、未认领
  - claimed：有 worker、无结论
  - concluded：产出 `to` Fact
- 已结论不可修改。
- 可保留 `bootstrap` 语义：`from=[origin]`，表示项目初始态的一次直接推进。

### Hint

- 人类/策略提示，可随时追加；项目 stopped/completed 也可加。
- 适合传递“态势评估”：例如“SSH/SQLi 已排除，攻击面在文件上传”。
- 不进入因果图，避免把判断伪装成事实。

---

## 3. 图的不变量

1. **Append-only**：Fact/Intent/Hint 只增不改；状态变化用新 Fact。
2. **DAG**：Intent 从旧 Fact 指向新 Fact；新 Fact 只能由已结论 Intent 产生。
3. **超边**：一个 Intent 可有多个 `from`。
4. **图即审计**：每个结论都能沿 Intent 回溯到 origin。
5. **长数据外置**：Fact 只放结论 + artifact 引用。
6. **单一共享状态**：Agent 之间不直接通信，只读写图（stigmergy）。

---

## 4. 执行模型

### 4.1 三类任务

| 任务 | 触发 | 输入 | 输出 |
|---|---|---|---|
| **Bootstrap** | 项目初始态 | origin/goal/hints | 直接尝试解决；成功 → Fact + Complete；失败/超时 → Conclude 产出 Fact |
| **Reason** | 新 Fact/Hint，或无 open intent | 完整图 YAML | Complete / 新 Intents / 空 |
| **Explore** | 有 open intent | 图 YAML + 一个 intent | 一个 Fact |

- `reason` 单项目最多一个（lease）。
- `explore` 认领 Intent（claim + heartbeat），超时释放。
- `bootstrap`/`explore` 支持“执行 + 超时/解析失败后 conclude”双阶段，避免丢已确认信息。

### 4.2 OODA + Stigmergy

- 每个 worker：Observe 图 → Orient 当前状态 → Decide 下一个 Intent → Act 执行 → 写回 Fact。
- Worker 没有固定角色；任务由图的当前状态生成。
- 协调靠共享图（stigmergy），不靠消息。

### 4.3 为什么有效

- **无角色分工**：避免“信息收集 Agent/Web Agent/后渗透 Agent”的低效信息交换。
- **图压缩上下文**：Fact 是结论，不是原始日志；长数据外置。
- **并行天然**：不同 worker 认领不同 Intent；reason 单点保证全局一致性。
- **可恢复**：图是持久事实；worker 挂了，Intent 超时释放，其他 worker 接手。
- **人类意图可注入**：Hint 不污染事实，但能改变 reason/explore 的方向。

### 4.4 已知风险

- **Reason 瓶颈**：全局判断集中在一个 reason lease；reason 慢/错会拖全局。
- **图膨胀**：Fact 太多会稀释注意力；需要 Hint/摘要/归档。
- **重复探索**：Intent 描述不清会导致重叠；需要 reason 去重。
- **并发成本**：多 worker 并行烧 token；比赛数据也显示边际收益递减。
- **许可**：Cairn 是 AGPLv3；不能把代码/提示词直接搬进我们的项目。

---

## 5. 对 pi4ctf 的改造

### 5.1 核心变化：路由板 → 图

| 之前 | 现在 |
|---|---|
| `state.routes` ≤3 条线性路线 | `facts[] + intents[] + hints[]` DAG |
| 路线状态 live/dead/blocked | Intent open/claimed/concluded；状态变化写新 Fact |
| `brief.md` 一次性简报 | `graph.yaml` 快照 + Hint |
| 发现被覆盖 | Fact 只增不改，完整因果链 |
| 单 agent 顺序执行 | 仍然单 agent；图天然支持以后多 worker |

### 5.2 仍然是 3 个工具

`ctf_case` 的 action 改为图操作：

```ts
input:
  | { action: "init"; path; category?; target?; goal; hints?; oracle?; backend?; timeboxMinutes? }
  | { action: "graph"; format?: "yaml"|"md"; maxFacts?: number }
  | { action: "fact"; description: string; source: { commandId: string; artifact?: string } }
  | { action: "intent"; add?: { from: string[]; description: string }; id?: string;
      state?: "open"|"claimed"|"concluded"; to?: string; worker?: string }
  | { action: "hint"; content: string; creator?: "user"|"agent" }
  | { action: "flag"; flag: string; source: { kind: "run"|"file"|"http"|"user"; ref: string } }
  | { action: "status" }
  | { action: "doctor" }
  | { action: "close"; reason?: string }
output: { project: Project; graph?: Graph; warnings: string[] }
```

`ctf_run` / `ctf_session` 不变。

### 5.3 单 Agent 循环

```text
init(origin, goal, hints)
  ↓
Bootstrap：直接尝试（小预算）
  ├─ solved → fact + complete → verify flag
  └─ not solved → conclude fact
  ↓
Reason：读 graph.yaml
  ├─ goal satisfied → complete → verify flag
  ├─ open intents → 选一个
  └─ no open intents → 提出 ≤3 个 intents
  ↓
Explore：认领一个 intent → 执行 → 写一个 fact → conclude
  ↓
回到 Reason
  ↓
预算/无进展/时间盒 → failure report
```

单 agent 不需要 server/dispatcher/lease；用文件锁即可：

- `graph.jsonl` 追加事实/意图/提示；`graph.yaml` 是投影。
- `ctf_case` 内部用文件锁保证追加原子性。
- 以后要并行：多个 `pi-subagents` 各认领一个 open intent；用同一把锁；不做直接通信。

### 5.4 提示词

- **BOOTSTRAP**：origin/goal/hints；尝试解决；只有确认达成才 complete；超时进 conclude。
- **REASON**：完整图 YAML；判断 goal 是否满足；否则提 ≤3 个独立、非重叠 intent。
- **EXPLORE**：图 YAML + 当前 intent；只沿这个方向探索；产出一个增量 Fact；长数据引用文件。
- **CONCLUDE**：超时/解析失败时，只总结已确认事实，不再执行。

> 这些提示词由我们独立编写，不复制 Cairn 的 AGPL 文本。

### 5.5 预算

| 预算 | 默认 |
|---|---|
| Bootstrap | 5 min / 8 turns |
| Reason | 1 次调用，≤3 intents |
| Explore | 120 s/命令；单 intent ≤8 turns |
| 总 turns | 30 |
| open intents | ≤5 |
| 连续无新 Fact | 2 轮 → 停/换 hint |
| 单 Fact | ≤2 KB，长数据引用 artifact |

### 5.6 完成与 flag

- `reason` 可以提出 `complete`，但**不能直接写 flag**。
- `ctf_case flag` 仍然是唯一硬门禁：格式 → artifact 溯源 → oracle → 去 decoy。
- `complete` 只在 flag verified 后写入图/关闭项目。
- 没有 oracle 时，只能是 candidate，不能 complete。

### 5.7 人类意图

- `hint` 随时注入；下一次 Reason/Explore 可见。
- 这是 TCH 第 5 天 AK 的关键：第 4 天 0 flag，人工分析日志后注入意图，第 5 天全解。
- 我们的 `/ctf-hint "..."` 或直接聊天即可写入 Hint。

---

## 6. 采纳/不采纳

### 采纳

- Fact/Intent/Hint 三原语。
- Append-only、DAG、超边、长数据外置。
- Bootstrap → Reason ↔ Explore。
- 图快照作为上下文，而不是原始日志。
- Hint 注入人类判断。
- 图即知识库 + 审计日志。
- 单 agent 文件图；以后可加 worker。

### 不采纳（v1）

- Cairn Server + Dispatcher + 每项目容器 + Web UI：太重；文件图 + 单 agent 足够。
- 常驻多 worker：先单 agent 验证图本身是否提升 solve；并行是后续优化。
- “完全不要 RAG/Skill”：我们保留**可选**、执行期注入；默认不预加载通识技能，避免锁死上限。
- AGPL 代码/提示词：只借鉴思想，独立实现。

---

## 7. 需要验证的假设

1. 图模型是否比线性 route board 减少重复、提高 solve？（15 题 A/B）
2. Bootstrap 是否值得？简单题直接解，难题转入图。
3. Reason/Explore 分离是否比单循环更少上下文污染？
4. Fact 只增不改是否让恢复/审计更好，但图膨胀是否拖慢？
5. 多 worker（2–4）是否在独立 intent 上正收益，成本是否可接受？
6. Hint 注入是否显著提升卡住题？（TCH 的单项证据）

---

## 8. 来源

- Cairn: <https://github.com/oritera/Cairn>
- Cairn README / specs: <https://github.com/oritera/Cairn/tree/main/docs/specs>
- TCH 复盘（镜像）: <https://zone.ci/secarticles/wx/526000.html>
- TCH 赛事: <https://zc.tencent.com/hackathon>
- 相关 fork/改进: <https://github.com/jingkeyimeng/cairn-agent>
