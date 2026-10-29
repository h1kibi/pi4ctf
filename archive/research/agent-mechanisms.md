# 其他 CTF Agent 的解题机制与 pi4ctf 的取舍 v0.1

> 目的：看别人**怎么循环、怎么规划、怎么管上下文、怎么验证、怎么停**，再决定 pi4ctf 的机制。
> 结论先行：主流机制有四类；有效的是“规划 + 宽工具 + 预算 + 验证”，无效的是“LLM 摘要当默认”“规划期灌知识”“为多代理而多代理”“拿静态 benchmark 当能力”。

---

## 1. 样本

| Agent | 类型 | 关键机制 | 公开结果 |
|---|---|---|---|
| NYU CTF baseline | ReAct + tools | 单循环、工具调用、flag 提交 | NYU 约 4–5% |
| **EnIGMA** | ReAct + interactive tools | gdb/pwntools 交互会话、LM summarizer、demos | NYU 13.5%，InterCode 72% |
| **D-CIPHER** | Planner/Executor 多代理 | Planner 拆任务、Executor 新上下文、Auto-prompter | NYU 19–22%，Cybench 22.5% |
| **CRAKEN** | D-CIPHER + RAG | 执行期注入知识、Self-RAG/Graph-RAG、hallucination grading | NYU 22% |
| **HackSynth** | Planner + Summarizer | 每轮一条命令；滚动摘要；容器 + 防火墙 | PicoCTF/OverTheWire 基准 |
| **CTF-Agent**（hvbhanot） | Planner/Specialist/Verifier | scratchpad、结构化 ReAct JSON、44 工具、flag 溯源 | 本地 Ollama，无公开大基准 |
| **CAI** | 通用安全 agent 框架 | Agents/Tools/Handoffs/Patterns/Turns/Tracing/Guardrails/HITL | 偏渗透/ bounty，非 CTF 专用 |
| **Plain Agents** | ReAct&Plan | 完整历史（截断）、30 turns、预装工具、best-of-5 | InterCode 81/85 = 95% |
| **CTFusion** | Live CTF 评测 | MCP 接口、提交代理、每 agent 独立状态 | Live 5–7%，静态 12–17% |

---

## 2. 机制对照

| 维度 | NYU baseline | EnIGMA | D-CIPHER | CRAKEN | HackSynth | CTF-Agent | CAI | Plain Agents | pi4ctf（目标） |
|---|---|---|---|---|---|---|---|---|---|
| 主循环 | ReAct | ReAct | Planner→Executor | Planner→Executor + RAG | Planner→Summarizer | Planner→Specialist→Verifier | ReAct / patterns | ReAct + Plan | **单循环 + 路由板** |
| 规划 | 无 | 弱 | 强（独立 Planner） | 强 + 知识 | 隐式（Planner） | 强（Planner） | 可配 | 开头 + 中途 | **轻量路由板（≤3）** |
| 上下文 | 原始历史 | LM summarizer | Executor 新上下文 | 摘要 + RAG | 滚动 LLM 摘要 | scratchpad | 可配 | 完整历史 + 截断 | **确定性整形 + artifact** |
| 知识 | 无 | demos | 无 | Self-RAG/Graph-RAG | 无 | playbooks | 工具 | 无 | **执行期按需 RAG/skill** |
| 工具 | 专用工具 | 交互 PTY | 专用工具 | 同 D-CIPHER | 单命令 | 44 工具 | 通用工具 | 预装宽工具 | **bash/read/write + 3 CTF 工具** |
| 验证 | 提交 flag | 提交 flag | 提交 flag | 提交 flag | 提交 flag | Verifier + 溯源 | 可配 | 提交 flag | **provenance + oracle** |
| 多代理 | 否 | 否 | 是 | 是 | 否（双模块） | 是 | 是 | 否 | **默认否；卡住才换上下文** |
| 停止 | 轮数/成本 | 轮数/成本 | 轮数/成本 | 轮数/成本 | 最大迭代 | 预算 | HITL | 成本/轮数 | **预算 + 无进展 + 时间盒** |
| 人 | 无 | 无 | 无 | 无 | 无 | 提示注入 | HITL | 无 | **边界确认；不参与解题** |

---

## 3. 哪些机制真的有用

### 3.1 有数据/强信号支持

1. **ReAct + 规划 + 宽工具 + 预算**  
   Plain Agents 在 InterCode 到 95%；10 turns→30 turns、预装工具、best-of-k 都有正收益。  
   → 机制上必须有“计划 + 足够 turns + 预装环境 + 受控重试”。

2. **执行期知识注入 > 规划期知识注入**  
   CRAKEN：执行期 RAG 21%，知识型 planner 17%；RE 33.3% vs 21.6%，web 15.8% vs 10.5%。  
   → 不要在开头灌一堆知识；在选定路线、需要细节时再检索。

3. **上下文隔离能救难题**  
   D-CIPHER 的 Executor 用新上下文，Planner 只看摘要；Context Segmentation 多解 18.52% 原失败任务。  
   → 不是“多代理角色扮演”，而是“卡住时换干净上下文”。

4. **验证/溯源是必要的**  
   EnIGMA 48.4% soliloquy；CTF-Agent 用 Verifier 做格式 + 溯源 + 自反思。  
   → flag 必须能指回真实输出；模型自述不算。

5. **交互 PTY 对 pwn/rev 有用，但不是万能**  
   EnIGMA IATs +2.1pp、turns −22.8%；web 反而下降。  
   → 按类别启用，不默认所有题都开 PTY。

### 3.2 有收益但有明显代价

1. **多代理 Planner/Executor**  
   D-CIPHER 19–22% vs EnIGMA 13.5%，但成本、调度、上下文截断都增加；CRAKEN 再加 RAG 只到 22%。  
   → 默认单 agent；把“隔离上下文”做成按需 worker，而不是常驻 Planner。

2. **LLM Summarizer**  
   HackSynth/EnIGMA 用它压上下文；但 EnIGMA 的 simple summarizer 反而 −2.6pp，LM summarizer 只小幅正收益；CRAKEN 的生成式知识 72.7% 未过幻觉检查。  
   → 默认确定性整形 + artifact；需要摘要时由模型显式决定。

3. **大规模工具集**  
   CTF-Agent 44 工具；但没有公开大基准证明“多工具=高 solve”。  
   → 工具数量不是能力；观察质量和选择策略才是。

### 3.3 明确不要照搬

- **静态 benchmark 分数**：CTFusion 显示 live 5–7% vs 静态 12–17%，web search 可直接抄 flag。  
- **规划期灌知识**：CRAKEN 已证明执行期更好。  
- **为多代理而多代理**：收益主要来自上下文隔离，不是角色。  
- **LLM 摘要当默认压缩**：会丢细节、会幻觉。  
- **无预算的自主循环**：CTFusion 常见失败是 cost limit / stall / giveup。

---

## 3.5 可吸纳的具体优点（按优先级）

| # | 来源 | 优点 | 怎么适配到 pi4ctf | 优先级 |
|---|---|---|---|---|
| 1 | HackSynth | **一轮一条命令**，易归因、易回放 | `ctf_run`/`ctf_session` 一次一个动作；`purpose` 必填；attempt 绑 `commandId` | P0 |
| 2 | HackSynth | **只看新观察**，历史靠滚动状态 | `ctf_run` 返回本次 delta/summary + artifact；`ctf_case status` 给滚动摘要 | P0 |
| 3 | D-CIPHER | **Auto-prompter 先探索再规划** | 新增 `Brief` 阶段：≤5 次便宜观察后写“题目简报 + 3 路线”，不另起 agent | P0 |
| 4 | D-CIPHER / segmentation | **Executor 用新上下文**，Planner 只看摘要 | 卡住时 `pi-subagents` 开 fresh-context worker；只给 artifact 引用，不给全历史 | P1 |
| 5 | CRAKEN | **执行期知识注入**，且拆成聚焦子查询 | 选定路线/要写 exploit 时检索；2–4 锚点 + 指纹；引用 `source+chunk_id` | P0 |
| 6 | CRAKEN | **检索结果要评分/防幻觉** | 只把“下一步/参数/约束”注入；环境假设必须复核；不整篇倒上下文 | P0 |
| 7 | CTF-Agent | **Scratchpad**：上下文/计划/步骤/findings/flags/error | `ctf_case` 的 `state.json` + `evidence.md`；error 单独记 failure tag | P0 |
| 8 | CTF-Agent / EnIGMA | **Verifier + 溯源**，防模型自述 flag | `ctf_case flag` 四层门禁：格式→artifact→oracle→去 decoy | P0 |
| 9 | D-CIPHER / CRAKEN | **只有中心角色能提交/give up** | 只有 `ctf_case flag` 能写 `flag.txt`；hook 阻止直接 write；give-up 用预算/审计代替 | P0 |
| 10 | Plain Agents | **中途再规划**，不只开头计划 | 每 6 步/路线失败触发 `audit` + 更新路由板 | P0 |
| 11 | Plain Agents | **best-of-k 只在高价值时用** | near-miss 才重试；换参数/种子，不重复同一轨迹 | P1 |
| 12 | EnIGMA | **交互工具的命令集**（start/step/send/stop） | `ctf_session` 提供通用 PTY；gdb/pwntools 的操作步骤写进 skill，不另做工具 | P1 |
| 13 | CTF-Agent | **运行时人工提示注入** | 用户中途输入 hint → `ctf_case fact`（标记 source=user）→ 下一轮可见 | P1 |
| 14 | HackSynth / CAI | **Guardrails/防火墙** | `allowedHosts` + 危险命令拦截 + Docker/WSL 隔离；每次执行前检查 | P0 |
| 15 | CAI | **Tracing**：每轮可审计 | `events.jsonl` 记录 state/action/observation；artifact 内容寻址 | P0 |
| 16 | EnIGMA | **开发集/测试集分离** | 15 题 dev 调参，CTFTiny 50 只做发布评测 | P0 |
| 17 | CTFusion | **Live CTF + 提交代理** | v1 不做；bench 预留 adapter，最终用 live 复核 | P2 |
| 18 | Cybench | **子任务/多 scaffold 消融** | 只用于评测分析：同题不同 scaffold，不把子任务写进解题循环 | P2 |

### 不吸纳

| 做法 | 原因 |
|---|---|
| LLM 摘要作为默认压缩 | EnIGMA simple summarizer 反而 −2.6pp；CRAKEN 生成知识 72.7% 未过幻觉检查 |
| 规划期灌知识 | CRAKEN：执行期 21% vs 规划期 17% |
| 44 个工具 | 没有证据表明工具数量提升 solve；观察质量更重要 |
| 常驻 Planner/Executor | 收益主要来自上下文隔离；常驻多代理增加成本和调度 |
| give-up 工具 | CRAKEN 显示模型 give-up 率差异大、可能过早；用预算/审计/失败报告替代 |
| 静态 benchmark 当能力 | CTFusion：live 5–7% vs 静态 12–17% |
| v1 上 Graph-RAG/Neo4j/Milvus | 重；先用现有 `ctf_rag` + 结构化查询，数据证明后再加 |

---

## 4. pi4ctf 的解题机制

### 4.1 角色（全部在一个 agent 内）

| 角色 | 由谁承担 | 职责 |
|---|---|---|
| 决策者 | 模型 | 分类、假设、选路线、写 exploit |
| 感知层 | `ctf_run` / `ctf_session` | 执行、整形、artifact |
| 记忆 | `.ctf/state.json` + `evidence.md` | 事实、路线、attempt、候选 |
| 验证者 | `ctf_case flag` + oracle | 格式、溯源、机器确认 |
| 预算官 | TS 工具层 | 时间、turns、cost、无进展 |
| 升级器 | `pi-subagents`（可选） | 卡住时换干净上下文 |

**没有独立 Planner / Summarizer / Verifier agent**。  
规划是路由板，摘要是确定性整形，验证是工具门禁。

### 4.2 状态：三张表

1. **Case**：题目、目标、flag 格式、oracle、backend、allowedHosts。
2. **Route board**：≤3 条路线，每条 `hypothesis / test / expected / cost / state / attempts`。
3. **Evidence ledger**：fact、attempt、artifact hash、candidate flag、failure tag。

状态是 JSON + Markdown；上下文丢了可恢复。

### 4.3 循环

```text
bind
  ↓
fingerprint（≤5 次便宜观察）
  ↓
route board（≤3，按最便宜可证伪排序）
  ↓
┌─────────────────────────────────────────────┐
│ pick route                                  │
│   ↓                                         │
│ maybe retrieve knowledge（执行期，按需）     │
│   ↓                                         │
│ act: ctf_run / ctf_session                  │
│   ↓                                         │
│ observe: summary + artifact（确定性）        │
│   ↓                                         │
│ record: fact / attempt / dead / blocked     │
│   ↓                                         │
│ audit every N steps or on failure           │
│   ↓                                         │
│ candidate flag? → verify                    │
│   ↓                                         │
│ update routes / budget / escalate           │
└─────────────────────────────────────────────┘
  ↓
solved → writeup
blocked/timebox → failure report
```

### 4.4 路由板：轻量规划，不另起 agent

每条路线必须回答四个问题：

```yaml
hypothesis: 为什么这题可能这样解
test:       最小可证伪动作（一条命令/一个脚本）
expected:   成功看到什么、失败看到什么
cost:       预计命令数/时间
```

规则：

- 最多 3 条；只执行一条。
- 最便宜可证伪优先；不做“大而全”的利用链。
- 失败两次不同尝试 → `dead`；环境/权限问题 → `blocked`，不是 dead。
- 有新证据（新地址、新偏移、新响应）→ 可以复活 dead。

### 4.5 知识注入：执行期，不预先灌

- 触发：选定路线、准备写 exploit/脚本、或连续失败需要新思路。
- 查询：2–4 个技术锚点 + 指纹（arch/libc/framework）。
- 使用：只取“下一步/参数/约束”，不把整篇 writeup 倒进上下文；引用 `source + chunk_id`。
- 验证：环境假设（glibc/arch/版本）必须复核；RAG 是证据，不是答案。
- 禁止：开头一次性检索一堆类别知识；把 RAG 内容当本题事实。

### 4.6 验证：四层门禁

```text
1. 格式：符合 flagFormat，非占位符
2. 溯源：在真实 command 的 artifact / 工作区文件中出现
3. oracle：本地 ground truth / CTFd / 人工确认
4. 唯一性：排除 decoy（多候选时看来源与上下文）
```

只有 1+2+3 都过才是 `verified`；否则 `candidate`。  
模型在回复里写出的 flag 不进入候选。

### 4.7 预算与停止

| 预算 | 默认 |
|---|---|
| 单题时间盒 | 45 min |
| 单命令超时 | 120 s |
| turns | 30 |
| 活跃路线 | 3 |
| 连续无新证据 | 2 轮 |
| 单次观察 | 16 KB |

停止：

- flag verified；
- 时间盒到；
- 连续 2 轮无新证据且所有路线 dead/blocked；
- 用户中断；
- 预算官判定边际收益为负。

禁止：重复同一命令同一参数；无目的扫描；白名单外请求。

### 4.8 进度审计与升级（来自失败机制）

每 6 步或每次路线失败：

```text
1. 上次命令改变了什么状态？
2. 当前假设被证伪了吗？
3. 是否重复了已失败的命令/参数？
4. 预算还剩多少？下一小时预期收益？
```

升级阶梯：

```text
A. 换参数/换变体重试（同一路线）
B. 换路线（dead 后）
C. 换干净上下文（fresh-context worker）
D. 向用户要最小提示（交互模式）
E. 停，写失败报告
```

不要从 A 直接跳到 E；也不要无限停在 A。

### 4.9 伪代码

```ts
bind()
fingerprint()
routes = proposeRoutes({ max: 3, order: "cheapest_to_falsify" })

while (!budget.exhausted) {
  const route = pick(routes)
  if (!route) break

  const knowledge = needsKnowledge(route) ? retrieve(route, fingerprint) : null
  const result = act(route, knowledge)        // ctf_run / ctf_session
  const obs = observe(result)                 // summary + artifact
  ledger.record(obs)

  if (containsFlag(obs)) {
    const verdict = verifyFlag(extractFlag(obs), obs.artifact)
    if (verdict === "verified") return close("solved")
  }

  updateRoute(route, obs)
  if (auditDue()) audit()
  if (noProgressTwice()) escalate()
}
return close("blocked_or_timeout")
```

---

## 5. 与竞品的差异

| 维度 | 竞品常见做法 | pi4ctf |
|---|---|---|
| 规划 | 独立 Planner agent | 路由板（状态，不是 agent） |
| 上下文 | LLM 摘要 / 全历史 | 确定性整形 + artifact 引用 |
| 知识 | 开头 RAG / 规划期注入 | 执行期按需注入 |
| 验证 | 提交 flag / 自反思 | provenance + oracle 硬门禁 |
| 多代理 | 常驻 Planner/Executor | 默认单 agent；卡住才换上下文 |
| 工具 | 44 个 / 专用工具集 | 3 个 CTF 工具 + pi 内置 |
| 停止 | 轮数/成本 | 预算 + 无进展 + 时间盒 + 升级阶梯 |
| 评测 | 静态 benchmark | 闭卷 + live CTF 复核 |

---

## 6. 需要验证的假设

1. 路由板是否比自由 ReAct 更少重复、更高 solve？（15 题 A/B）
2. 执行期 RAG 是否比开头 RAG 更省 token/更高 solve？（参考 CRAKEN 方向）
3. 确定性整形是否比 LLM 摘要更少丢细节、更少幻觉？（raw vs shaped vs LLM summary）
4. provenance + oracle 是否把误报降到 0，且不显著拖慢？（ledger on/off）
5. 卡住时 fresh-context worker 是否正收益？（单循环 vs fallback）
6. 3 工具是否不弱于 9 工具/44 工具？（工具面消融）

---

## 7. 来源

- EnIGMA: <https://arxiv.org/abs/2409.16165>
- D-CIPHER: <https://arxiv.org/abs/2502.10931>
- CRAKEN: <https://arxiv.org/abs/2505.17107>
- HackSynth: <https://arxiv.org/abs/2412.01778>
- CTF-Agent: <https://github.com/hvbhanot/CTF-Agent>
- CAI architecture: <https://github.com/aliasrobotics/cai>
- Plain Agents: <https://arxiv.org/abs/2412.02776>
- CTFusion: <https://arxiv.org/abs/2605.11504>
- Cybench: <https://arxiv.org/abs/2408.08926>
- Context Segmentation: <https://arxiv.org/abs/2609.12839>
