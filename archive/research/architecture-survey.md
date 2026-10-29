# 更多 CTF/安全 Agent 与优秀架构调研 v0.1

> 目标：扩大样本，找出**可以吸纳的架构**，而不是继续堆功能。
> 结论：最值得吸纳的是 **event-sourced 状态、artifact handoff、evidence grading、execution-verified traces、resume/checkpoint**。
> 最不该照搬的是 **常驻多代理、Web UI/插件框架、44 工具/206 技能、Graph DB**。

---

## 1. 项目清单

| 项目 | 类型 | 架构 | 值得看的一点 | 吸纳/拒绝 |
|---|---|---|---|---|
| **OpenHands** | 通用 coding agent | Event-sourced runtime | 不可变 append-only 事件日志；typed events；condensation | **吸纳事件模型** |
| **Anthropic Research** | 多代理研究 | Orchestrator-worker | 90.2% 提升；15× token；artifact 文件交接；citation agent | **吸纳 artifact handoff / 预算**；拒绝常驻多代理 |
| **Confucius Code Agent** | 大规模 coding agent | 统一 orchestrator + 持久笔记 | SWE-Bench-Pro 59%；persistent note-taking；meta-agent | 吸纳持久笔记/恢复 |
| **SWE-agent** | coding agent | ACI | 工具接口设计 +10.7pp | 已吸纳（观察契约） |
| **CodeAct** | 通用 agent | 代码即动作 | 统一 action space；最高 +20% 成功率 | **吸纳“优先写脚本”** |
| **ReWOO** | 规划/执行解耦 | Planner → Workers，无观察回灌 | 5× token 效率；+4% HotpotQA | 吸纳“批量探针”思路，不照搬 |
| **LATS** | 搜索型 agent | MCTS + reflection | 树搜索 + 反思 | 以后用于 hard pwn/crypto |
| **Voyager** | 具身 agent | 技能库 + 课程 + 自验证 | 可复用技能复利 | 吸纳技能库，但需验证/去重 |
| **CTF-Dojo** | 训练环境 | 658 个可执行 CTF；486 条 verified 轨迹 | **+11.6% 绝对提升；32B 31.9% pass@1** | **吸纳 verified trace 数据飞轮** |
| **Cyber-Zero** | 无 runtime 训练 | 从 writeup 反推模拟轨迹 | 无环境也能造训练数据 | 后期；需防泄漏 |
| **EnIGMA** | CTF agent | ReAct + IAT + summarizer | 交互 PTY；dev set；soliloquy 48.4% | 已吸纳 PTY/验证；拒绝默认 LLM 摘要 |
| **D-CIPHER** | CTF 多代理 | Planner/Executor/Auto-prompter | 上下文隔离；19–22% NYU | 吸纳 fresh-context，拒绝常驻 planner |
| **CRAKEN** | CTF + RAG | D-CIPHER + Self-RAG/Graph-RAG | 执行期注入 21% > 规划期 17% | **吸纳执行期知识**；拒绝 Graph DB |
| **HackSynth** | CTF agent | Planner + Summarizer | 一轮一条命令；new observation window | 已吸纳 delta 观察；拒绝 LLM 摘要默认 |
| **LingXi** | CTF/渗透 | Main + Advisor + Reflector | 分层记忆；flag 快路径；重复路径拦截；经验门控 | **吸纳 advisor/reflector 模式** |
| **BoxPwnr** | CTF 评测框架 | Solver 抽象 + 多 executor + traces | 4,749 题/10,009 traces；progress.md resume；max turns/cost/time | **吸纳 solver/traces/resume** |
| **Cairn** | 通用状态空间/渗透 | Blackboard + Fact/Intent 图 | TCH 唯一 54/54 AK；无角色/RAG；stigmergy；OODA | **吸纳图机制**；拒绝 Server/Dispatcher 重型运行时 |
| **Pentest Harness** | 安全 agent 产品 | 插件化 + durable sessions | 会话持久化/回放；上下文压缩；凭据隔离 | 借鉴 durable/replay；拒绝整套插件框架 |
| **xorcise** | 安全评测 | Evidence grading | 归一化事件、隔离网络、决定论检查 + judge | **吸纳 evidence grading** |
| **CTF-Agent** | CTF 多代理 | Planner/Specialist/Verifier | scratchpad；verifier 溯源；44 工具 | 已吸纳 scratchpad/verifier；拒绝工具数量 |
| **CAI** | 安全 agent 框架 | Agents/Tools/Handoffs/HITL | 8 支柱；tracing；guardrails；半自主 | 吸纳 tracing/guardrails/HITL |
| **CTFusion** | Live CTF 评测 | MCP + 提交代理 | live 5–7% vs 静态 12–17% | 吸纳 live 评测/独立状态 |
| **Cyber-Zero / CTF-Dojo** | 训练 | 轨迹/模拟 | 执行验证轨迹可训练 | 后期数据飞轮 |

---

## 2. 优秀架构拆解

### 2.1 Event-sourced runtime（OpenHands）

**做法**：所有 agent 行为是 typed event，append-only 日志；事件分 LLM-visible 与 internal；`source`（user/agent/environment）与 LLM `role` 分离；压缩用 condensation event。

**为什么好**：

- 状态可重建；调试/回放/审计天然成立。
- 事件来源清晰：observation 来自 environment，不来自模型。
- 压缩不丢历史：只标记 forgotten event ids + summary。

**对 pi4ctf**：

- `.ctf/events.jsonl` 升级为 **typed append-only log**：`case_init`、`action`、`observation`、`fact`、`route_update`、`flag_candidate`、`oracle_result`、`audit`、`checkpoint`。
- 每条事件有 `id/ts/source/type/payload/artifact_hash`。
- `state.json` 是投影（projection），不是唯一事实源；`state` 可重建。
- `flag.txt` 只能由 `ctf_case flag` 的 verified 事件触发。

### 2.2 Orchestrator-worker + artifact handoff（Anthropic）

**做法**：lead agent 规划，3–5 个 subagents 并行；subagent 把结果写文件，返回轻量引用；citation agent 统一验证引用。

**数据**：内部研究 eval 比单 agent 高 90.2%；但多代理约 **15× token**；token 使用解释 80% 性能方差。

**为什么好**：并行扩展 token 预算；独立上下文减少 path dependency；artifact 避免“传话游戏”。

**对 pi4ctf**：

- CTF 更像 coding（共享状态、强依赖），不是 breadth-first research，所以**默认单 agent**。
- 只在“独立路线”上开 worker：每条路线一个 fresh context，写 `scratch/route-<id>.md` + artifact refs，父级合并。
- 不做常驻 lead/worker；`pi-subagents` 按需。

### 2.3 Planner-executor + context isolation（D-CIPHER / CRAKEN）

**做法**：Planner 拆任务；Executor 新上下文执行并返回摘要；Auto-prompter 先探索；CRAKEN 在 delegation 时注入知识。

**数据**：D-CIPHER 19–22% NYU；CRAKEN 执行期 RAG 21% > 规划期 17%；72.7% 生成知识未过幻觉检查。

**对 pi4ctf**：

- 用 **Brief + Route board** 代替 Planner agent。
- 执行期注入知识；不预先灌。
- fresh-context 只用于卡住路线，不常驻。

### 2.4 Main + Advisor + Reflector（LingXi）

**做法**：主攻手直接执行；Advisor 在卡点/失败累积时做一次性纠偏；Reflector 对失败路径分层归因；分层记忆（运行记忆 / 结构化经验 / 外部 writeup）。

**为什么好**：不引入常驻多代理，只在“高价值卡点”花第二次推理；失败归因能改变策略。

**对 pi4ctf**：

- 每 6 步/路线失败触发 **Audit**（不是每次都问 Advisor）。
- 需要时用 `pi-subagents` 开一个 **advisor**（只读、无执行工具）或 **reflector**（读事件日志，输出 failure tag + 下一步）。
- 经验写回 `lessons/`，但必须验证过、带 scope。

### 2.5 Solver 抽象 + traces + resume（BoxPwnr）

**做法**：同一套 harness 支持 `single_loop`、`compaction`、`hacksynth`、Claude Code/Codex 等 solver；统一 trace；`progress.md` 可 resume；max turns/cost/time/attempts。

**数据**：4,749 题、10,009 traces；多平台适配。

**对 pi4ctf**：

- bench 层抽象 `solver = pi4ctf | omp | ...`，统一 trace 格式。
- `ctf_case status` 生成 `progress.md`；下一次可 `resume`。
- 预算参数统一：turns/cost/time/attempts。
- trace 用于回放、失败分析、训练数据。

### 2.6 CodeAct：代码即动作

**做法**：不让模型只选工具，而是写可执行 Python/JS 作为统一 action；可组合、可调试。

**数据**：最高 +20% 成功率（API-Bank/新 benchmark）。

**对 pi4ctf**：

- skill 明确：**若需要 2 步以上，写脚本，而不是连发多条命令**。
- `ctf_run` 执行脚本；`ctf_session` 保留交互状态。
- 不新增工具；把“代码优先”写进 CTF_MODE/skill。

### 2.7 Evidence grading（xorcise / CTF-Agent）

**做法**：归一化事件（command/tool/message），确定性检查 + judge 评分；隔离网络；报告证据而非声明。

**对 pi4ctf**：

- flag：确定性 oracle + provenance，不用 judge。
- writeup：可在 bench 层用 judge 检查“步骤是否有事件支持”。
- 审计：`events.jsonl` 归一化，`ctf_case status` 只读投影。

### 2.8 Execution-verified traces / data flywheel（CTF-Dojo / Cyber-Zero）

**做法**：CTF-Dojo 658 个可执行题、486 条 verified 轨迹 → +11.6% 绝对提升，32B 31.9% pass@1；Cyber-Zero 从 writeup 反推模拟轨迹，无 runtime 训练。

**对 pi4ctf**：

- 每次 solved 保存 `trace.json`：state、actions、observations、artifacts、oracle。
- 先用于检索（相似状态-动作）和失败分析；数据足够后再考虑 SFT/RL。
- 不做 runtime-free 伪造轨迹，避免学到错误观察；真实执行优先。

### 2.9 ReWOO：规划与观察解耦

**做法**：Planner 一次生成完整计划，Workers 执行，不把观察回灌 Planner；5× token 效率。

**对 pi4ctf**：

- 不照搬（CTF 需要根据观察转向）。
- 可借“批量独立探针”：一次计划 2–3 个互不依赖的检查，批量执行，减少往返。

### 2.10 搜索型 agent（LATS / AlphaCode / FunSearch）

**做法**：树搜索/MCTS/进化搜索 + 执行器评估；LLM 负责提议，搜索负责分配算力。

**对 pi4ctf**：

- v1 不做；作为 hard pwn/crypto 的后续实验（B1 赌注）。
- 需要先有稳定的执行/评估/状态，否则搜索只是在噪声上烧钱。

---

### 2.11 Blackboard + Fact/Intent 图（Cairn / TCH）

**做法**：

- 三个原语：**Fact**（已确认事实，图节点）、**Intent**（从 Fact 出发的探索边）、**Hint**（人类提示，图外）。
- Fact 只增不改；状态变化写新 Fact；Intent 可有多个 `from`（超边）。
- Agent 只做 OODA：读图 → 判断 → 声明/认领 Intent → 执行 → 写 Fact。
- 无固定角色；Agent 之间不直接通信，只通过共享图协调（stigmergy）。
- 任务类型：Bootstrap（直接尝试）、Reason（读图判断 complete/新 intent）、Explore（认领一个 intent，产出一个 Fact）。
- 长数据不进 Fact，引用 artifact 路径。

**证据**：TCH 腾讯云黑客松智能渗透赛，610 队/1345 人；**54/54 唯一 AK**；5 天约 7692 元、10.9 亿 tokens；第 4 天 0 flag，第 5 天注入人类 Hint 后 AK。公开资料对最终名次有 3/4 名不同表述。

**对 pi4ctf**：把线性 route board 升级为**单 agent 的 Fact/Intent 图**；文件图 + 3 个工具，不做 Cairn 的 Server/Dispatcher/容器/Web UI。只借鉴思想，不复制 AGPL 代码/提示词。

---

## 3. 对 pi4ctf 的具体吸纳

| 吸纳 | 具体改动 | 阶段 |
|---|---|---|
| Typed event log | `events.jsonl` 事件化；`state.json` 变投影 | P0 |
| Artifact handoff | subagent 写 `scratch/report.md` + refs，父级读引用 | P1 |
| Resume | `status` 生成 `progress.md`；`ctf_case init --resume` 读取 | P1 |
| Evidence grading | flag 确定性门禁；writeup 事件校验 | P0/P2 |
| Fact/Intent graph | 用 `graph.jsonl` 替代 route board；Bootstrap/Reason/Explore | P0 |
| Verified traces | solved 后写 `traces/<id>.json`；用于检索/分析 | P1 |
| Advisor/Reflector | 卡点一次性 subagent；failure tag + 下一步 | P1 |
| Solver abstraction | bench 统一 `--solver pi4ctf/omp/...` | P1 |
| Code-first | skill/CTF_MODE 要求“多步写脚本” | P0 |
| Batch probes | 2–3 个独立检查批量执行 | P2 |
| Search over actions | hard 子集实验（B1） | P3 |

---

## 4. 明确不吸纳

| 架构 | 原因 |
|---|---|
| 常驻多代理/Orchestrator-worker | Anthropic 自身说 coding/共享上下文不适合；15× token；CTF 强依赖 |
| Web UI + 插件框架（Pentest Harness） | 与 pi 的 minimal 冲突；维护面大 |
| 44 工具/206 技能 | 工具/技能数量不等于能力；上下文膨胀 |
| Graph-RAG/Neo4j/Milvus（CRAKEN） | v1 太重；现有 `ctf_rag` 足够，数据证明后再加 |
| LLM 摘要默认压缩 | 会丢细节/幻觉；确定性整形 + artifact 更好 |
| Runtime-free 合成轨迹（Cyber-Zero） | 容易学到错误观察；先积累真实 verified traces |
| 静态 benchmark 当能力 | CTFusion 已证明会虚高 |

---

## 5. 更新后的 pi4ctf 架构

```text
pi 1.4
├─ extensions/ctf.ts          # 3 tools + /ctf + CTF_MODE
├─ skills/ctf/SKILL.md        # loop + decision cards + code-first
├─ bin/ctf-rt                 # Rust: exec/pty/shape/artifact
└─ .ctf/
   ├─ case.json
   ├─ state.json              # projection
   ├─ events.jsonl            # typed append-only log
   ├─ brief.md
   ├─ progress.md             # resume
   ├─ evidence.md
   ├─ artifacts/
   └─ traces/                 # verified runs, later retrieval
```

新增的不是工具，而是**状态形态**：

- `events.jsonl` 是事实源；`state.json` 可重建。
- `progress.md` 支持中断恢复。
- `traces/` 支持回放、失败分析、后续训练。
- `scratch/` 支持 subagent artifact handoff。

仍然是 **一个 Rust 二进制、三个工具、一个循环**。

---

## 6. 来源

- OpenHands events: <https://docs.openhands.dev/sdk/arch/events>
- Anthropic multi-agent research: <https://www.anthropic.com/engineering/multi-agent-research-system>
- Confucius Code Agent: <https://arxiv.org/abs/2512.10398>
- CodeAct: <https://arxiv.org/abs/2402.01030>
- ReWOO: <https://arxiv.org/abs/2305.18323>
- CTF-Dojo: <https://arxiv.org/abs/2508.18370>
- Cyber-Zero: <https://arxiv.org/abs/2508.00910>
- LingXi: <https://github.com/adrian803/LingXi>
- BoxPwnr: <https://github.com/0ca/BoxPwnr>
- Pentest Harness: <https://github.com/S1N6H/pentest-harness>
- xorcise: <https://github.com/xorcise-ai/xorcise>
- CTF-Agent: <https://github.com/hvbhanot/CTF-Agent>
- CAI: <https://github.com/aliasrobotics/cai>
- EnIGMA: <https://arxiv.org/abs/2409.16165>
- D-CIPHER: <https://arxiv.org/abs/2502.10931>
- CRAKEN: <https://arxiv.org/abs/2505.17107>
- HackSynth: <https://arxiv.org/abs/2412.01778>
- CTFusion: <https://arxiv.org/abs/2605.11504>
- Voyager: <https://arxiv.org/abs/2305.16291>
- LATS: <https://arxiv.org/abs/2310.04406>
- Cairn: <https://github.com/oritera/Cairn>
- TCH 复盘（镜像）: <https://zone.ci/secarticles/wx/526000.html>
