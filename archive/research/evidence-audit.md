# 证据审计与突破假设 v0.1

> 直说：现有论文**不能**证明 pi4ctf 的具体设计能提高 CTFTiny/Live CTF 的解题率。
> 它们只能支持一些先验，并警告一些坑。真正有效的证据只能自己跑出来。
> 本文把设计分成三类：**卫生措施（table stakes）**、**有间接证据的杠杆**、**未验证的突破赌注**。

---

## 1. 证据审计：哪些数据能信到什么程度

| 主张 | 来源 | 实验设置 | 观测效果 | 迁移到“pi4ctf + 现代模型 + CTF”的风险 | 判定 |
|---|---|---|---|---|---|
| 简单 ReAct&Plan 足够强 | Plain Agents (2024) | InterCode-CTF（picoCTF，高中级），GPT-4o/o1 | 81/85 = 95% | benchmark 偏简单；现代模型可能已饱和；不能外推到 pwn/forensics | **直接但低难度** |
| 交互工具（gdb/pwntools）有用 | EnIGMA (ICML 2025) | NYU/CyBench/InterCode，Claude 3.5 | IATs +2.1pp；turns −22.8%；NYU 13.5% | 模型旧；类别差异大（web 反而下降）；静态集可能污染 | **间接** |
| 多代理 planner/executor 更强 | D-CIPHER (2025) | NYU/CyBench/HTB，Claude 3.5 | NYU 19–22% vs 13.5% | 模型旧；静态集污染；成本/调度未计入 solve | **弱** |
| 上下文分段能救小模型 | Context Segmentation (2026) | picoCTF，gemma-4-E2B/E4B | E4B 多解 18.52% 原失败任务；token 优于 best-of-4 | 小模型专属；简单题会过度复杂化；前沿模型未必受益 | **间接（小模型）** |
| 定位关键错误再重跑 | AgentDebug (2025) | ALFWorld/GAIA/WebShop | 最高 +26% 相对提升 | 不是 CTF；CTF 状态更难快照/重放；错误定位本身可能错 | **间接（非 CTF）** |
| ACI/接口设计影响成绩 | SWE-agent (NeurIPS 2024) | SWE-bench，GPT-4 | 约 +10.7pp | 软件工程，不是 CTF；但“接口是变量”可迁移 | **间接** |
| 工具格式能吃掉模型能力 | omp harness blog (2026) | React 代码编辑，16 模型 | Grok Code Fast 6.7→68.3%；输出 token −61% | 编辑格式，不是 CTF；说明“表示方式”重要 | **类比** |
| 静态 CTF benchmark 会虚高 | CTFusion (2026) | 5 场 Live CTF + NYU 180 | Live 5–7% vs 静态 12–17%；web search 可抄 flag | 直接警告：CTFTiny 结果也不能当真实能力 | **直接（评测）** |
| 失败集中在中段、会传播 | AgentErrorTaxonomy (2025) | ALFWorld/GAIA/WebShop | step 6–15 为主；memory/reflection 主导 | 非 CTF，但长轨迹结构相似 | **间接** |
| 技能库可复利 | Voyager (2023) | Minecraft | 自动课程 + 技能库 + 自验证 | 具身任务；CTF 技能的可执行性/验证不同 | **弱** |
| Live CTF 类别难度 | CTFusion | 5 场 live | misc/rev 较易；pwn/crypto/forensics 持续难；失败多为 cost/stall/giveup | 直接说明优先级，但样本小、模型旧 | **直接（方向）** |

### 结论

1. **有数据支持的**：简单 agent 在简单 CTF 上很强；live CTF 比静态难很多；静态 benchmark 会虚高；接口/上下文/恢复很重要。
2. **没有数据支持的**：我们的“Observation Contract + Ledger + Rust runtime + 配方卡”组合，能在 CTFTiny/Live CTF 上提高多少 solve。
3. **被数据反对的**：复杂交互工具并非总是有益；多代理收益有限；上下文分段对简单题有害；LLM summarizer 不一定比无 summarizer 好；web/RAG 会带来作弊/泄漏。

---

## 2. 哪些是“老套”，哪些是“赌注”

| 类别 | 内容 | 评价 |
|---|---|---|
| 卫生措施 | 状态机、账本、观察整形、超时、flag oracle、技能按需 | **必要，但不构成差异化**；别人也能做 |
| 有间接证据 | 交互 PTY、配方卡、指纹检索、best-of-k、fresh-context | 值得做，但要 A/B；不要当真理 |
| 未验证赌注 | 可执行搜索、轨迹条件策略、状态级反事实重放、自适应算力 | **可能突破，也可能失败**；必须预注册 + 消融 |

如果项目要有特点，特点必须落在第三类，而不是第一类。

---

## 3. 三个突破赌注（可证伪）

### B1：把 CTF 解题变成“可执行动作空间上的搜索”

**现状**：ReAct 一次只走一条自然语言动作，靠模型“想下一步”。难题上搜索深度不够。

**赌注**：

- 为高价值类别定义**动作/状态空间**：
  - pwn：primitive 图（leak/write/control），动作 = 尝试一种原语/链
  - crypto：攻击模板 + 参数（RSA/AES/ECC/PRNG/格）
  - web：请求变异 + 响应差分（payload grammar）
- LLM 负责**提议**候选动作/程序；执行器负责**验证**；外层用 best-first / beam / bandit 分配算力。
- 不要求 LLM 记住整条轨迹；状态由 runtime 维护。

**假设**：在 hard 子集（pwn/crypto 的 10–15 题）上，同模型同预算，solve 比自由 ReAct 高 ≥10pp，或同 solve 下 token/cost 低 ≥30%。

**类比证据**：AlphaCode 的大规模采样+过滤、FunSearch 的 LLM+评估器+进化搜索；但**没有 CTF 直接证据**。

**失败条件**：DSL 设计成本过高；LLM 提议命中率低；搜索开销吃掉收益；只在简单题有效。

**最小实验**：只做 crypto 的 5 个攻击模板 + pwn 的 ret2libc/format-string 两个模板；10 题 A/B。

---

### B2：用“已验证轨迹”做检索，而不是用 writeup 做 RAG

**现状**：RAG 检索的是文章，模型仍要自己把文章映射到当前状态；而且静态 writeup 可能泄漏/过时。

**赌注**：

- 记录每条成功/失败轨迹的 `(state fingerprint, action, observation, outcome, fix)`。
- 检索相似**状态-动作-修复**片段，作为 in-context 示例；不是整篇 writeup。
- 数据来自自己的验证轨迹，可控制质量与泄漏。

**假设**：在同类题上，轨迹检索比 writeup RAG 的 next-action accuracy 更高，solve 提升 ≥5pp；或相同 solve 下 turns 更少。

**类比证据**：Voyager 技能库、AgentDebug 的 failure-fix 反馈；CTF 领域缺失。

**失败条件**：轨迹太少；状态指纹不可比；检索到错误经验；过拟合到训练题。

**最小实验**：先在 15 题上收集 30–50 条轨迹；对 5 题做“有/无轨迹检索”的配对比较。

---

### B3：状态级反事实重放（不是从头发送）

**现状**：失败后要么重跑整题，要么 best-of-k；成本高，且重复已确认事实。

**赌注**：

- runtime 保存命令、artifact、环境指纹、关键状态快照（文件系统 diff、PTY 缓冲、HTTP session）。
- 失败时定位**最早的关键错误状态**，从该状态重放，而不是从第 0 步。
- 反馈针对该错误（错误偏移/错误假设/错误环境），不是泛泛“再试一次”。

**假设**：卡住题的 recovery rate 提升 ≥20% 相对；重跑 token 比 full restart 低 ≥40%。

**类比证据**：AgentDebug 在 ALFWorld/GAIA/WebShop 最高 +26% 相对；**非 CTF**。

**失败条件**：CTF 状态难以快照（pwn 堆/网络连接）；关键错误定位不准；重放不确定。

**最小实验**：先在确定性 crypto/forensics 题上做文件级快照；pwn/web 后置。

---

### B4（可选）：自适应算力分配

**现状**：所有题/路线平均用力；EnIGMA 显示成功多在前 20 步，失败常拖到预算耗尽。

**赌注**：用进度信号（新事实数、差分变化、oracle 响应）做 bandit，决定“加注/换路/放弃”。

**假设**：同 solve 下 cost 降 ≥25%；或同 cost 下 solve 升 ≥5pp。

**失败条件**：信号噪声大；过早放弃；对难题系统性低估。

---

## 4. 实验设计：怎样才算“有数据”

### 4.1 预注册

每个赌注先写死：

- 假设与方向（单侧）
- 最小有意义效应（例如 +10pp / −30% cost）
- 样本量与停止规则
- 主指标与次指标
- 失败/回退条件

### 4.2 规模

| 阶段 | 题量 | 用途 | 能得出的结论 |
|---|---|---|---|
| 开发 | 15 题分层 | 迭代、找 bug | **不能**对外声称效果 |
| 发布 | CTFTiny 50 | 主评测 | 只能检测较大效应；CI 仍宽 |
| 最终 | NYU 200 / Live CTF | 泛化与防污染 | 才能谈“能力” |

### 4.3 统计

- 同模型、同预算、同 prompt、同网络策略；配对题目。
- 每个配置 ≥3 seeds；报告均值、bootstrap 95% CI。
- 二分类用 McNemar（配对）；连续指标用配对 bootstrap。
- 负控制：只改工具名/描述（应无显著差异）；随机检索；随机重放点。
- 报告 cost-per-solve，不只 solve rate。

### 4.4 指标

`solve`（分类）、`false flags`、`cost`、`tokens`、`turns`、`stall rate`、`recovery rate`、`triage hit`、`repeat rate`。

### 4.5 失败即结论

- B1 若 hard 子集 +<10pp 或 cost >1.5× → 放弃 DSL 搜索。
- B2 若轨迹检索 +<5pp → 退回普通 RAG。
- B3 若 recovery +<20% 相对 → 只保留全量重跑。
- B4 若 cost 降 <15% → 去掉 bandit。

---

## 5. 最小验证顺序（先便宜后昂贵）

1. **搭 15 题 harness + 失败标签**（1 周内可跑）。
2. **B3-lite**：确定性题的 artifact 快照 + 从错误步重放；最便宜，直接验证“恢复”假设。
3. **B1-lite**：crypto 5 个攻击模板 + pwn 2 个模板；验证“搜索 > 自由 ReAct”。
4. **B2-lite**：收集 30–50 条轨迹，做 5 题配对检索。
5. 只有以上有正效应，才投入 Rust runtime / 大规模 DSL / 经验库。

---

## 6. 诚实的结论

- **卫生措施**让系统不犯低级错误，但不保证比别人强。
- **间接证据**支持“接口、上下文、恢复”方向，但不能证明我们的组合有效。
- **突破**只能来自可执行搜索、轨迹学习、状态级恢复这类改变“搜索/学习回路”的东西；它们目前都**没有 CTF 直接数据**。
- 所以正确姿势不是继续堆设计，而是：**先把 15 题实验台搭起来，用数据决定哪个赌注值得加码。**

---

## 7. 来源

- CTFusion: <https://arxiv.org/abs/2605.11504>
- AgentErrorTaxonomy / AgentDebug: <https://arxiv.org/abs/2509.25370>
- EnIGMA: <https://arxiv.org/abs/2409.16165>
- D-CIPHER: <https://arxiv.org/abs/2502.10931>
- Plain Agents: <https://arxiv.org/abs/2412.02776>
- Context Segmentation: <https://arxiv.org/abs/2609.12839>
- SWE-agent ACI: <https://arxiv.org/html/2405.15793v2>
- omp harness: <https://stencil.so/blog/the-harness-problem>
- Voyager: <https://arxiv.org/abs/2305.16291>
- FunSearch: <https://www.nature.com/articles/s41586-023-06924-6>
- AlphaCode: <https://www.science.org/doi/10.1126/science.abq1158>
