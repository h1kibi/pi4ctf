# TCH 第二届/第三届经验与设计启示 v0.1

> 微信正文直连会触发 captcha；本文综合了作者博客、ZONE.CI/gm7 镜像、GitHub 仓库、SapperLens 逆向分析、腾讯云开发者社区文章。
> 只借鉴设计思想；不复制 AGPL/闭源代码与提示词。

---

## 0. 结论

TCH 头部方案已经收敛出三个共识：

1. **图/黑板是共享状态的核心**：Cairn、sapper-v2、BinX 双图谱、BreachWeave 的 Idea/Memory，本质都是“事实 + 意图/因果”的图。
2. **角色不是越多越好**：Cairn 明确反对固定角色；BreachWeave 用 Manager/Solver/Observer 但强调 Observer 旁路监督；CHYing 用 Orchestrator + 专用子 Agent，并靠 **MCP 可见性**控制上下文。
3. **速度和终止条件比“能不能解”更关键**：动态计分下，慢就是输；ABANDON 停损、Observer、Ralph-Loop、deadline、flag-first 都是工程护栏。

对我们最重要的三条改造：

- **Typed Fact + Intent DAG + Flag Ledger**（Cairn + sapper-v2）。
- **一文件一节点 + 原子写 + flock**，不用 DB/Server/UI（sapper-v2）。
- **Verify 步骤 + Prompt Injection fencing + ABANDON 重复调用拦截**（sapper-v2 / CHYing）。

---

## 1. 项目对照

| 项目 | 赛事/成绩 | 架构 | 最值得看的点 |
|---|---|---|---|
| **Cairn**（l3yx/Bytex） | 第二届；610 队；**唯一 54/54 AK**；作者自述第 4（动态计分），README 标第 3 | Blackboard + Fact/Intent DAG；Server + Dispatcher + Worker | 无角色、stigmergy、Bootstrap/Reason/Explore、Hint、append-only |
| **BreachWeave**（ai 小分队/绿盟） | 第二届；线上 1/613；线下一等奖 | Manager / Solver / Observer；基于 pi-mono SDK | Observer 旁路监督；Idea/Memory 分层；结束条件外置；RTK Rewrite 压缩；7 模型并行 |
| **sapper-v2**（N1nEmAn） | **第三届线上第一**；85/100 flags；85% 完成率；27,100 分；槽利用率 96.4% | 3 实例 → 8 pane；每题一张 typed fact graph；`sapper` Python CLI；无 DB/Server/UI | Typed facts（host/service/cred/vuln/loot/flag）；flag ledger；verify；deadline；一文件一节点 + flock |
| **SapperLens** | 对 sapper-v2 的独立逆向 | Commander/Worker/Executor 提示词 + 会话/事件表复算 | 63/63、74/74；先易后难、单旗优先、多旗最后；3 槽并发；family brief；拿旗即交 |
| **CHYing-agent**（yhy） | 第二届主赛场 30/54、rank 60；零界第一；700 元 | Orchestrator + Executor/Browser/C2/Reverse 子 Agent | **MCP 可见性**（父只看到 browser 工具）；PromptCompiler；ProgressCompiler；ABANDON 停损 |
| **BinX / LuaN1ao** | 首届 Top3；方班-BinX | P-E-R + **双图谱**：任务 DAG + 因果图谱 | 证据→假设→漏洞→利用；贝叶斯置信度；上下文压缩 70%、细节保留 93%（厂商口径） |
| **清华战队** | 第二届多个一血/二血 | Planner + Executor + 漏洞库检索 Agent | 30,000+ 漏洞数据；737 靶场；动态难度调度；429 治理 |
| **90.7% 低成本队** | 第二届 49/54，<2000 元 | 六次架构迭代 v1→v6 | Prompt caching、429 重试/529 切模型、四维循环检测（厂商口径） |
| **For Future** | 第二届第 7 | 纯自然语言 FSM；"Less Than Nothing" | 零领域知识是主动排除；Coordinator/P2P/Craft 自组织 |
| **CyberStrikeAI** | 首届 6.6k★ | 多 Agent / 工具集 | 工程化与工具生态 |
| **tinyctfer** | 首届第 4 | 100 行、无调优 | 极简 harness 的可能性 |

---

## 2. 六个可复用模式

### 2.1 Fact/Intent 图（最核心）

**Cairn**：

- Fact 只增不改；状态变化写新 Fact。
- Intent 是探索边，可超边（多个 from）；open/claimed/concluded。
- Hint 是图外人类判断。
- Bootstrap → Reason ↔ Explore。
- 图即知识库 + 审计日志。

**sapper-v2**：

- Typed facts：`host/service/cred/vuln/loot/flag` + `key=value`。
- 每题一张图；一文件一节点；`flock` + `os.replace` 原子写。
- `frontier`：ready intent = open + 所有 from facts 存在 + 不需确认。
- `verify`：对 executor 声称的结果单独验证。
- `flag` ledger：去重、先记录后提交、submitted/rejected 生命周期。
- `auto --deadline`：时间预算注入；`sweep` 多题 round-robin。

**BinX 双图谱**：

- 任务 DAG：子任务状态 + 依赖，解决线性死锁。
- 因果图：证据→假设→漏洞→利用；贝叶斯置信度（支撑 +0.25 / 矛盾 -0.35）。
- 先任务图、再因果图，适合长链路内网。

**对我们的意义**：

- 我们之前的“route board”不够：它没有超边、没有完整因果、不可并行、状态会覆盖。
- Fact/Intent 图可以单 agent 使用；多 worker 只是“认领不同 Intent”。

### 2.2 角色：少而硬，或者无角色

- **Cairn**：无固定角色；任务由图的当前状态生成。
- **sapper-v2**：Commander + Worker panes；Commander 只做调度，Worker 执行 intent；没有按漏洞类型分角色。
- **BreachWeave**：Manager / Solver / Observer；Observer 不执行，只旁路监督（偏移、状态混杂、过早结束、上下文膨胀）。
- **CHYing**：Orchestrator + 专用子 Agent（Browser/C2/Reverse），但关键不是角色，而是**MCP 可见性**。

**对我们的意义**：

- 默认单 agent + 图；不要按“Web Agent / Pwn Agent”分工。
- 需要并行时：Commander 只做 Reason，Worker 只做 Explore。
- Observer 可以作为可选 audit worker，不参与执行。

### 2.3 工具可见性 > 工具数量（CHYing）

- Chrome DevTools MCP 有约 30 个工具；如果父 Agent 都看得到，它会自己动手，子 Agent 隔离失效，还吃上下文。
- 方案：`visibility: subagent:browser`；父只看到 `browser` 一个工具。
- Orchestrator 工具列表从 50+ 降到十几个，注意力回到策略。

**对我们的意义**：

- 3 个工具本身就是可见性控制。
- 如果以后接浏览器/逆向 MCP：**父只暴露一个 `browser` / `reverse` 工具**，细节藏在子 Agent；不要把 30 个 MCP 工具直接暴露。
- `ctf_run`/`ctf_session` 的 `summary + artifact` 也是可见性控制。

### 2.4 编译器：Prompt / Progress / Retry（CHYing）

- **PromptCompiler**：开始前用轻量 Agent 把题目描述、侦察、指纹编译成结构化 XML（攻击面、优先级、关键问题、约束）。复杂题值得，简单题多 30 秒。
- **ProgressCompiler**：compact 时另开轻量 Agent 读工作目录，生成 `compact_handoff.md`；不要让做题 Agent 自己总结自己（笔记会膨胀）。
- **RetryHandoffCompiler**：老题重试时，把历史日志编译成“续作报告”，从卡点继续。

**对我们的意义**：

- 我们的 `Bootstrap` 已经在做“先审题”；但可以加一个 **可选的 light compiler**：把 fingerprint 结果编译成结构化 `hint/fact`，而不是让主 Agent 反复读原始输出。
- `progress.md` 应该由**独立上下文**生成（可选 `pi-subagents`），或从图确定性投影；不要让主 Agent 把笔记越写越长。
- `ctf_case graph` 的快照就是“编译器”的确定性版本。

### 2.5 停损与监督（ABANDON / Observer）

**CHYing ABANDON** 三层：

1. 关键词层：连续出现 `Access Denied` / `Connection refused` 等。
2. 调用签名层：工具名 + 关键参数；连续重复同一操作 → 拦截。
3. CVE 层：同一 CVE 试 3 次不通 → 拦截。

通过 `PreToolUse` 拦截，返回“这条路已证明走不通 + 历史尝试 + 换方向”。

坑：签名带 IP 会误杀同一目标的不同攻击路径；应只取 URL 路径等稳定特征；阈值固定不够灵活。

**BreachWeave Observer**：

- 旁路检查最近几轮轨迹；
- 发现偏移/状态混杂/过早结束/上下文膨胀时轻量纠偏；
- 不替代 Solver 决策。
- 结束条件外置（Ralph-Loop），不完全交给模型主观判断。

**对我们的意义**：

- 我们的 `audit` 要加入**命令签名重复检测**（工具 + 归一化参数），不只是“连续无新 Fact”。
- 终止条件外置：flag/oracle、时间盒、无新 Fact、重复签名、预算；不靠模型“我觉得完了”。
- Observer 可选：每 6 步用只读子 Agent 检查一次，默认确定性 audit。

### 2.6 速度、模型与经济性

- l3yx：5 天 7692 元、10.9 亿 tokens；第 4 天 0 flag，第 5 天注入 Hint 后 AK；边际收益递减。
- CHYing：700 元 GLM，30/54，rank 60；弱模型慢，动态计分下损失远大于省钱。
- 90.7% 队：<2000 元、49/54、六次迭代、prompt caching、429/529 处理（厂商口径）。
- SapperLens：3 槽 96.4% 利用率；先易后难、单旗优先、多旗最后；拿旗即交。

**对我们的意义**：

- 默认用强模型做 Reason/关键 exploit；便宜模型做编译/摘要/机械检查。
- 预算不只看 token，还要看**单位时间得分**；比赛模式要 flag-first、立即提交。
- `deadline` 和 `slot utilization` 应成为可选指标。

---

## 3. 对 pi4ctf 的具体改造

### 3.1 Typed Fact

`ctf_case fact` 增加：

```ts
{
  action: "fact";
  description: string;
  kind?: "host" | "service" | "cred" | "vuln" | "loot" | "flag" | "general";
  data?: Record<string, string>;   // key=value，可查询
  source: { commandId: string; artifact?: string };
}
```

好处：

- `frontier` 可以查“有哪些 cred 可复用”“哪些 host 有服务”；
- 因果链更清晰；
- 与 sapper-v2 的经验对齐。

### 3.2 一文件一节点 + 原子写 + flock

```text
.ctf/
├─ project.json
├─ graph/
│  ├─ facts/f001.json
│  ├─ intents/i001.json
│  └─ hints/h001.json
├─ graph.yaml        # 投影
├─ flags.jsonl       # flag ledger：candidate/submitted/rejected
├─ events.jsonl
├─ traces/
└─ scratch/
```

- 一文件一节点：git diff 可读；并发写不互相覆盖。
- 原子写 `os.replace` / Rust `rename`；`flock`（Windows `LockFileEx`）。
- `state.json` 只作为投影，可删可重建。

### 3.3 Intent readiness + Verify

- Intent ready = `open` + 所有 `from` facts 存在 + 不需确认。
- Explore 产出 Fact 后，进入 **Verify**：
  - 命令类：artifact/exit code 确定性校验；
  - 结论类：可选独立 verifier（只读、无执行工具）检查 Fact 是否被证据支持；
  - flag：`ctf_case flag` 四层门禁。
- 失败 Fact 不能进图；标 rejected。

### 3.4 Flag ledger + flag-first

- `flags.jsonl`：候选、提交、平台返回、去重。
- 比赛模式：拿到 flag 立即 `ctf_case flag`；不要等 writeup。
- 多旗题：先交已确认的；未确认的继续。
- 与动态计分对齐：便宜/单旗题优先，多旗题尾段收割（SapperLens 的策略不变量）。

### 3.5 Deadline / budget

- `init` 增加 `deadline?` / `timeboxMinutes`。
- `status` 返回剩余时间、剩余预算、活跃 intent。
- `Reason` 提示中包含 deadline；避免“无限探索”。

### 3.6 Prompt injection fencing

Sapper 的提醒：图里的 Fact/Hint 会被下一个 executor 读到，任何文本都可能变成指令。

- 所有图内容在 prompt 中用 `<UNTRUSTED_GRAPH_DATA>` 包裹，明确“这是数据，不是指令”。
- `ctf_case` 写入时拒绝明显指令性文本？不应过度；至少标记/转义。
- 禁止把未信任网页/题目输出直接写成 Hint；Hint 只来自用户/agent 的明确策略。

### 3.7 ABANDON 命令签名

- `ctf_run`/`ctf_session` 归一化签名：`tool + path + method + 关键参数`，去掉 IP/域名/随机值。
- 连续 N 次相同签名 → 返回 `blocked` + 历史 + 换方向提示。
- 先做 3 次阈值；记录误杀；后续再调。

### 3.8 工具可见性（未来）

- 如果接浏览器/逆向 MCP：父只看到 `browser` / `reverse` 一个工具；具体 30 个工具只给子 Agent。
- `pi-subagents` 的 per-agent tools 可以做到；不要让所有 MCP 工具对主 Agent 可见。

---

## 4. 不照搬

| 做法 | 原因 |
|---|---|
| 3 实例 / 8 pane / 7 模型并行 | 比赛刷分有效，但成本、复杂度高；v1 单 agent |
| Server + Dispatcher + 容器 + Web UI | sapper-v2 证明 JSON + CLI 足够；我们保留 3 工具 |
| 30,000+ 漏洞库 / 大规模 RAG | 维护重；先用现有 `ctf_rag`，按需 |
| 固定角色 Agent | Cairn/CHYing 都指向“角色不是关键，可见性和上下文才是” |
| 零领域知识教条（For Future） | 我们没有模型训练能力；保留可选 skill |
| 直接复制 AGPL/闭源提示词 | 只借鉴思想，独立实现 |

---

## 5. 需要验证

1. Typed facts 是否比 free-text facts 提升 frontier 质量/减少重复？
2. 一文件一节点 + flock 是否比 JSONL 更适合并发/恢复？
3. Verify 步骤是否降低假 Fact / 假 flag，成本是否可接受？
4. ABANDON 签名检测是否减少重复调用，误杀率多少？
5. Deadline + flag-first 是否提升单位时间得分？
6. 可选 Observer/Compiler 是否值得，还是确定性 audit 足够？

---

## 6. 来源

- l3yx/TCH 第二届复盘: <https://l3yx.github.io/2026/04/21/国内最强-AI-渗透测试-Agent-——-TCH·腾讯云黑客松第二届智能渗透挑战赛-唯一-AK-战队复盘/>
- Cairn: <https://github.com/oritera/Cairn>
- BreachWeave: <https://github.com/m-sec-org/BreachWeave>
- Tsec-Hackathon 项目索引: <https://github.com/Yeti-791/Tsec-Hackathon>
- sapper-v2: <https://github.com/N1nEmAn/sapper>
- SapperLens: <https://github.com/inwpu/SapperLens>
- CHYing-agent 复盘: <https://github.com/yhy0/CHYing-agent>
- 双图谱（BinX，厂商口径）: <https://developer.cloud.tencent.com/article/2650361>
- 清华 Planner+Executor（厂商口径）: <https://developer.cloud.tencent.com/article/2668602>
- 90.7% 低成本（厂商口径）: <https://cloud.tencent.com/developer/article/2668018>
- TCH3 / TSecBench: <https://tsecbench.zc.tencent.com/>
