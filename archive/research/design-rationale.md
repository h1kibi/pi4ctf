# pi4ctf 设计理性、创新点与 Rust 运行时 v0.3

> 一句话：**不是提示词合集，也不是通用 agent 框架；是一个“有执行记忆、会控制上下文预算”的 CTF 运行时。**
> 模型负责策略，运行时负责事实。

---

## 0. 结论

1. **极简方向正确**：少工具、无 planner/blackboard、skills 按需、环境预装宽工具。文献支持“简单 harness + 好接口”优于复杂编排。
2. **“完全相信模型”只对一半**：策略、分类、假设、代码可以交给模型；**观察、命令成功、环境事实、flag 有效性不能**。EnIGMA 实测 48.4% 轨迹出现模型自编 observation。
3. **Rust 值得上，但只做运行时**：PTY/进程组/输出整形/artifact/egress/replay。CTF 工具生态（pwntools/Sage/angr/Ghidra）留在 Python，不重写。
4. **三个真正的创新点**：Observation Contract、Provenance Ledger、Fresh-context Strategy Workers。其余是复用与工程化。
5. **每个创新都必须用消融证明**：solve rate、false flags、tokens、time、cost、recovery。没有数据就回退。

---

## 0.5 设计思想

> **CTF agent 不是“会写 exploit 的模型”，而是一个在不确定环境里、用有限上下文做高保真信息获取与假设淘汰的搜索系统。**
> 所以：**把智能留给模型，把真实留给运行时。**

### 五条公理

1. **观察即产品（Observation is the product）**
   模型不是靠“能跑命令”变强，而是靠“看到什么”变强。工具的第一职责是产出可推理、可追溯、低噪声的观察，执行只是手段。
   → 输出整形 > 工具数量；原始 stdout 直接进上下文是失败模式。

2. **主张不等于事实（Claims ≠ facts）**
   模型可以提出任何主张；只有环境能确认。事实必须有 provenance，flag 必须过 oracle。
   → 账本（ledger）而不是聊天记录，才是事实源。

3. **上下文是预算，不是仓库（Context is a budget）**
   长上下文会退化；压缩必须确定性、可回读（artifact），默认不交给另一个模型总结。
   → artifact store + 按行读取 + 会话增量。

4. **最小策略，最大环境（Minimal policy, maximal environment）**
   不在 harness 里预编解题路径；把工具装进环境，把知识放进按需 skill，把编排留给模型。
   → 9 个工具、无 planner、无 swarm；Kali 预装宽工具集。

5. **复杂度必须付租金（Complexity must pay rent）**
   每个机制都要用消融证明收益（solve / tokens / false flags / time）；证明不了就删。
   → 单 agent 先行；Rust 只在买到可靠性时上；多代理只在卡住时用。

### 角色分工

| 角色 | 负责 |
|---|---|
| 模型 | 策略、假设、代码、工具选择、何时停 |
| 运行时 | 真实、边界、记忆、预算、审计 |
| Skills | 先验知识，按需加载 |
| Benchmark | 唯一裁判 |

### 反面清单

- 不用全 Rust 重写 CTF 工具：瓶颈是模型与上下文，不是 CPU；生态在 Python。
- 不默认多代理：多代理的价值主要是上下文隔离，不是角色扮演。
- 不追求工具数量：100 个工具不如 9 个观察契约。
- 不“完全相信模型”：信策略，不信事实。
- 不把 RAG 当答案：它是证据，不是 oracle。

### 判断标准

任何设计提案先问四句：

1. 它让模型**看到**的更多、更准、更省吗？
2. 它让**事实**更可验证吗？
3. 它让失败更早暴露、更容易恢复吗？
4. 它的收益能否在 15 题子集上被消融证明？

四问没有“是”，就不进 v1。

---

## 1. 证据：CTF agent 的设计经验

### 1.1 简单 agent 可以很强

[Hacking CTFs with Plain Agents](https://arxiv.org/abs/2412.02776) 在 InterCode-CTF 上用非常朴素的组件达到 **81/85 = 95%**：

| 组件 | 取值 | 作用 |
|---|---|---|
| 历史 | 完整 action-observation，单条截断 3500 字符 | 避免“只看最近 5 条”丢线索 |
| turns | 30（对比 10） | 10 turns 时 agent 常“找到 flag 但来不及提交” |
| 工具环境 | Kali + nmap/exiftool/tshark/binwalk/steghide/john/RsaCtfTool 等 | 预装宽度比自研工具更有效 |
| 提示策略 | ReAct + Plan（开头一次，turn 12 再计划一次） | 比纯 ReAct 多解 4 题 |
| 输出 | 结构化输出 | 提交 flag/写 bash/Python 更可靠 |
| 尝试 | best-of-5（最多 10 attempts） | @1→@10 提升 15–20pp |
| 交互工具 | **明确禁用** vim/nano 等 | 在 InterCode 上不是必需，降低复杂度 |

消融：换小模型 −12 题；10 秒超时 −3；不预装包 −3；用 GPT-4o 规划 −2；10 turns −4。

**含义**：不要用复杂 harness 掩盖模型能力；先把环境、预算、计划、重试做对。

### 1.2 交互工具不是万能，但确实有用

[EnIGMA](https://arxiv.org/abs/2409.16165) 给 SWE-agent 加 gdb/pwntools 交互会话和 summarizer：

- NYU CTF **13.5%**（27/200），是当时基线 4% 的 3 倍；InterCode 72%。
- 交互工具让平均 turns 从 14.9 降到 11.5（−22.8%）。
- 消融：IATs 29.5 vs 无 27.4（+2.1pp）；LM summarizer 29.5 vs 无 28.2；simple summarizer 26.9（反而更差）。
- 类别差异：crypto/pwn/rev 受益，web 反而下降（因为缺少 web 交互工具）。
- **48.4% 的 Claude 轨迹出现 soliloquizing**：模型不执行就生成“观察”，甚至编造文件内容和 flag。

**含义**：交互会话值得做，但要按类别；观察必须可验证；简单 summarizer 可能有害，artifact 引用 + 按需读更稳。

### 1.3 多代理有收益，但不是质变

[D-CIPHER](https://arxiv.org/abs/2502.10931)：Planner + heterogeneous Executors + Auto-prompter。

- NYU 19.0%（Claude 3.5），无 auto-prompter 22.0%；Cybench 22.5%；HTB 44%。
- 比 EnIGMA 高约 5.5pp；代价是 planner 调度、上下文截断、成本。
- Executor 用新上下文处理子任务，Planner 只看摘要，避免上下文爆炸。

**含义**：多代理的价值主要在“隔离上下文”，不是“角色扮演”。把这一点抽出来，做成按需的 fresh-context worker，比常驻 planner 更轻。

### 1.4 上下文分段：小模型/卡住时的有效 fallback

[Context Segmentation](https://arxiv.org/abs/2609.12839)（RAISE 2026）用 Explorer + Worker：

- gemma-4-E4B：plain reward 0.23；plain+explorer 0.39；多解 **18.52%** 原本失败的任务。
- token：plain+explorer 8652，best-of-4 10874（reward 0.38），更省。
- 但 Explorer 对简单题会过度复杂化，所以最佳策略是 **plain 先跑，失败再 fallback**。

**含义**：fresh-context worker 应作为工具/fallback，不是默认架构。

### 1.5 接口/harness 本身是变量

- [SWE-agent ACI](https://arxiv.org/html/2405.15793v2)：仅改 agent-computer interface，SWE-bench 约 +10.7pp。
- [omp harness 实验](https://stencil.so/blog/the-harness-problem)：只换 edit 格式，Grok Code Fast 6.7%→68.3%；Grok 4 Fast 输出 token −61%；14/16 模型 hashline 优于 patch。
- [Anthropic: Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)：最简单方案优先；工具文档、绝对路径、poka-yoke 比框架重要。
- [Cybench](https://arxiv.org/abs/2408.08926)：同一模型换 scaffold（structured bash / action-only / PTY / web search）成绩不同。

**含义**：工具返回什么、怎么截断、怎么标识，能和模型升级同量级地影响成绩。

### 1.6 评测必须防自欺

[AI Agents That Matter](https://arxiv.org/abs/2407.01502)：

- 只报 accuracy 不够，要 **cost-controlled**、joint accuracy-cost。
- 评测可复现性普遍差；benchmark 可能被 shortcut/泄漏污染。
- CTF 基准里 `flag.txt`/`test_solver`/writeup 都是泄漏源。

**含义**：闭卷主指标、staging 清洗、oracle 工作区外、报告 cost/tokens/time。

---

## 2. 什么该信模型，什么不该

| 维度 | 信模型 | 由运行时兜底 |
|---|---|---|
| 策略 | 选类别、提假设、定路线、写 exploit | — |
| 工具选择 | 用哪个 skill/tool | 工具参数校验、路径/网络边界 |
| 观察 | — | 命令真实 exit、stdout/artifact 内容、hash |
| 环境 | 提出 glibc/arch 假设 | 指纹检测、RAG 引用、版本核对 |
| flag | 提候选 | 是否出现在 artifact、oracle 是否接受 |
| 停止 | 判断“没路了” | 时间/预算/重复命令/无新证据 |

设计口号：

> **Trust the model for strategy. Verify facts with the runtime.**
> **The agent can lie; the ledger can't.**

---

## 3. 设计原则

1. **工具少，环境宽**：自建 9 个工具；Kali/Ubuntu 预装宽工具集。
2. **上下文是预算**：默认返回整形观察；原文进 artifact，按需读。
3. **先单 agent，卡住再换上下文**：不默认多代理。
4. **状态在磁盘**：`state.json`/`events.jsonl`/artifacts；上下文可丢。
5. **事实有溯源**：fact/attempt/flag 都绑 `command_id` + artifact hash。
6. **每个复杂度都要消融**：没有 solve/token/误报收益就删。

---

## 4. 四个创新点

### 4.1 Observation Contract（观察契约）

**问题**：原始 stdout 又长又脏；context rot 会让模型越跑越笨；模型会编造观察。

**设计**：

```ts
ctf_run(...) -> {
  command_id, exit_code, signals,
  summary: string,          // 确定性摘要：首尾行、错误行、命中行
  artifact_id, log_path,    // 全文，按行范围可读
  bytes, lines, truncated,
  duration_ms, backend
}
```

- 默认 `mode=auto`：ANSI/进度条/重复行清理；保留错误、警告、flag 模式、路径、数字；上限 64KB。
- 原文写 `artifacts/<command_id>.log`；返回路径，模型用 `read` 按范围取。
- `ctf_session` 返回 **delta**（自上次 read 以来的新字节）+ 缓冲区路径，适合 gdb/nc。
- 不使用 LLM summarizer 作为默认（EnIGMA simple summarizer 反而 −2.6pp）；需要时由模型显式调用子代理总结。
- 可选 `mode=raw` 仅调试用；`mode=hex` 用于二进制。

**预期收益**：token 降低、context rot 减缓、重试减少、观察可复核。

**消融**：raw vs shaped；指标：tokens、turns、solve、retry rate。

### 4.2 Provenance Ledger（溯源账本）

**问题**：模型口述 flag/事实不可信；EnIGMA 48.4% soliloquy。

**设计**：

- `state.json` 里每个 fact/attempt/flag 是节点：

```json
{
  "id": "f7",
  "claim": "binary is PIE, no canary",
  "source": { "kind": "run", "command_id": "cmd-12", "artifact": "sha256:..." },
  "status": "verified",
  "ts": "..."
}
```

- 无 `source` 的 fact 标记 `unverified`；系统提示要求先验证再用于下一步。
- flag 只接受 `run|file|http|user` 来源；必须在 artifact 文本中出现；再由 oracle 判定。
- `writeup.md` 从账本投影；没记录过的步骤不能写。
- 可选的“soliloquy 检测”：assistant 消息里出现 `flag{...}` 但当前 turn 没有对应工具调用 → 标 `unsupported_claim`，不进入候选。

**预期收益**：误报 flag 接近 0；可恢复；writeup 可信。

**消融**：账本 on/off；指标：false flags、unsupported claims、恢复成功率。

### 4.3 Fresh-context Strategy Workers（按需换上下文）

**问题**：长轨迹上下文污染；多代理常驻 planner 太重。

**设计**：

```ts
ctf_delegate({
  strategy: string,          // 自然语言策略
  artifact_refs: string[],   // 只传引用，不传全文
  budget: { turns, tokens }
}) -> {
  status, summary, findings[], artifacts[], candidate_flags[]
}
```

- 触发条件：单 agent 连续 2 次无新证据；或上下文 > 60%；或用户显式 `/ctf-parallel`。
- 子 agent 从干净上下文开始，只读 `files/` 和指定 artifacts；写独立 `scratch/`。
- 返回结构化报告；父 agent 合并，flag 仍走 `ctf_flag`。
- 不做常驻 planner/blackboard；不做自动 fan-out。

**证据**：context segmentation 在 gemma-4-E4B 多解 18.52% 原失败任务，token 优于 best-of-4；但简单题会过度复杂化，所以是 fallback。

**消融**：单循环 vs fallback workers；指标：solve、tokens、cost。

### 4.4 Scope-enforced Runtime + Replay（强制边界与复现）

**设计**（Rust `ctf-rt`）：

- 所有外连走本地 allowlist 代理（HTTP CONNECT/SOCKS）；`HTTP(S)_PROXY` 注入命令环境；记录 host/port/字节数；非白名单拒绝。
- 严格模式 Docker `--network none`；题目服务走 compose 内部网络。
- 记录环境指纹（OS、glibc、arch、Python、工具版本）到 `challenge.json`/state。
- Replay：命令日志 + artifact hash + 指纹 → 在新容器重放，验证 flag 可复现。
- 这不是“更安全”的口号，而是让“这题真的解出来了”可审计。

**预期收益**：未授权外连 0；flag 可复现；调试“为什么刚才成功”有依据。

**消融**：regex 白名单 vs 代理强制；指标：违规尝试、误杀、额外延迟。

---

## 5. Rust：用在哪，不用在哪

### 5.1 决策矩阵

| 能力 | 语言 | 理由 |
|---|---|---|
| PTY/ConPTY 会话（gdb/nc/socat） | **Rust** | 跨平台、无 node-gyp、非阻塞、delta 读、可杀进程组 |
| 一次性命令执行 + 进程组 | **Rust** | Windows Job Object / Unix process group；超时可靠 |
| 输出整形/过滤/ring buffer | **Rust** | 零拷贝、低延迟、确定性；避免大字符串进 JS |
| Artifact store（blake3+zstd） | **Rust** | 内容寻址、压缩、快速 hash/索引 |
| Egress allowlist 代理 | **Rust** | tokio 并发、CONNECT 解析、日志；TS 也能做但易漏 |
| Replay 引擎 | **Rust** | 与 runtime 共享命令/artifact 模型 |
| MCP/JSON-RPC 接口 | **Rust (rmcp)** | 官方 Rust MCP SDK；单二进制 |
| 状态机/策略/提示词/工具描述 | **TypeScript** | pi extension 原生；迭代快 |
| RAG 服务 | **Python** | 已有实现；FAISS/embedding 生态 |
| pwntools/Sage/angr/Ghidra/ffuf/sqlmap | **外部** | 不重写；通过 shell/MCP 调用 |
| 浏览器 | **MCP** | Playwright/Chrome DevTools MCP 成熟 |
| Benchmark harness | **Python** | docker/进程/数据加载方便 |

### 5.2 为什么不是“全 Rust”

- CTF 的瓶颈是模型推理与上下文，不是 CPU；全 Rust 不会直接提高 solve rate。
- 安全工具生态在 Python（pwntools、Sage、angr、volatility）；重写是负收益。
- 跨平台 PTY/进程/代理是 Node 的痛点，才是 Rust 的甜点。
- 两语言成本要用 **接口契约 + 消融** 控制；Rust 没收益就退回 TS。

### 5.3 架构

```text
pi 1.4 (TS extension)
  ├─ policy/state/skills/prompts
  ├─ ctf_run/ctf_session/ctf_py/ctf_note/ctf_flag...
  └─ JSON-RPC (stdio) ──> ctf-rt (Rust)
                           ├─ PTY/process supervisor
                           ├─ observation shaper
                           ├─ artifact store
                           ├─ egress proxy
                           └─ replay
```

- `ctf-rt` 默认 stdio，仅本机；可 `ctf-rt mcp` 暴露 MCP 供其他 harness。
- TS 侧保留 policy：allowed_hosts、workspace 边界、flag oracle、state 写入。
- Rust 侧不读配置里的密钥；不直接写 `state.json`；只返回事实与 artifact。

### 5.4 Kill criteria

P1 结束做对比：

- TS `child_process` + 无 PTY vs Rust runtime。
- 指标：命令启动延迟、10MB 输出整形耗时、PTY 交互可靠性、超时残留进程数、Windows 兼容性、打包体积。
- 若 Rust 没有 ≥20% 的可靠性/延迟/体积优势，保留 TS 实现，Rust 降级为可选。

---

## 6. 提升解题能力的杠杆（按证据排序）

| 杠杆 | 证据 | 采用方式 |
|---|---|---|
| 预装宽工具环境 | plain agents：不预装 −3 题 | Kali/Ubuntu 镜像 + `ctf_env` 体检 |
| 完整历史 + 截断 | plain agents：3500 字符 | `ctf_run` 返回整形 + artifact 全文 |
| 计划 + 中途再计划 | plain agents：+4 题 | `ctf-mode` + `/ctf` 入口 |
| 足够 turns + 超时 | plain agents：30 turns / 5 min；10 turns −4 | 默认 30 turns、120s/命令 |
| best-of-k / 重试 | plain agents @10 +15–20pp | 仅 near-miss 重试；预算控制 |
| 类别 skill + demos | EnIGMA +6.2pp，但 web/misc 下降 | ctf-skills 按需 + 类别条件示例 |
| 交互 PTY | EnIGMA +2.1pp、−22.8% turns | `ctf_session`，按需 |
| 上下文分段 | context segmentation +18.52% unique | `ctf_delegate` fallback |
| 观察整形 | context rot / ACI / hashline | Observation Contract |
| 指纹条件 RAG | pwn 环境错配是常见失败 | 自动检测 + 引用 + mismatch 警告 |
| flag 去伪 | EnIGMA soliloquy 48.4% | Provenance Ledger |

**不要一次全上**：先 P0 验证“整形 + 账本 + 预装工具”，再加 PTY/RAG 指纹/分段代理。

---

## 7. 项目特点（对外表达）

- **“The CTF agent that can't fake its observations.”**
- **“Thin policy, hard runtime.”**
- **“Every token in context is earned.”**
- **“Rust where it matters: PTY, process, egress, artifacts.”**
- **“Benchmarked against omp with leakage and cost controls.”**

中文：

> 不是提示词合集，而是有执行记忆的 CTF 运行时；
> 模型可以编，账本不能。

---

## 8. 实验计划（消融先行）

| 实验 | 对照 | 指标 | 预期 |
|---|---|---|---|
| Observation shaping | raw stdout vs shaped | tokens、turns、solve、retry | tokens ↓、solve ≥ |
| Ledger | off vs on | false flags、unsupported claims、恢复 | 误报→0 |
| Fresh-context worker | 单循环 vs fallback | solve、tokens、cost | 卡住题 solve ↑ |
| Rust runtime | TS exec vs `ctf-rt` | 延迟、PTY 可靠性、残留进程 | 可靠性 ↑ |
| RAG | off vs plain vs fingerprint | solve、wrong-env attempts | pwn ↑ |
| Best-of-k | 1 vs k（near-miss） | solve、cost | 有条件 ↑ |

数据集：CTFTiny 50；开发 15 题分层子集；后续 NYU 200（`nyuctf`）。
纪律：闭卷主指标；staging 清洗；oracle 工作区外；报告 cost/tokens/time。

---

## 9. 风险

| 风险 | 处置 |
|---|---|
| Rust 跨平台 PTY（ConPTY/WSL） | `portable-pty` + 真机矩阵；保留 TS fallback |
| 两语言接口漂移 | JSON-RPC schema + contract tests；版本号 |
| 观察整形隐藏关键细节 | 永远给 artifact path/行范围；`mode=raw` |
| 分段 worker 过度复杂化简单题 | plain 先跑；失败/上下文阈值才 fallback |
| egress 代理误杀 | allowlist + 明确 bypass + 日志；严格模式 Docker |
| 复杂度膨胀 | 每个功能必须有消融收益；无收益删除 |
| 评测泄漏 | staging + 闭卷 + oracle 隔离 |
| 模型能力主导 | 固定强模型；报告分模型；工具只补信息/纪律 |

---

## 10. 来源

- Hacking CTFs with Plain Agents: <https://arxiv.org/abs/2412.02776>
- EnIGMA: <https://arxiv.org/abs/2409.16165>
- D-CIPHER: <https://arxiv.org/abs/2502.10931>
- Context Segmentation: <https://arxiv.org/abs/2609.12839>
- Context rot: <https://research.trychroma.com/context-rot>
- SWE-agent ACI: <https://arxiv.org/html/2405.15793v2>
- Anthropic Building effective agents: <https://www.anthropic.com/engineering/building-effective-agents>
- omp harness problem: <https://stencil.so/blog/the-harness-problem>
- Cybench: <https://arxiv.org/abs/2408.08926>
- AI Agents That Matter: <https://arxiv.org/abs/2407.01502>
- NYU CTF Bench: <https://github.com/NYU-LLM-CTF/NYU_CTF_Bench>
- ctf-skills: <https://github.com/ljagiello/ctf-skills>
- rmcp: <https://docs.rs/rmcp>
- portable-pty: <https://docs.rs/portable-pty>
