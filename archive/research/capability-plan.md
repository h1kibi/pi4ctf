# pi4ctf 能力提升方案 v0.1

> 提升 CTF 解题能力，不是“加更多工具”，而是**降低每一类失败的比率**：
> 让模型在正确的阶段，拿到正确的观察，做更少的错误假设，并在错误发生后以最小代价恢复。

---

## 0. 结论

| 优先级 | 干预 | 主要解决的失败 | 证据 |
|---|---|---|---|
| P0 | **结构化感知**（Observation Contract + 类别探针） | 上下文爆炸、误读输出、工具摩擦 | ACI +10.7pp；context rot；CTFusion 的 stall/large artifact |
| P0 | **配方卡 + 按需 skill 路由** | “不知道下一步试什么” | plain agents 95%；EnIGMA demos +6.2pp（类别条件） |
| P1 | **指纹条件检索** | 环境错配、pwn/crypto 知识找不到 | RAG 语料 + 环境指纹；pwn 对 glibc/arch 极敏感 |
| P1 | **进度审计 + 关键错误重放** | 中段记忆/反思错误、错误传播 | AgentErrorTaxonomy：失败集中在 step 6–15；AgentDebug 最高 +26% 相对提升 |
| P2 | **near-miss best-of-k** | 差一点成功、采样方差 | plain agents @10 +15–20pp；EnIGMA 成功多在前 20 步 |
| P2 | **fresh-context workers** | 长轨迹污染、卡住 | context segmentation：多解 18.52% 原失败任务 |
| P3 | **工具合成 + 经验库** | 长尾格式/协议/编码 | Voyager 技能库；需验证与去重 |

---

## 1. 失败地图

### 1.1 外部证据

- **CTFusion**（Live CTF，2026）：live CTF pass@3 约 **5–7%**，NYU 静态集约 **11–17%**；静态集高约 2 倍，存在污染/抄 writeup 风险。类别上 misc/rev 较易，**pwn/crypto/forensics 持续困难**；常见失败是 **cost limit、execution stall、giveup**。
- **AgentErrorTaxonomy**（2025）：失败集中在轨迹中段（step 6–15），**memory/reflection 错误主导**，并向后传播；AgentDebug 定位最早关键错误并从该步重跑，在 ALFWorld/GAIA/WebShop 最高 **+26% 相对提升**。
- **EnIGMA**：Claude 轨迹 **48.4% soliloquy**；成功多在前 20 步，失败常拖到预算耗尽；交互工具主要减少 turns，类别差异明显。
- **Plain agents**：简单 ReAct&Plan + 完整历史（截断 3500 字符）+ 30 turns + 预装工具 + best-of-5，InterCode-CTF **95%**；说明“环境宽度 + 预算 + 计划”比复杂编排更重要。
- **CTFusion 污染实验**：给 D-cipher 加 web search，NYU 从 12.59% 到 24.07%，但 71 次作弊尝试（63 次直接抄 flag）；说明“检索能力”和“评测有效性”必须分开。

### 1.2 CTF 的七类失败

| # | 阶段 | 典型失败 | 可观测信号 | 干预 |
|---|---|---|---|---|
| 1 | 分类/路由 | 把 crypto 当 misc、把 rev 当 pwn | 首轮命令与文件类型不匹配 | 分类探针 + 路由规则 + 允许改判 |
| 2 | 知识/配方 | 不知道攻击类别、库/框架/漏洞名 | 反复搜索、无假设 | 配方卡 + 相似题检索 + 类别 skill |
| 3 | 假设/搜索 | 只走一条路、不会杀假设 | 重复命令、无新证据 | 3 路线、最便宜可证伪、stop-loss |
| 4 | 感知/工具 | 输出太长/太脏、二进制/PCAP 读不懂 | 上下文爆、误读、跳过关键行 | 结构化探针 + 整形 + artifact 引用 |
| 5 | 状态/上下文 | 忘了已排除项、重复失败 | 同一命令/同一错误循环 | 账本 + 进度审计 + 压缩保留事实 |
| 6 | 验证/flag | 假 flag、decoy、未验证就提交 | 候选 flag 无 artifact 来源 | provenance + oracle + 去伪 |
| 7 | 恢复/停止 | 卡死、预算耗尽、giveup 太早 | stall、cost limit、长尾低收益 | 关键错误重放 + 预算策略 + 换上下文 |

---

## 2. 能力栈

```text
L0 环境保真   libc/arch/工具版本/网络与题目服务
L1 感知       结构化探针、PTY、Python、浏览器、反编译、PCAP
L2 知识       类别 skill、配方卡、相似题检索、指纹条件 RAG
L3 搜索       计划、3 路线、代价/收益、stop-loss、best-of-k
L4 验证       本地复现、差分、oracle、flag 去伪
L5 记忆       事实账本、已验证经验、技能补丁
L6 元认知     进度审计、关键错误定位、重放、模型路由
```

每一层都要有可观测输出，否则模型无法用它做决策。

---

## 3. 关键干预

### 3.1 结构化感知（P0）

**做什么**：

- `ctf_run` 返回 `summary + artifact + log_path`；默认不返回原始 stdout。
- 高价值类别探针（可由 `ctf-skills` 调用，不必每个都做成工具）：
  - ELF/PE：arch/bits/RELRO/canary/NX/PIE/libc/seccomp/符号/字符串命中
  - HTTP：请求/响应、headers、cookies、redirect、timing、diff
  - TCP/PTY：连接、发送、增量读、hex/base64
  - PCAP：流重组、协议、HTTP 对象、时间线
  - 文件：type/entropy/hash/嵌入文件/元数据
- 所有探针输出必须带 `artifact_id`，允许回读原文。

**为什么**：模型读不懂/读不完是高频失败；ACI 与 context rot 都说明“接口决定成绩”。

**度量**：tokens、turns、retry、solve；raw vs shaped A/B。

### 3.2 配方卡 + 按需 skill 路由（P0）

**做什么**：

- 每个类别一张“决策卡”，不是教程：
  - 入口问题（先看什么）
  - 3–7 个分支（症状 → 下一步 → 工具）
  - 验证条件（怎么知道这条路对了）
  - 常见死路
- `ctf-skills` 提供深度；配方卡负责“下一步做什么”。
- 路由允许改判：首轮 triage 后若证据不符，显式切换类别。

**为什么**：plain agents 的强项是“有工具、有计划”；模型缺的是**下一步的决策过程**，不是更多知识段落。

**度量**：首轮命中率、triage 到首个有效动作的 turns、每类 solve。

### 3.3 指纹条件检索（P1）

**做什么**：

- 侦察时生成 challenge fingerprint：category、file types、arch、libc、protections、framework、ports、protocol。
- 检索 query 带 2–4 个技术锚点 + 指纹过滤（如 `glibc 2.31 tcache`、`Flask Jinja2 SSTI`）。
- 引用 `source + chunk_id`；环境不匹配时显式警告。
- 相似题检索按**结构特征**（protections、bug class、protocol）而非纯文本。

**为什么**：pwn/crypto 的失败常是“知识对了但环境不对”；RAG 泛化查询会召回无关 writeup。

**度量**：wrong-environment attempts、RAG 命中率、pwn/crypto solve。

### 3.4 进度审计 + 关键错误重放（P1）

**做什么**：

- 每 N 步（如 6）或每次路线失败，做一次 progress audit：
  - 上次命令改变了什么状态？
  - 当前假设是否被证伪？
  - 是否重复了已失败的命令/参数？
  - 剩余预算 vs 预期收益？
- 失败后不总是从头重跑：
  - 用账本找**最早的关键错误**（错误假设/错误偏移/错误环境）；
  - 从该步的 artifact/状态快照重放，带针对性反馈；
  - 保留已确认事实，只重做错误分支。
- 需要 `ctf-rt` 的 replay + state snapshot 支撑。

**为什么**：AgentErrorTaxonomy 显示失败集中在中段且会传播；AgentDebug 证明定位最早关键错误再重跑，比盲目 best-of-k 更有效（最高 +26% 相对提升，需在 CTF 上复核）。

**度量**：recovery rate、重跑 token、重复命令率、solve。

### 3.5 near-miss best-of-k（P2）

**做什么**：

- 只在“接近成功”时重试：拿到部分泄露、正确 crash offset、正确 oracle 响应、最后一步失败。
- 每次重试换策略/种子/参数，不重复同一轨迹。
- 预算上限与停止条件显式。

**为什么**：plain agents @10 +15–20pp；但无差别重跑会烧钱且掩盖能力问题。

**度量**：near-miss 定义命中率、每次重试的边际 solve、cost。

### 3.6 fresh-context workers（P2）

**做什么**：

- 单 agent 卡住或上下文超阈值时，把“策略 + artifact 引用”交给干净上下文的 worker。
- worker 只读挑战文件与指定 artifact，返回结构化报告；父级合并。
- 简单题不启用，避免 context segmentation 的过度复杂化。

**为什么**：多代理的真正价值是上下文隔离；D-CIPHER / context segmentation 都指向这一点。

**度量**：卡住题 solve、tokens、cost。

### 3.7 工具合成与经验库（P3）

**做什么**：

- 当 agent 连续两次手工解析同一格式/协议，生成小工具/脚本，附测试，注册为会话工具或 skill 补丁。
- 经验条目格式：`if <fingerprint/symptom> then <action> because <evidence>`；只有验证过才入库。
- 去重、版本化、可回滚；检索按指纹/症状。

**为什么**：长尾题靠“现场造工具”；Voyager 技能库证明可复用技能会复利。风险是噪声与错误经验，必须验证。

**度量**：工具复用率、长尾题 solve、错误经验率。

### 3.8 模型路由（P2/P3）

**做什么**：

- 强模型：triage 后的假设生成、复杂 crypto/rev 推理、关键错误定位。
- 便宜模型：文件清点、简单解析、摘要、格式转换。
- 关键验证用独立模型/独立上下文，避免自我确认。

**为什么**：plain agents 用 o1-preview 规划 + GPT-4o 执行，规划换模型只差 2 题，但成本/稳定性可调；不是所有步骤都需要最强模型。

**度量**：solve/cost 曲线、每类模型收益。

---

## 4. 分类能力卡（决策过程，不是教程）

### 4.1 pwn

**先问**：架构/位数？保护（RELRO/Canary/NX/PIE）？libc 版本？seccomp？远程交互协议？

**primitive 图**：leak（地址/堆/栈/libc）→ write（任意写/相对写）→ control（RIP/函数指针/FSOP）→ 目标（shell/ORW/flag）。

**分支**：

- 栈溢出 → 偏移/ret2libc/ROP/ret2csu/SROP
- 格式化字符串 → 读写原语/任意地址
- 堆 → UAF/overflow/double free/tcache/House of *
- 菜单题 → 对象生命周期/索引越界
- 沙箱 → ORW/open-read-write

**验证**：本地同 libc 复现；远程多跑几次确认稳定性；记录 leak 来源。

**常见失败**：libc 不匹配、偏移错、远程超时、one_gadget 约束不满足。

### 4.2 web

**先问**：入口/路由/参数/认证/上传/模板/数据库/依赖版本？

**surface map**：endpoints、methods、params、cookies、headers、JS 路由、错误页。

**分支**：SQLi、SSTI、SSRF、XXE、反序列化、文件上传、JWT/OAuth、race、smuggling、prototype pollution、source leak。

**验证**：可复现请求；区分“疑似”与“已利用”；OOB 通道确认；flag 读取路径。

**常见失败**：只测首页、忽略 JS/隐藏参数、session 丢失、WAF 误判。

### 4.3 crypto

**先问**：算法/模式/密钥生成/随机源/oracle/已知明文？

**决策树**：RSA（小 e、共模、Wiener、Coppersmith、padding oracle）→ AES（ECB/CBC/GCM/nonce）→ ECC（小子群/无效曲线/非随机 nonce）→ PRNG（状态恢复）→ 格（LLL/Coppersmith）。

**验证**：脚本对已知向量；解密结果可读；oracle 响应符合假设。

**常见失败**：数学假设错、字节序/填充错、把概率攻击当确定攻击。

### 4.4 rev

**先问**：ELF/PE/APK/WASM/字节码？输入检查在哪？有无反调试/壳/VM？

**顺序**：strings/xref → decompile（Ghidra/IDA MCP）→ 动态（gdb/unicorn）→ 符号执行（angr）→ patch/复现。

**验证**：输入 → 期望输出；本地跑通；flag 生成逻辑可解释。

**常见失败**：只读汇编不读伪代码、忽略初始化/构造、VM 不 lift、反调试卡死。

### 4.5 forensics

**先问**：磁盘/内存/PCAP/音频/图片/日志？时间线？隐藏卷/嵌入文件？

**工具矩阵**：file/binwalk/foremost、tshark/zeek、volatility3、exiftool/zsteg/steghide、sleuthkit、strings/hex。

**验证**：提取物可打开；时间线自洽；flag 来源文件明确。

**常见失败**：只看表层文件、漏流重组、内存 profile 不匹配、隐写工具参数错。

### 4.6 misc

**先问**：编码/约束/沙箱/游戏/协议/问卷？

**顺序**：识别编码 → 约束求解（z3）→ 沙箱逃逸（pyjail/bash jail）→ 自动化交互 → 自定义工具。

**验证**：输入输出闭环；脚本可复现。

**常见失败**：编码链断、约束建模错、jail 版本差异。

---

## 5. 从失败中学习

### 5.1 CTF 错误标签

在每个失败 run 上打一个主标签（可多选）：

`triage_wrong | knowledge_gap | hypothesis_stuck | tool_misuse | observation_misread | state_lost | verification_false | budget_exhausted | giveup_early | environment_mismatch`

写入 `state.json` 的 `failure` 字段，供周度统计。

### 5.2 周度改进循环

1. 统计 top 3 失败标签（按类别）。
2. 只改一个：加探针/改配方/改检索/改预算。
3. 15 题子集 A/B；有收益才进主线。
4. 记录到 `lessons/`，带证据与适用范围。

### 5.3 经验格式

```yaml
id: pwn-tcache-key-bypass
if:
  libc: ">=2.29"
  bug: "double free"
then: "tcache key 需要先 leak/绕过；优先 fastbin dup 或 unsorted bin"
evidence: "artifact:...; writeup:..."
scope: "pwn/heap"
verified_by: "local repro + remote"
```

只有 `verified_by` 非空的条目才允许进入检索库。

---

## 6. 实验计划

### 6.1 基线

- B0：pi 1.4 + `ctf-skills`，无自建工具（裸模型 + skills）。
- B1：B0 + `ctf_run`/`ctf_py`（原始输出）。
- B2：B1 + Observation Contract（整形 + artifact）。
- B3：B2 + Provenance Ledger + 配方卡。
- B4：B3 + 指纹 RAG。
- B5：B4 + progress audit + critical-error reroll。
- B6：B5 + fresh-context workers + near-miss best-of-k。

### 6.2 指标

| 指标 | 说明 |
|---|---|
| solve | oracle 通过率（分类型） |
| false flags | 错误 flag 数（必须 0） |
| tokens / cost | 输入+输出 token、API 成本 |
| turns | 到 flag 的步数 |
| stall rate | 超时/无进展比例 |
| recovery rate | 卡住后恢复并解出的比例 |
| triage hit | 首次分类正确率 |
| repeat rate | 重复失败命令比例 |

### 6.3 数据集

- 15 题分层子集（每类 2–3 题）：开发。
- CTFTiny 50：发布。
- Live CTF（CTFusion 风格）：最终能力验证，防污染。
- 纪律：闭卷主指标；staging 清洗；oracle 工作区外；web/RAG 开关单列。

---

## 7. 落地顺序

| 阶段 | 内容 | 验收 |
|---|---|---|
| C0 | 结构化感知 + 配方卡 + 账本 | raw vs shaped 有 token/retry 收益；误报 0 |
| C1 | 指纹 RAG + progress audit | pwn/crypto 错误环境尝试下降 |
| C2 | critical-error reroll | 卡住题 recovery 提升，重跑 token 可控 |
| C3 | fresh-context workers + near-miss | 边际 solve 为正，cost 可接受 |
| C4 | 工具合成 + 经验库 | 长尾题 solve 提升，错误经验率低 |
| C5 | Live CTF 评测 | 与静态集差距可解释 |

---

## 8. 不做什么

- 不做 prompt stuffing / 把 70 个 skill 全塞进系统提示。
- 不做通用 LLM summarizer 当默认压缩；确定性整形优先。
- 不默认多代理/planner；上下文隔离用按需 worker。
- 不把 RAG 当答案；它是证据。
- 不在 v1 做 fine-tune；先积累**已验证轨迹**，再考虑 SFT/RL。
- 不用 web search 刷静态 benchmark；评测用闭卷/live。
- 不为“更多工具”而加工具；每个工具都要有观察契约与消融。

---

## 9. 来源

- CTFusion: <https://arxiv.org/abs/2605.11504>
- AgentErrorTaxonomy / AgentDebug: <https://arxiv.org/abs/2509.25370>
- EnIGMA: <https://arxiv.org/abs/2409.16165>
- D-CIPHER: <https://arxiv.org/abs/2502.10931>
- Plain Agents: <https://arxiv.org/abs/2412.02776>
- Context Segmentation: <https://arxiv.org/abs/2609.12839>
- SWE-agent ACI: <https://arxiv.org/html/2405.15793v2>
- Anthropic Building effective agents: <https://www.anthropic.com/engineering/building-effective-agents>
- Voyager: <https://arxiv.org/abs/2305.16291>
- ctf-skills: <https://github.com/ljagiello/ctf-skills>
