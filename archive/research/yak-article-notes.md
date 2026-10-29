# Yak 文章笔记：无限游戏 / 安全 Harness / 场景化工具

> 来源：Yak Project 公众号文章，用户提供正文。
> 与异步 Intent 无关；异步设计见 [`async-intent.md`](async-intent.md)。
> 本文记录文章观点，以及这些观点对 pi4ctf 的影响。

---

## 1. 文章主线

### 1.1 无限游戏

- 有限游戏：目标是赢。
- 无限游戏：目标是让游戏继续。
- 对产品与技术：目标是代码、能力、场景运营持续多年。
- “流水不争先，争滔滔不绝。”

### 1.2 网络安全 Harness 与渗透测试 Harness

文章列举的场景：

- SDLC：甲方海量代码仓库更新，有代码有环境的灰盒评估。
- 蓝队值班：处理报警、流量分析、写报告、封端口。
- 审计：从流量中找未脱敏数据、危险请求。
- 甲方运维：已有资产台账的日常安全巡检。
- 监管与资质评估：几十万家下级单位，低成本、快速、可规模化评估。

文章判断：渗透测试只是安全的一小块；把安全 Harness 等同于渗透测试 Harness 会忽略大量真实工作。

### 1.3 通用 Harness 的商业位置

- 很多渗透 Agent 的水平低于通用 Agent（WorkBuddy、Pi Agent、放开限制的 Claude Code）。
- 通用 Harness 架构、知识图谱、Ontology 与控制论，大厂与模型厂更容易做好；安全公司很难在通用架构上长期领先。
- 架构与想法容易被复制，难以形成护城河。
- 价值衡量：使用人数、token 消耗、产生价值、合同产值；个人估价不构成价值证明。

### 1.4 无限可能性与无限能力

- AI 能写代码，不代表现场手搓 Wireshark、Patch OpenSSL、写 10Gbps 流量引擎、每次修畸形包是合理工作。
- AI 写代码的“可能性”廉价，token 成本可能超过事情本身的价值，产生负价值。
- 关键是可重复、场景化、经过验证的工具。

### 1.5 工具与能力边界

- 安全领域知识对万亿参数模型不再稀缺；知识距离工程实现很远。
- 把人的经验与 AI 执行力蒸馏成可重复执行的场景化专业工具，比再写一个渗透 Harness 更有价值。
- 只给 bash 的安全 Agent，在具体场景上通常低于带专业工具的通用 Agent。

### 1.6 三个案例

#### Minirehs（Mini-Regexp-HyperScan）

- 灵感：Intel Hyperscan，把多条正则编成一组，一次扫描。
- Hyperscan 限制：不支持高级正则与回溯、绑定 SIMD 与 x86、复杂场景只能走慢路径、只回答命中。
- Minirehs：
  - 多条指纹正则编成规则；
  - 字面量自动机只过一遍；
  - 没有必现字面量的规则跳过；
  - 命中点附近才运行小自动机；
  - 最后少量交给 PCRE2 抽取捕获组；
  - 支持环视与反向引用；
  - 可保存为镜像，下次不重编。
- 文中数据：1 条快 28.0 倍；1000 条快 23.3 倍；10000 条快 26.7 倍；100000 条快 27.4 倍（总计 2 分 30 秒降至 5.49 秒）。
- 意义：把多规则匹配从 N×M 降到接近一次扫描，属于典型的场景化底层工具。

#### PcapDB

- 把 pcap 变成可反复查询的数据库：原始报文、解析字段、会话与流关联。
- AI 可按时间、IP、端口、协议字段定位，再回溯原始证据；不用每次重新解析、临时编写脚本。
- 用 AI 长期任务扩充协议支持；已支持 400 多个协议；目标为 Wireshark 级。
- 意义：把流量分析从一次性脚本变成可累积的查询与取证能力。

#### JavaJive

- 纯 Go Java 反编译器，从 yaklang 抽离开源，主要由 AI 维护。
- 内部算法：支配树、后支配树、循环分析、稀疏到达定义、异常区间索引、图分析缓存。
- 正确性 Harness：Java 源码编译为 class，反编译，再用 javac 重编译，对比 md5/sha256 输出。
- 意义：AI 能维护复杂工具，前提是具备可验证的正确性闭环；人必须能提出问题并设计验证。

### 1.7 AI 与工具

- AI 提升迭代速度，单次迭代快不等于从零积累快。
- 仍需编写、测试、修复的循环；JavaJive 与 Pcap 这类工作需要大量积累和搜索。
- 人的经验决定提出什么问题、设计什么验证系统；缺乏专业判断时，AI 产出的内容与单句需求没有区别。

---

## 2. 对 pi4ctf 的影响

### 2.1 不押注通用安全 Harness

- 不建设通用 planner、通用 ontology、通用知识图谱作为护城河。
- pi4ctf 的选择是 CTF 场景与少量高价值原语，不建设通用安全 Agent 架构。

### 2.2 CTF 场景化工具优先

优先把以下能力做成稳定、可重复、可验证的原语：

- 二进制：checksec、ELF/PE 解析、反汇编与反编译调用、调试器 PTY、ROP 辅助。
- Web：HTTP 会话、代理与重放、JWT、序列化、JNDI 等常见链路。
- 流量与取证：pcap 查询、协议字段、会话还原（借鉴 PcapDB 思路，当前范围不建设大型系统）。
- 结果整形：ANSI 去除、重复折叠、命中行保留、artifact 分页。
- 验证：flag oracle、Fact verify、生成工具的差分测试。

原则：**工具是经验蒸馏，按 fixture 与 A/B 证明需要后固化。**

### 2.3 验证 Harness 属于核心

JavaJive 的启示：AI 维护工具的前提是“编译、反编译、重编译、对比输出”的闭环。

pi4ctf 对应：

- flag 四层验证；
- Fact 必须绑定 commandId 与 artifact；
- 新增工具必须有差分或回归测试；
- benchmark 不只测 solve，还测 false flag、premature finish、artifact 正确性。

### 2.4 文章与异步机制的关系

- 文章没有讨论 async dispatch、job、wait、结果投递。
- 异步机制是独立需求，参考 Yak 源码实现（`20-background-subagents.md`、`subagent_manager.go`），文章不构成 async 的设计依据。
- 两者的交集是“工具与能力要可重复、可验证”；文章不影响 async 的具体设计。

---

## 3. 当前设计取舍

| 文章观点 | pi4ctf 取舍 |
|---|---|
| 通用 Harness 是商品 | 不建设通用安全 Harness；只做 CTF 主循环 |
| 场景化工具更有价值 | 3 个顶层工具 + Rust CTF 原语；题型能力按数据扩展 |
| 无限可能与无限能力不同 | 不让模型每次现写大工具；预置稳定原语 |
| 验证闭环 | flag oracle + Fact verify + 工具回归 |
| 无限游戏 | 建设可维护、可评测的运行时，不追“最强 CTF Agent” |

### 3.1 当前设计采用的内容

- `final-design.md` §1.2：非目标包含通用安全 Harness、Ontology、知识图谱；不默认让模型现场造大工具；题型能力不做新顶层工具。
- `final-design.md` §1.4：工具优先；能力扩展走 `ctf-rt` 子命令与 `py` SDK；每个能力要 fixture、差分与 15 题 A/B；列出 `inspect`、`traffic`、`web`、`disasm` 候选槽，当前范围均不实现。
- `final-design.md` §1.5：文章与异步机制无关；异步参考 Yak 源码。
- `final-design.md` §2：公理 8 与 9（工具是经验蒸馏；验证先于能力）。
- `final-design.md` §3：新增 Yak 文章来源行；借鉴场景工具与验证闭环。
- `final-design.md` §9.1：`ctf-rt <capability>` 复用同一请求信封，只扩能力，不增顶层工具。
- `final-design.md` §12.4：工具验证 Harness（fixture、差分、per-category 行为用例、ROI、负结果保留）。
- `final-design.md` §13：M1 加 capability fixtures；M5 加工具 ROI。
- `final-design.md` §14：新增通用化漂移、工具正确性、题型能力堆积三条风险。
- `README.md` 设计纪律：3 工具上限、能力扩展路径、验证门槛。

### 3.2 当前设计不包含的内容

- 不预装题型工具库：文章强调工具价值，当前范围仍按 15 题数据决定。
- 不增加顶层工具：图、Reason、Explore、Verify 主循环保持 3 个工具。
- 不把文章结论用于异步机制：异步设计独立成立。

---

## 4. 来源

- 用户提供的 Yak Project 公众号正文。
- Minirehs、PcapDB、JavaJive 均为文章内案例；具体实现以 Yak 仓库为准。
- JavaJive: <https://github.com/yaklang/javajive>
