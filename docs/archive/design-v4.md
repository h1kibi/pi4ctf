# pi4ctf Design v4（历史）

> **能力层施工基线（2026-10-24）。** 内核仍按 v3：**4 动词 / 5 机制 / 4 记录**。v4 只改“冻结之后先做什么”，不新增动词、记录或角色动物园。
>
> **已被 [`design.md`](../design.md) 统一取代**；本文保留为能力层证据与推演历史。
>
> 依据：v3 机制审计 + ZCode 三轮研究对话 + 外部论文/比赛代理复核。证据不足处标 `Hypothesis`。

---

## 0. 一句话

> **v3 管“别自欺”；v4 管“先解题”。**
>
> 顺序：模型 → 环境 → 识别/案例 → first contact gate → session → race/browser。

v4 的主线不是再加验证层，而是把 solve 的最大杠杆放到前面：

1. 强 backbone；
2. 真实 CTF 工具链沙箱；
3. 识别卡 + 具体 case；
4. 5 题 first contact；
5. session；
6. 可选 race；
7. 评测防污染。

---

## 1. 证据表

| 干预 | 观察值 | 证据 | v4 决策 |
|---|---|---|---|
| backbone 升档 | GPT-4.1 9/30 → GPT-5 19/30；Claude 4.5 Opus 59% vs Gemini 3 Pro 52% | arXiv:2605.21497；arXiv:2604.17159 | P0 |
| CTF 工具链环境 | Kali 52.0% vs Ubuntu 42.5%，+9.5pp；forensics 46.7 vs 20.0 | arXiv:2604.17159 | P0 |
| category tips | Kali 上 generic 52.0% vs tips 40.0%，−12pp | 同上 | **默认禁用** |
| auto-prompt | Kali+generic 52.0% → 39.5%，−12.5pp | 同上 | **禁用** |
| 同模型 planner/executor | Pro/Pro 52.0%；Pro/Flash 28.5%；Flash/Pro 23.5% | 同上 | 单 agent 同模型 |
| 架构峰值 | Executor / E+E / P+E+E 都是 19/30；结构提升一致性/成本，不抬峰值 | arXiv:2605.21497 | 不追 triad |
| 识别瓶颈 | Planner 识别 23/30；识别对但执行失败仅 4 | 同上 | 识别卡优先 |
| writeup 知识 | CRAKEN 22% vs D-CIPHER 19%，绝对 +2~3pp；复现中 22% vs 22%，无增量 | arXiv:2505.17107；arXiv:2604.17159 | 条件性 P1，不默认 |
| 检索质量 | 43.8% 文档过关；72.7% 生成内容 hallucination 失败；重试贡献 33.7% | arXiv:2505.17107 | 注入门 + 引用 |
| 执行期注入 | 执行期 21% > 规划期 17% | 同上 | case 在执行期注入 |
| 多模型竞争 | BSidesSF 2026 52/52，5 模型 swarm + coordinator + findings bus | `verialabs/ctf-agent`（单场，非控制） | 可选 race，P2 |
| 静态 benchmark 污染 | web-search agent 检索 writeup 使 solve 近乎翻倍；live 掉约一半 | arXiv:2605.11504 | 评测禁检索 + live/holdout |
| loop | 同 tool+args 3 次 warn、5 次 break | `verialabs/ctf-agent` | 复用签名门 |

---

## 2. 优先级

### Gate：5 题 first contact

每类 1 题，中等难度，容器化，有公开 writeup（供 case 蒸馏；评测期禁检索）：

- web：盲注；
- crypto：RSA 分解；
- pwn：ret2win；
- rev：UPX；
- forensics：pcap。

验收的是**地基**，不是 solve：

- 镜像两次构建同 digest；
- `shape@1` 幂等 100%；
- processFailure 四态对人工金标 100%；
- quote 全部可锚 span；
- 逐题标注“识别失败/执行失败”；
- 失败判定：幂等破、kill 后撕裂、>1 题被缺工具阻塞。

记录 baseline solve，但不以 solve 作为 gate fail。

### P0：模型 + sandbox

- 先钉 backbone；单 agent 内 planner/executor 同模型；
- 同一镜像内 `run`/`session`，不跑宿主裸环境；
- 5 题在镜像里跑通。

### P1：识别卡 + case + session

- 卡先做 2 天：trigger/deadEnds/verify 指针；
- case 片段 W1 末起：每技术 2–3 条具体命令；
- 执行期注入，默认关，A/B；
- session 做实：PTY open/send/expect + 增量读。

### P2：race + browser

- race 只出设计，W2 不实现；
- browser 作为 `run` capability，不新增第五动词；
- 并发表达 later。

### P3：live 评测

- cybench 静态 10 题只做开发锚；
- live CTF / CTFusion 做外验；
- holdout 不参与调参。

---

## 3. Sandbox

### 3.1 形态

- `kali-rolling` 派生**单镜像**；digest 钉死；
- `run`/`session` 默认在容器内执行；
- 挑战材料挂 `/challenge` 只读，工作区 `/challenge/workspace` 可写；
- 服务通过 Docker bridge / `host.docker.internal` 可达；
- 不默认挂宿主文件系统；不默认联网。

### 3.2 最小工具集

- pwn：pwntools、gdb + pwndbg、one_gadget、ropper、ROPgadget；
- crypto：sage、pycryptodome、RsaCtfTool、z3、gmpy2、cado-nfs；
- web：sqlmap、ffuf、seclists、hashcat、jwt-tool；
- rev：radare2、ghidra-headless、binutils、ltrace、strace；
- forensics：binwalk、volatility3、stegseek、exiftool、tshark、sleuthkit；
- 通用：python3、gcc、git、jq、curl、nc。

### 3.3 工具发现

- 构建期从包清单生成 `toolbox digest`（≤0.5KB）；
- 进 packet stable prefix；
- 不调用 LLM；
- 比 category tips 更稳：Kali 的“隐含引导”被代码化。

### 3.4 验收

- 两次构建同 digest；
- 工具清单差分 = 0；
- 5 题容器内可执行；
- 无宿主路径泄漏；
- 无网时仍可做静态题。

---

## 4. Playbook：卡 + case

### 4.1 卡：索引与死路，不写技术建议

```json
{
  "id": "web-blind-sqli-length",
  "category": "web",
  "trigger": {"tech": ["php", "mysql"], "signals": ["id parameter", "boolean difference"]},
  "deadEnds": [{"signature": "union-select", "failureClass": "client-blocked"}],
  "verify": {"claimType": "differential", "predicate": "http.length_delta"},
  "evidence": {"refs": ["writeup:..."], "verifiedBy": "case|human"},
  "stats": {"used": 0, "success": 0, "fail": 0}
}
```

刻意**不含** `toolchain` 建议文本。理由：Kali + category tips 实测 −12pp；建议文本会过约束。卡只负责“何时想起”和“别再走死路”。

### 4.2 case：具体命令片段

```json
{
  "id": "case-web-blind-sqli-01",
  "category": "web",
  "trigger": {"tech": ["php", "mysql"], "signals": ["id parameter"]},
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

### 4.3 注入门

- 离线标注 50 对（任务，检索）；
- `precision@3 ≥ 0.6` 才允许注入；30 对太少，报告置信区间；
- 默认关；
- 带/不带 A/B；无提升就只保留 deadEnds；
- playbook digest ≤2KB（top 3），Budget 块 ≤0.5KB 单独计。

### 4.4 首批 20 卡

前 10：

1. web 盲注长度差分；
2. web PHP filter chain；
3. crypto RSA Fermat；
4. crypto AES ECB/padding oracle；
5. pwn cyclic → ret2win；
6. pwn format string leak；
7. rev UPX + ghidra headless；
8. rev ltrace/gdb key-check；
9. forensics pcap HTTP objects + creds；
10. forensics binwalk/strings carving。

后 10：

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

---

## 5. Race（可选能力，不改进内核）

### 5.1 形态

- 外层 adapter 启动 3 个独立 solver；
- 每个 solver 自己的 case/store/container；
- 共享同一 challenge 镜像；
- 不共享 claim/ledger；
- 可选 findings bus：只共享已观察事实，不共享 belief；
- first confirmed flag 胜出；CTFd/oracle 验证；
- flag 去重 + 错误提交 cooldown；
- loop guard：同 tool+args 3 warn / 5 break。

### 5.2 模型组合

- backbone；
- 同族变体；
- 异族竞争者；
- 单 agent 仍同模型；race 才异族。

### 5.3 触发（代码判定）

- 同 case 内 ≥2 个 route class 被 negative ledger 关闭；或
- token >1.5× 单 agent 帽且零新 verified。

### 5.4 预算

- 总帽 = 单 agent 帽 ×2；
- 3 模型起步；5 模型是 Veria 的单场经验，`Hypothesis`；
- W2 只出设计文档，不实现。

### 5.5 与内核边界

- 不改 4 动词；
- 不新增记录类型；
- race 结果只写各自 case；
- 不允许跨 solver 合并 claim；
- 不做 auto-swarm 默认。

---

## 6. 模型

- 单 agent：planner/executor 同模型；强 backbone；
- verifier：异族，仅用于无便宜谓词的 claim；
- 不设 `cheap` 角色；
- fallback：429/529 → 退避 ≤2 → backbone 同族降档；verifier 只能降同族且 claim 降级 `interpreted`、不产 Fact；
- 不硬编码型号；provider/role 配置；
- 选型看等成本：Claude 4.5 Opus 59% @ $2.12/solve；Gemini 3 Pro 52% @ $0.43/solve。

---

## 7. 评测

### 7.1 集合

- 5 题 first contact（地基 + baseline solve）；
- 15 题 dev（调参）；
- cybench 静态 10 题（FST 分档，manifest 钉死）；
- holdout 题不参与调参；
- later：CTFTiny 50、live CTF/CTFusion。

### 7.2 基线

- B0：裸模型 + skill；
- B1：+ verifier；
- B2：+ verifier + 卡/case；
- R1：race 3 模型（可选 arm）。

### 7.3 指标

solve、false Fact、false flag、repeat signature、recovery、tokens-to-solve、wall-clock、quote-support error、injection pass、cost/solve、识别失败/执行失败占比。

### 7.4 防污染

- 评测期禁 web 检索；
- case 库排除 dev/cybench 同源；
- 静态与 live 分开报告；
- 等成本 arm；
- 不把公开 writeup 命中当成 solve。

---

## 8. 里程碑

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

回退阀：

- 整形幂等 <100% → 冻结新增，先修地基；
- B2−B0 < +1 题 → 卡/case 降级参考数据；
- verifier 对已接受 claim 误拒 ≥10% → 先修谓词；
- case precision@3 <0.6 → 不注入，只留 deadEnds；
- race 每美元 solve 低于单 agent → 不做。

---

## 9. 砍项与非目标

- 不默认 category tips；
- 不用 auto-prompt；
- 不 race 首发；
- 不做 5 模型 swarm 默认；
- 不做 triad/角色动物园；
- 不做向量长期记忆；
- 不做 TUI；
- 不做多 worker/A2A；
- 不把 playbook 当第六机制；
- 不把 race 当第五动词。

---

## 10. 相对 v3 的变更单

1. **P0 增加 Kali 单镜像 sandbox + zero-LLM toolbox digest**；
2. **playbook 改为卡 + case 混合**：卡只做 trigger/deadEnds/verify，case 执行期注入；precision 门；默认关；防同源；
3. **race 可选升级**：代码触发、3 模型、×2 帽、first confirmed flag；W2 只设计；
4. **单 agent 同模型**；verifier 异族仅限无谓词 claim；砍 cheap；
5. **评测**：holdout + 等成本 arm + 禁检索；静态/live 分开。

内核 4/5/4 不变。v4 是能力层基线，不是 v3 的重写。
