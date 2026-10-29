# omp 可借鉴设计 v0.1

> omp 写代码好用，核心不是工具多，而是几个接口把“模型输出 → 真实动作 → 可恢复上下文”接得很顺。
> 本文只挑能进 pi4ctf（3 工具 / 1 Rust 二进制 / 图循环）的部分。

---

## 0. 优先级

| 优先级 | 借鉴 | 进 pi4ctf 的形态 |
|---|---|---|
| P0 | **持久 eval + tool 回桥** | `ctf_session` 的 `py` preset：保留 Python 状态，能调 `read`/`run`/`graph` |
| P0 | **artifact spill + 稳定引用** | `summary + artifact + hash`；head/tail；按行读；不塞全文 |
| P0 | **typed subagent 输出** | `pi-subagents` + schema：facts/intents/flags/artifacts/findings |
| P0 | **checkpoint/handoff** | `ctf_case checkpoint` + `handoff`；不假装能回滚文件 |
| P1 | **advisor / observer** | 独立模型、只看 delta、severity、免疫回合 |
| P1 | **learn / managed skill** | solved 后写 verified lesson；可选生成 skill |
| P1 | **tool search / deferred tools** | 接 MCP 时只暴露高层工具；底层用 `tool_search` |
| P1 | **model roles / fallback** | Reason/Explore/Verify 分层；429/529 切换 |
| P2 | **hashline 编辑锚点** | 大脚本编辑可借；不新增工具，先写进 skill |
| P2 | **ask/todo/wait** | 结构化提问、阶段、后台任务；可选 |

---

## 1. hashline：编辑格式是能力的一部分

**omp 做法**：

- `[PATH#TAG]` + `LINE:TEXT`；`TAG` 是内容哈希。
- `PUT N.=M:` / `PUT <N:` / `CUT` / `MV`；不重抄旧行。
- 文件变了 → tag 不匹配 → 拒绝，防止写坏。
- 效果：Grok Code Fast 6.7%→68.3%，Grok 4 Fast 输出 token −61%（omp 博客，代码编辑场景）。

**对 pi4ctf**：

- CTF 的 exploit 脚本通常短；pi 的 `edit` 够用。
- 但**“稳定锚点 + 内容哈希”**可以借到状态层：
  - Fact/Intent 有稳定 id；
  - artifact 有 sha256；
  - 引用 `cmd-7:120-180`，不重抄输出。
- 大脚本编辑可选：skill 建议“优先整文件 `write`；大文件用 pi edit 的精确替换；不要逐行重抄”。
- 不新增 `ctf_edit` 工具；保持 3 工具。

**结论**：借“稳定引用”思想，不搬 hashline 实现。

---

## 2. eval：持久 Python + tool 回桥（最值得借）

**omp 做法**：

- `eval` 一次一个 cell；Python/JS 状态跨调用保留。
- prelude 暴露 `read`、`write`、`tool.<name>()`、`agent()`、`wait()`、`workpool()`。
- `%load` 复用脚本；`%pip install` 保留变量。
- 输出 spill 到 artifact；timeout/cancel/auto-background。

**为什么适合 CTF**：

- crypto：密钥、明文、Sage 对象跨步骤保留；
- pwn：连接、libc 基址、payload 对象保留；
- web：session/cookie/请求上下文保留；
- 不用每次 `python -c` 重建。

**对 pi4ctf**：

- 不新增第 4 个工具；给 `ctf_session` 加 `preset: "py"`：
  - 启动持久 Python kernel（`python -u -i` 或小 kernel）。
  - prelude 暴露：
    ```python
    read(path, offset=None, limit=None)
    write(path, content)
    run(cmd, timeout=120)      # 调 ctf-rt exec
    graph(action, **kwargs)    # 调 ctf_case 的只读操作
    ```
  - kernel 的 stdout/stderr 走 `ctf_session` 增量读；长输出落 artifact。
- 不做 JS eval；CTF 不需要。
- 不做 `agent()`/`workpool()` 进 kernel；并行交给 `pi-subagents`。

**验证**：同一 crypto 题，`ctf_session py` vs `ctf_run python script.py`，比 turns/tokens/solve。

---

## 3. task：typed subagent + artifact handoff

**omp 做法**：

- `task` 单/批量；`tasks[]` + 共享 `context`。
- `outputSchema` + `schemaMode`；结果 `agent://<id>` / `<id>.md` / `<id>.json`。
- 后台 job、`wait`、`proc://`、keep-alive/park/revive。
- `agent://<id>/key/index` JSON 提取。
- 并发 semaphore、递归深度、soft request budget、wall clock。
- isolation/worktree（代码任务）。

**对 pi4ctf**：

- 用 `pi-subagents` 做 executor，但要求结构化输出：
  ```json
  {
    "findings": [{"claim":"...", "evidence":"cmd-7", "confidence":0.8}],
    "facts": [{"kind":"service","description":"...","data":{...},"source":"cmd-7"}],
    "intents": [{"from":["f003"],"description":"..."}],
    "candidate_flags": [{"flag":"...","source":"cmd-9"}],
    "artifacts": ["artifacts/cmd-7.log"]
  }
  ```
- 子 Agent 写 `scratch/<agent>.md` + `.json`；父级读引用，不读长文。
- 不做 worktree；每题一个 workspace，子 Agent 用 `scratch/<agent>/`。
- 后台/等待用 `pi-subagents` 自带；父级只在需要时 `wait`。
- 并发 2–4；递归 1 层；soft budget。

**验证**：并行 2 条独立 Intent vs 单 agent，看 solve/token/冲突率。

---

## 4. checkpoint / rewind：上下文折叠

**omp 做法**：

- `checkpoint(goal)` 标记边界；`rewind(report)` 把探索上下文折叠成报告，保留摘要。
- 只改会话上下文，不恢复文件/artifact/git。
- 一个 active checkpoint；默认关闭。

**对 pi4ctf**：

- 不假装能回滚文件；用图 + 报告实现同样效果：
  - `ctf_case checkpoint {goal}`：记录 `checkpoint` 事件 + 图快照 + `progress.md`。
  - `ctf_case handoff`：从图/事件生成 `progress.md`（做到哪、确认了什么、哪些路死了、下一步）。
  - 卡住/死路时：写一条 Fact + handoff，然后开 fresh-context worker；旧上下文留在会话里但不进新 worker。
- 如果 pi 支持 session fork/compact，可在 command 层做真 rewind；v1 先做 handoff。
- 不新增工具；`ctf_case` 两个 action。

**验证**：长题 compact 后，有 handoff vs 无 handoff 的恢复率/tokens。

---

## 5. advisor / watchdog：旁路监督

**omp 做法**：

- 独立模型；只看 transcript delta；read/grep/glob；`advise` 注入。
- severity：nit / concern / blocker；`immuneTurns` 防连续打断。
- emission guard：去重、内容空话过滤、每次更新上限。
- `WATCHDOG.md` 只给 advisor，不进主上下文。
- 独立 context/model；失败 fallback。

**对 pi4ctf**：

- 可选 `Observer`（`pi-subagents` 只读）：
  - 每 6 步或路线失败触发；
  - 只看新增事件/图 delta，不看全历史；
  - 输出 `nit/concern/blocker` + 证据；
  - `blocker` 才打断，其他写 `hint`。
- 默认确定性 audit；Observer 只在长题/卡住时开。
- `WATCHDOG.md` → `ctf-observer.md`：只放 CTF 审查点（scope、未验证 flag、重复签名、图膨胀）。

**验证**：Observer on/off 的 solve/成本/误打断率。

---

## 6. learn / managed skill：已验证经验

**omp 做法**：

- `learn` 存 lesson；可附带 create/update managed skill。
- 本地 `learned.md`：去重、最多 100 条、每条 2k 字符。
- managed skill 与 authored skill 隔离；失败不破坏 lesson。
- 默认关闭，需 memory backend。

**对 pi4ctf**：

- solved 后写 `lessons/<category>.md`：
  ```yaml
  id: pwn-tcache-key-bypass
  if: {libc: ">=2.29", bug: "double free"}
  then: "..."
  evidence: "traces/..."
  scope: "pwn/heap"
  verified_by: "local+remote"
  ```
- 只收 verified；最多 100 条/类；每条 2k；去重。
- 可选生成 managed skill（`skills/learned/<name>/SKILL.md`），但默认不自动加载；下次 session 手动/按需。
- 不引入 omp 的 memory backend；文件足够。

**验证**：有/无 lesson 检索的 15 题 A/B；错误经验率。

---

## 7. artifact / blob：稳定引用与 spill

**omp 做法**：

- 输出超过 50KB → spill 到 artifact；head/tail；`artifact://<id>`。
- blob store：`blob:sha256:<hash>` 去重。
- artifact ID 会话内递增；`artifact://` 读全文，>8MB 拒绝内联，给路径。
- 子 Agent 输出 `<id>.md` / `<id>.json`；`agent://<id>`。
- 持久化截断 500k 字符；图片 blob 外置。

**对 pi4ctf**：

- 已经用 `summary + artifact + hash`；补：
  - 输出 >16KB 就 spill；head 3MB/tail 滚动，超 cap 标 `[TRUNCATED]`。
  - artifact 路径 = `artifacts/<commandId>.log`；hash = sha256/blake3。
  - 读：`read artifacts/cmd-7.log:120-180`（pi 原生行范围），不需要自定义 scheme。
  - 子 Agent 输出 `scratch/<agent>.md/json`；父级读路径。
- 不引入全局 blob store；per-project artifact 足够。
- 不在 prompt 里塞全文；只给摘要 + 路径 + 行范围提示。

**验证**：10MB 输出下的 tokens/RSS/延迟；artifact 命中率。

---

## 8. tool search / deferred tools：可见性

**omp 做法**：

- 31 个工具不全暴露；`xd://` 设备、`tool_search` 按需加载。
- 大工具集（MCP）只声明相关的；减少上下文。

**对 pi4ctf**：

- 3 个工具已经很小。
- 未来接浏览器/逆向 MCP：父只暴露 `browser`/`reverse` 一个高层工具；底层用 `tool_search` 或子 Agent。
- 不在系统提示里列 30 个 MCP 工具。

---

## 9. model roles / fallback

**omp 做法**：

- `default/smol/slow/plan/advisor` 角色；fallback chains；path-scoped；credential round-robin。
- 429/529 自动切换；prompt caching。

**对 pi4ctf**：

- Reason/关键 exploit：强模型；
- Verify/编译/摘要：便宜模型；
- 429/529：fallback；bench 记录模型/成本。
- 不做 9 个角色；2–3 个够。

---

## 10. 不借

| 功能 | 原因 |
|---|---|
| 31 工具 / browser / computer / LSP / DAP / IDA | CTF 可按需接 MCP；不做内核 |
| 完整 memory backend（local/Hindsight/Mnemopi） | 文件 lessons 足够；避免重 |
| worktree/isolation | CTF 每题独立 workspace；不需要 git 隔离 |
| collab / ACP / TTS / image gen / security_scan | 与 CTF 解题无关 |
| 7 模型 advisor roster | 1 个可选 observer 足够 |
| hashline 实现 | pi edit 够用；借稳定引用思想 |
| 32 并发 / workpool | 2–4 worker 足够；先单 agent |

---

## 11. 落地顺序

1. `ctf_session py` preset + prelude（P0）
2. artifact spill/head-tail（P0）
3. typed subagent schema + scratch 输出（P0）
4. `checkpoint` / `handoff`（P0）
5. Observer 只读（P1）
6. lessons（P1）
7. tool visibility / model roles（P1）
8. hashline/ask/todo（P2）

---

## 12. 来源

- omp README: <https://github.com/can1357/oh-my-pi>
- hashline: <https://github.com/can1357/oh-my-pi/blob/main/crates/pi-edit/prompts/hashline.md>
- eval: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/eval.md>
- task: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/task.md>
- checkpoint: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/checkpoint.md>
- rewind: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/rewind.md>
- advisor: <https://github.com/can1357/oh-my-pi/blob/main/docs/advisor-watchdog.md>
- learn: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/learn.md>
- artifacts: <https://github.com/can1357/oh-my-pi/blob/main/docs/blob-artifact-architecture.md>
- read/internal URLs: <https://github.com/can1357/oh-my-pi/blob/main/docs/tools/read.md>
