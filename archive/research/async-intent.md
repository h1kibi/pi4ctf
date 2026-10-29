# 异步 Intent / Job 机制设计

> **范围说明**：异步机制是独立的工程需求，与 Yak 微信公众号那篇“无限游戏 / 安全 Harness / 场景化工具”文章无关。该文章的笔记见 [`yak-article-notes.md`](yak-article-notes.md)。
>
> 本文的 async 设计参考 Yak 的公开源码与文档：`reactloops/docs/20-background-subagents.md`、`subagent_manager.go`、`loop_intent/intent_runner.go`、`deep_intent.go`。

---

## 0. 设计结论

异步执行分两类任务：

1. **command job**：`ctf_run --async` 执行长扫描、爆破等命令；Rust 管理子进程与结果。
2. **intent job**：`ctf_case dispatch` 把独立 Intent 交给 `pi-subagents`；TypeScript 扩展启动 worker，Rust 记录任务与结果。

Intent 创建保持同步：Reason 写 graph 节点，耗时很短。Intent 执行只对独立、长耗时、高期望的任务使用异步；依赖型、快速型任务同步执行。

两类任务共用同一套 job 模型、结果投递、完成门禁、配额与取消机制。

---

## 1. Yak 的实现要点

### 1.1 dispatch 立即返回回执

`dispatch_sub_react_agents`：

- 输入：`dispatches[]`（goal/identifier/task_name/loop_name/result_contract/context_mode）。
- 行为：准备、入队、返回 `batch_id` + 每个 `job_id` + 实际 `context_mode`。
- 回执只表示接收成功，不表示分析成功。
- 父模型下一轮可以继续做本地动作，不必等整批结果。

### 1.2 wait 是观察窗口

`wait_sub_react_agents`：

- 默认 `timeout_ms=30000`，范围 0–600000（最大 10 分钟）。
- 任何选中任务出现未读终态就提前返回；否则返回当前状态、最近活动、轮数、工具调用数、阶段输出。
- `observation_timeout` 不取消子任务；子任务继续运行。
- 不会每 30 秒自动唤醒模型；没有后台定时器。

### 1.3 结果投递与版本

- worker 把完整结论写到固定产物文件；manager 登记摘要、文件引用、递增的 `result_revision`。
- 父 `generateLoopPrompt` 取未投递结果，最多 8 项，放进 reactive data 动态分区；提示组装完成后才写父 timeline，避免首次投递出现两份正文。
- 父记录本轮模型输入覆盖的结果版本。
- `finish` 同时检查：没有活跃子任务、最新结果已进入产生该动作的模型输入。
- 结果晚于父 prompt 到达时，本轮 finish 被拒绝；下一轮收到摘要与引用后再收尾。

### 1.4 状态与并发

状态：`queued / preparing / running / cancelling / completed / failed / cancelled / timed_out`。

配额：

- `MaxSubAgents` 默认 5，上限 20；
- 当前 owner 最多 20 项未终结任务；
- 总提交最多 100；
- 连续 20 次无新阶段输出、终态或真实进展的 inspect/wait 触发有界停止；
- 取消不消耗该预算。

### 1.5 取消与清理

- 取消是协作式；直到 worker 退出才发布终态。
- 父 task 正常结束会取消 context；有活跃子任务或未见结果时，普通 finish 被拒绝并 Continue。
- 清理最多等 1 秒；不响应 context 的 worker 标 `cancelling/cleanup_pending`，不谎报停止。
- 晚到结果只属于原 manager，不污染新父任务。

### 1.6 上下文与写入边界

- 子 Agent 有独立 task/loop/timeline；父不自动读取子模型的每段流。
- 上下文模式：`fork`（默认）或 `task_only`。
- 子 worker 只更新自己的历史和 manager 快照；不写父 operator/vars/timeline。
- 父线程冻结 timeline、配置、结果目录；排队子任务启动时继承当前工具策略，不回写旧策略。

### 1.7 Intent 识别

`loop_intent` 的流程：

- 1 次 AI 调用生成 `intent_summary + search_keywords + tags + questions`；
- 本地 BM25 搜索 capabilities（tools/forges/skills），不调用 AI；
- 匹配数超过 12 才做第 2 次 AI 推荐；
- 结果注入 `deep_intent`，再把匹配的 tools/forges/skills 加入 ExtraCapabilities。

---

## 2. pi4ctf 的异步设计

### 2.1 任务类型

| 任务类型 | 执行方式 | 说明 |
|---|---|---|
| command job | Rust 子进程 | `ctf_run --async`；长扫描、爆破；结果写入 artifact |
| intent job | `pi-subagents` | `ctf_case dispatch`；worker 独立上下文；结果写入 scratch |
| Intent 创建 | 同步 | Reason 写 graph 节点，耗时很短 |

### 2.2 Job 模型

```ts
type JobState = "queued" | "preparing" | "running" | "cancelling"
              | "completed" | "failed" | "cancelled" | "timed_out";

interface Job {
  jobId: string;
  batchId: string;
  kind: "command" | "intent";
  intentId?: string;
  state: JobState;
  createdAt: string;
  startedAt?: string;
  endedAt?: string;
  lastActivityAt: string;
  lastEvent?: string;
  iterations?: number;
  toolCalls?: number;
  latestOutput?: string;
  resultRef?: string;
  resultRevision?: number;
  error?: string;
  cleanupPending?: boolean;
}
```

存储：`jobs.jsonl` 追加记录，`scratch/jobs/<jobId>.md` 保存结果，`state.json` 保存投影。

### 2.3 工具接口

保持 3 个顶层工具，job 控制放在 `ctf_case`：

```ts
// 异步命令
ctf_run({ command, purpose, async: true, timeoutSec })
  -> { jobId, state: "queued"|"running", receipt: true }

// Intent 异步执行
ctf_case({ action: "dispatch", intentId, contextMode?: "fork"|"task_only" })
  -> { jobId, batchId, state: "queued", receipt: true }

ctf_case({ action: "inspect", jobIds?: string[] })
  -> { jobs: Job[] }

ctf_case({ action: "wait", jobIds?: string[], timeoutMs?: number })
  -> { reason, timedOut, jobs: Job[] }

ctf_case({ action: "cancel", jobIds?: string[] })
  -> { accepted: true, jobs: Job[] }
```

- `inspect` 不消费结果；`wait` 遇到未读终态提前返回。
- 结果由 manager 投递；父下一轮 Reason 看到摘要与 `resultRef`。
- 未指定 `jobIds` 表示当前父任务的全部子任务；未知或他人的 job 报错。
- **归属**：command job 由 Rust 管理；intent job 由 TypeScript 扩展调用 `pi-subagents` 启动 worker，Rust 只记录任务与结果，不启动 LLM。两类任务共用 job 表。

### 2.4 结果投递

- worker 写 `scratch/jobs/<jobId>.md` 与 `.json`；
- manager 写 `jobs.jsonl` 的结果记录（`summary`、`resultRef`、`resultRevision`）；
- 父 Reason 的 prompt 注入未投递结果，最多 8 项；注入后记录 `inputRevision`；
- `complete` 与 `finish` 门禁：
  - 没有 `queued/preparing/running/cancelling`；
  - 所有终态结果已进入当前 prompt 版本；
  - 否则拒绝完成，下一轮继续。
- **pi 不会自动续父轮**：交互模式要求 dispatch 后继续本地动作，或显式 `wait`；headless 可开启 `notifyOnComplete`，用 `pi.sendMessage({triggerTurn:true})` 唤醒。默认不后台打断。

### 2.5 上下文与写入边界

- Intent worker 只读 `graph/` 与指定 artifacts；写自己的 `scratch/jobs/<jobId>/`。
- worker 不写父 `graph/`；只返回结果。由 manager 或父 `ctf_case` 写 Fact，避免并发污染。
- `contextMode`：
  - `fork`：带父图摘要与当前 Intent；
  - `task_only`：只给 Intent 与 artifact refs（推荐，节省 token）。
- 子 Agent 不继承父会话历史；只拿 `graph.json` 路径与摘要。

### 2.6 配额与取消

- 并发：默认 2，上限 4。
- 单 owner 未终结任务 ≤8；总提交 ≤32。
- 连续 20 次 inspect/wait 无新进展，触发有界停止。
- 取消协作式；清理 ≤1 秒；`cleanup_pending` 如实上报。
- 父 `complete` 时若仍有活跃 job，拒绝完成。

### 2.7 异步条件

对以下 Intent 使用异步：

- 独立，不依赖其他正在运行的 Intent；
- 预计超过 30 秒；
- 有明确验证路径；
- 只读 graph 与 artifacts，不修改共享状态。

保持同步：

- Bootstrap；
- 依赖链上的下一步；
- 快速验证（少于 30 秒）；
- 需要立即用结果决定下一步的 Intent。

### 2.8 失败模式与对策

| 失败 | 对策 |
|---|---|
| 父没看到结果就 finish | finish 门禁与 `inputRevision` |
| 重复投递或旧结果覆盖 | `resultRevision`，只投未投递结果 |
| 取消后 worker 仍写图 | worker 不写父图；manager 统一提交 |
| orphan job 或进程重启 | job 状态写入文件；重启标 `orphaned`，不自动续跑 |
| 子 Agent 上下文污染 | `task_only` 与 artifact refs |
| 结果过长 | `resultRef` 与摘要；父按需读取 |
| 并发过多 | 2–4 并发、pending/submitted 上限、无进展停止 |

---

## 3. 任务归属与执行边界

| 部分 | 负责方 | 职责 |
|---|---|---|
| command job 生命周期 | Rust | 启动子进程、超时、进程组终止、结果写入文件、状态更新 |
| intent job 生命周期 | TypeScript 扩展 + `pi-subagents` | 启动 worker、上下文隔离、结果回传 |
| job 状态与结果索引 | Rust | `jobs.jsonl`、`resultRevision`、`inspect/wait/cancel` |
| 父图写入 | 父 Agent 或 manager | worker 只写 scratch；Fact 由父级统一提交 |
| 完成门禁 | TypeScript 扩展 | 检查活跃 job 与未投递结果 |

---

## 4. 实验

1. 长扫描（超过 120 秒）同步与 async：父轮阻塞时间、总耗时。
2. 两个独立 Intent 同步串行与 async 并行：wall-clock、tokens、solve。
3. 结果晚到：finish 门禁是否阻止过早完成。
4. 取消：worker 是否停止、是否污染 graph。
5. 并发 2 与 4：solve、成本、429。
6. `task_only` 与 `fork`：tokens、结果质量。

---

## 5. 来源

- Yak Project 源码：<https://github.com/yaklang/yaklang>
- `20-background-subagents.md`：<https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/docs/20-background-subagents.md>
- `subagent_manager.go`：<https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/subagent_manager.go>
- `loop_intent/intent_runner.go`：<https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/loop_intent/intent_runner.go>
- `deep_intent.go`：<https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/deep_intent.go>
- Claude async multi-agent cookbook: <https://platform.claude.com/cookbook/patterns-agents-async-multi-agent-orchestration>
