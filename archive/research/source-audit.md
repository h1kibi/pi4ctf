# 源码级核对结论

> 目的：记录已核对仓库的实际实现，以及由此采用的工程约束。
> 范围：以下结论只覆盖本文列出的文件；未逐行核对的模块不作为结论依据。

---

## 1. Cairn：图快照使用文件引用

`tasks/explore.py` 与 `reason.py` 把图写入容器内文件，prompt 只拿引用，不内联完整 YAML。

采用：

- `graph.json` 作为文件路径与有界摘要，不每次内联全图。
- Reason 的 `complete` 必须处理写入失败；Intent 创建处理 409 与重复。
- `graph.md` 供人阅读；`graph.json` 供机器读取。
- 单 agent 可以不实现 lease，但保留 `claimed` 状态与超时释放语义，供并行扩展使用。

---

## 2. Sapper：平台锁与 flag 账本

`Store.locked()` 使用 `fcntl.flock`。

采用：

- Unix 使用 `flock`，Windows 使用 `LockFileEx`；不假设 `fcntl` 跨平台。
- `ctf_case flag` 使用 `candidate → recorded → submitted/rejected` 生命周期；按值去重；先记录后提交；Fact 不丢。
- 提交失败保留为 rejected，供审计与防重复。

---

## 3. BreachWeave：Observer 参数

源码中的 Observer：

- 每 6 轮 review，窗口 10；
- 冷却 6，重复窗 12，活动窗 3；
- board 上限：memory ≤12 条、intents ≤8 条；
- solver 对 intents 只读；Observer 不提交 flag、不拿 hint、不执行 solver 行为。

采用：

- audit/observer 不在每 6 步打断；使用 cooldown 与 activity fingerprint 去重；
- 默认只更新图，不直接 steer；
- board 有上限，超出时压缩。

---

## 4. CHYing：编译器参数与 ABANDON

`PromptCompiler`、`ProgressCompiler`、`RetryHandoffCompiler` 的参数：

- 10 turns、Read/Grep only、60k chars、no Write、`## Session Handoff` 标记；
- PromptCompiler 1 turn、无工具。

采用：

- 编译器参数直接采用上述数值；
- 工具可见性需要删除不用的工具定义，不只隐藏；
- benchmark 默认关闭 WebSearch/WebFetch，防止 writeup 泄漏；比赛规则允许时再开；
- ABANDON 使用 dead-end 关键词、signature、CVE；默认在 stagnation 后激活，记录误杀。

---

## 5. dsh-ops：两层预算

源码区分：

- worker 默认 300 秒；
- host 默认与上限 30 秒。

采用：

- `ctf_run` 保留 120 秒默认，但协议写清 host 与 worker 两层预算；
- request ≤2MB、output ≤128KB、result store 10MB/result、100MB/session；
- 结果存储支持分页与引用，不把完整输出放入上下文。

---

## 6. pi-code：项目资源信任

`ctx.isProjectTrusted()` 只覆盖 `.pi` 与 `.agents/skills`，不覆盖 `.ctf`、`.mcp.json`。

采用：

- `.ctf` 与项目 skill/MCP 使用独立 trust gate；
- headless 严格拒绝未批准资源；
- `complete` 不能由 solver 自判，必须有独立 verifier 或 oracle。

`goal.ts`：

- goal 由独立模型评估，不能运行工具；
- transcript 取上下文的一半；
- 30 秒 evaluator timeout、512 max tokens；
- 连续无工具进展的 not-met 有 block cap（默认 8）；
- 受 hooks 限制与项目信任门控。

---

## 7. pi-agent-plugins：分发边界

`loader.ts`：

- 校验 `plugin.json` 后，发现组件；
- 只识别 `skills/*/SKILL.md` 的直接子目录；
- manifest 与 skill 必须 resolve 在 plugin root 内；
- MCP server 名使用 namespace：`plugin__server`；
- `PLUGIN_DATA` 隔离；`enabled` 状态。

`mcp-runtime.ts`：

- stdio command 必须是 bare name 或 contained `./` 路径；
- HTTP headers 与 legacy SSE 受限。

采用：

- 分发 skills/MCP 时使用同样的 containment、namespace、trust；
- 不直接把用户 MCP 改全局。

---

## 8. Yak：异步子 Agent 的回执、投递与门禁

`reactloops/docs/20-background-subagents.md` 与 `subagent_manager.go`：

- `dispatch_sub_react_agents` 立即返回 `batch_id` 与 `job_id`；回执只表示接收成功。
- `wait` 默认 30 秒、最大 10 分钟；有未读终态提前返回；观察超时不取消任务。
- 结果写固定产物文件，manager 登记摘要、引用、`result_revision`；父 prompt 只取未投递结果，最多 8 项；提示组装后才写父 timeline。
- `finish` 门禁：无活跃子任务，且最新结果已进入产生该动作的模型输入；晚到结果会拒绝本轮 finish。
- 状态：`queued/preparing/running/cancelling/completed/failed/cancelled/timed_out`。
- 配额：`MaxSubAgents` 默认 5、上限 20；pending 20；submitted 100；连续 20 次无进展停止；取消不耗预算。
- 取消协作式，清理最多 1 秒；`cleanup_pending` 如实上报；晚到结果隔离。
- 上下文：`fork` 或 `task_only`；子 worker 不写父 operator/vars/timeline。
- `loop_intent`：1 次 AI 生成 summary、keywords、tags、questions；本地 BM25；超过 12 个匹配才做第 2 次 AI 推荐。

采用：

1. async 必须有 job 回执、结果引用与 revision、finish 门禁、配额、协作取消。
2. `wait` 是观察窗口，不设置执行超时。
3. 子 worker 不直接写父图；结果由 manager 或父统一提交。
4. pi 不会自动续父轮；交互模式由模型继续本地动作或 `wait`，headless 才使用 `sendMessage({triggerTurn:true})`。

---

## 9. 工程约束

1. 图快照使用文件引用：`graph.json` 路径与有界摘要。
2. Reason 写入语义：处理 409 与重复 Intent；`complete` 写入失败必须重试或报错；`created==0` 不计成功。
3. flag 生命周期：candidate → recorded → submitted/rejected；按值去重；先记录后提交。
4. Observer 节流：6/10/12/3 与 activity fingerprint；board 上限 12/8。
5. 编译器参数：60k、10 turns、Read/Grep only、no Write、handoff marker；PromptCompiler 1 turn、无工具。
6. 独立 trust gate：`.ctf` 与项目资源单独 gate；headless 拒绝。
7. 独立 complete evaluator：不依赖 solver 自判；flag 仍走 oracle。
8. 两层预算：worker 默认 300 秒、host 上限 30 秒；request 2MB、output 128KB、budget 1KiB–128KiB。
9. 工具可见性：删除不用的工具定义；MCP namespace 与 containment；benchmark 默认关闭 WebSearch/WebFetch。
10. Windows 锁：使用 `LockFileEx`，不假设 `fcntl`。

---

## 10. 来源

- Cairn: <https://github.com/oritera/Cairn>
- Sapper: <https://github.com/N1nEmAn/sapper>
- SapperLens: <https://github.com/inwpu/SapperLens>
- BreachWeave: <https://github.com/m-sec-org/BreachWeave>
- CHYing: <https://github.com/yhy0/CHYing-agent>
- dsh-ops: <https://github.com/T-Auto/dsh-ops>
- pi-code: <https://github.com/ilovepixelart/pi-code>
- pi-agent-plugins: <https://github.com/BlockedPath/pi-agent-plugins>
- Yak async subagents: <https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/docs/20-background-subagents.md>
- Yak subagent manager: <https://github.com/yaklang/yaklang/blob/main/common/ai/aid/aireact/reactloops/subagent_manager.go>
- omp: <https://github.com/can1357/oh-my-pi>
