# dsh-ops 与 pi 社区插件：可借鉴的 Rust 优化与插件工程 v0.1

> dsh-ops 实际是 **JS 插件 + 一次性 Rust worker**，不是纯 Rust 插件。
> 它最值得学的不是语言，而是：**有界协议、PTC 代码调用、结果引用、渐进披露、token 预算**。
> pi 社区插件最值得学的是：**小而专、信任边界、可组合、可回滚**。

---

## 0. 结论

pi4ctf 应该借：

1. **一次性 Rust worker + 有界 JSON 协议**：无 daemon，30s/128KB/64KB/10MB 分层预算。
2. **PTC / code-mode**：模型写一小段代码，一次调用批量做 read/grep/stat/diff/run，返回结构化 JSON。
3. **结果引用与分页**：大结果进 session store，`page/release`，显式 `complete/nextOffset`，不静默截断。
4. **上下文读取去重**：同一内容已在上一次模型请求里，就只回 `unchanged + revision`。
5. **渐进披露**：默认只暴露 3 个工具；可选探针/skill/MCP 按需加载。
6. **信任边界**：项目资源默认不可信；headless 不加载未批准项目资源；MCP 按插件实例授权。
7. **预编译二进制 + 校验 + 无 postinstall 编译**；benchmark gates 把 token/时间纳入 CI。

不借：

- 31 个工具/大插件市场/多 profile 安装器。
- 完整文档解析器（PDF/DOCX/CSV）进 v1；CTF 用外部工具。
- 复杂 PTC SDK 18 API 全量；先 8–10 个。
- 多实例/8 pane/32 并发；pi4ctf 先单 agent。

---

## 1. dsh-ops 的 Rust 优化拆解

### 1.1 形态：一次性 worker，不是常驻服务

- `dsh-ops-worker` 每次调用：读一个 bounded JSON 请求 → 执行 → 写一个 JSON 结果 → 退出。
- 没有常驻 server；卸载/权限降级会 abort 在途 worker。
- 请求信封：`{ version, requestId, component, budget, request }`。
- 预算：默认 30s；transport 128KB；模型文本 64KB；结果存储 10MB/result、100MB/session。
- 超限返回 `OUTPUT_LIMIT`，不是静默截断；mutation receipt 丢失时标 unknown effects，不自动重试。

**对 pi4ctf**：

- `ctf-rt exec` 保持一次性；`ctf-rt session` 只保留 PTY 子进程。
- 每个工具结果有明确 budget：`timeoutMs`、`maxBytes`；超限返回 `partial` + `nextOffset`。
- 区分 **transport / model / storage** 三层预算，不混为一个“max output”。

### 1.2 Crate 拆分：单一职责，内核 crate 禁止 unsafe

```text
ops-protocol   请求/错误/job 记录/权限
ops-files      无 follow 的句柄、读、CAS 发布、元数据、树操作
ops-search     glob/grep/replace
ops-results    有界结果存储、分页、审计
ops-documents  CSV/DOCX/PDF（可选）
ops-batch      plan/resume、写前状态、保守恢复
```

**对 pi4ctf**：

```text
ctf-protocol   JSON 信封、错误码、预算
ctf-store      atomic write、flock、节点文件
ctf-graph      fact/intent/hint、ready/frontier、校验
ctf-flag       ledger、oracle、去重
ctf-exec       进程组、超时、网络检查
ctf-pty        ConPTY/Unix PTY、增量读
ctf-shape      确定性整形、compact ranges
ctf-results    结果存储、分页、引用
ctf-trace      verified trace
```

内核 crate 禁止 unsafe；平台 FFI 单独 crate。

### 1.3 PTC：模型写代码批量调工具

dsh-ops 的 PTC：

- 18 个 typed API：文件/文档工具 + batch + result + loader。
- 模型写 TypeScript 调用 `tools.ops_grep(...)`、`tools.ops_read_files(...)`，一次完成多步。
- 结果是 typed Outcome：`status: completed|partial|failed`、`data`、`error.code/nextAction`、`coverage`、`continuation`。
- 大结果用 `ops_result` put/page/release；页有 `nextOffset`、`complete`、`maxBytes`。
- 文件工具失败是值，不是抛异常；模型必须检查 `status`。

**对 pi4ctf**：

- `ctf_session` 的 `py` preset 暴露 **CTF SDK**（不是 18 个）：
  ```python
  read(path, offset=None, limit=None)
  read_many([{path, offset, limit}, ...])
  grep(pattern, path=".", glob=None, mode="content|count|summary")
  stat(path)
  diff(path_a, path_b)
  run(cmd, timeout=120)          # ctf-rt exec
  graph(action, **kwargs)        # fact/intent/status 只读
  result.put(items) -> ref
  result.page(ref, offset, limit, fields) -> rows
  result.release(ref)
  ```
- 一次脚本完成“列文件 → 读关键文件 → grep → 跑命令”，只回结构化结果。
- 默认返回 compact；大结果走 `result.page`。
- 不做 JS SDK；Python 足够 CTF。

### 1.4 Compact results：行号、范围、receipt

dsh-ops Native 输出：

- `=== FILE: path (Lines a-b of n) ===` + `N | text`。
- 完全返回的多文件范围可用 `N|text`；共享父路径。
- 64KB escaped cap；截断标 `Display incomplete` / `TruncatedBy`。
- 变更只回 receipt（revision、changed count、bytes），不回显内容。
- `nextOffset` / `complete` / `pending` 显式。

**对 pi4ctf**：

- `ctf_run` summary 用固定头：`=== CMD cmd-7 (exit=0, 42ms) ===`，行号。
- artifact 读用 `read path:120-180`；不重抄。
- 变更/flag 提交只回 receipt，不重复内容。
- 任何截断都带 `nextOffset`/`complete`，不允许“看似完整”。

### 1.5 上下文读取去重

dsh-ops：

- 只有证明“完全相同的成功结果已经在最近一次完成的模型请求里”，才把重复读替换为 `unchanged + revision`。
- 证据包括：tool/result message identity、source call、exact text、latest request、同一 session、path/file identity/size/mtime/revision、请求参数/range。
- 失败/中止/压缩/权限变更/变更工具结果都会使证据失效。
- 不是 I/O cache；不省磁盘读，只省模型输出/上下文 bytes。

**对 pi4ctf**：

- `ctf_run` 对同一命令 + 同一 artifact hash 的重复调用，可返回 `unchanged` + `artifact` + `hash`，如果该 artifact 已在最近一次请求中完整出现。
- `read artifact` 同样：同一 range + 同一 revision → `unchanged`。
- 只在证据充分时启用；默认保守，不确定就回全文。
- 这对“反复看同一段日志/脚本”非常省 token。

### 1.6 渐进披露

dsh-ops：

- `deferLoading` + `tool-addition`：工具声明可延迟，模型看到 addition 后才激活；保护 prompt cache。
- skill 目录只给 name + 一句摘要；模型调用 `skill` 才加载全文。
- 高级工具（PDF/DOCX/CSV）默认不在 schema，`ops_discover_tools` / `ops_load_sdk` 按需激活。

**对 pi4ctf**：

- 默认 3 个工具；可选探针/浏览器/逆向 MCP 不进默认 schema。
- skill 只给目录摘要，命中后 `/skill:` 加载全文。
- 如果 pi 支持 `defaultActive: false` / tool_search，底层 MCP 工具延迟暴露。

### 1.7 权限/安全

dsh-ops：

- 每次调用重新解析 `sandboxPolicy`；无 unconfined fallback。
- 路径 no-follow、拒绝 symlink/junction、更新锁 sidecar、CAS 发布。
- 请求 bounded stdin JSON，不是 shell 命令；路径列表不拼 argv。
- 卸载/权限降级 abort 在途 worker；结果引用绑定 session/authority。

**对 pi4ctf**：

- `ctf_run` 每次重新检查 allowedHosts/工作区边界；没有“上次允许所以这次也允许”。
- 路径 no-follow；符号链接逃逸拒绝。
- 写入 tmp + rename；flock；不把路径拼 shell。
- 权限/配置变化使旧结果引用失效。

### 1.8 打包与基准

dsh-ops：

- 预编译 `win32-x64`/`linux-x64`/`darwin-arm64`；版本/校验 receipt；无 postinstall 下载/编译。
- `bench/` + gates：fixtures、指标、integrity、provenance、PDF gates；CI。

**对 pi4ctf**：

- `bin/<platform>/ctf-rt` 预编译；SHA256 receipt；npm optional deps 或包内二进制；不 postinstall 编译。
- `bench/gates`：token、turns、time、artifact bytes；CI 阈值。
- 不支持平台 fail closed + 明确错误，不静默降级到慢路径。

---

## 2. pi 社区插件可借鉴

### 2.1 pi-code（Claude Code 体验）

- 一个包聚合：hooks、MCP、commands、skills、subagents、memory、todo、checkpoints/rewind、goals、web。
- **信任模型**：项目 `.claude` 资源默认不可信；headless 不加载未批准资源；hook 超时 fail closed。
- **goal**：`/goal <condition>` 持续工作，直到独立模型检查确认条件成立；有 status/clear/block cap/背景工作延迟。
- checkpoints/rewind、todos、AskUserQuestion、memory index、statusline。
- 开发：biome + strict tsc + knip + vitest coverage + e2e smoke。

**借鉴**：

- 项目资源信任：`.ctf`/项目 skill/MCP 默认不可信；headless 不加载。
- `goal` 模式：CTF 可以用 `goal` 代替“直到 flag”；但 flag 必须 oracle，不能模型自判。
- checkpoint/rewind、todo、ask 这些 UX 可以作为可选包，不必进核心。
- 质量门：strict types、单测、e2e smoke。

### 2.2 pi-agent-plugins（Agent Plugins 1.0.0）

- 发现 `plugin.json`；skills + MCP；closed schemas；文件系统 containment；插件变量 `${PLUGIN_ROOT}`/`${PLUGIN_DATA}`。
- **MCP 信任**：每个插件实例显式 trust；项目插件数据隔离；managed MCP ledger；卸载只删自己投影的 MCP。
- 项目 MCP 投影到 `.pi/mcp.json`，用户投影到 `~/.pi/agent/mcp.json`，不泄漏到别的 cwd。
- npm 安装 `npm pack --ignore-scripts`；git shallow clone；staged + manifest 校验。

**借鉴**：

- 如果 pi4ctf 未来分发 skills/MCP/agents，采用同样边界：项目资源 trust、命名空间、managed ledger、数据隔离。
- `ctf` 包不要直接改用户全局 MCP；用项目 `.pi/mcp.json` 或 extension `registerMcpServer`。
- 安装不执行 lifecycle scripts。

### 2.3 pi-agent-extensions（17 个小扩展）

- 每个扩展单一职责：sessions、ask_user、handoff、files、notify、context、review、loop、todos、control、answer、cwd_history、btw、powerline-footer、session-breakdown、workflow。
- 可单独 `-e` 加载；可整体安装。
- UI/命令/工具分离；不强行一个大包。

**借鉴**：

- pi4ctf 可以拆成小资源：`ctf-core`、`ctf-observer`、`ctf-tui` 可选；但运行时保持一个 Rust binary。
- 每个扩展可独立关闭；默认只开核心。

### 2.4 pi-subagents（typed/parallel）

- 单/并行/后台；agents；工具白名单；worktree；live fleet；typed results。
- 借鉴：CTF 子 Agent schema、后台、并发上限、可杀/可 steer。
- 不借：32 并发、worktree（CTF 不需要）。

### 2.5 pi-web-access

- 搜索/抓取/PDF/视频；多 provider。
- 借鉴：CTF 的外部检索/URL 读取应独立包，不塞进核心；比赛规则可关。

---

## 3. pi4ctf 具体改造

| 改造 | 来源 | 落点 |
|---|---|---|
| 一次性 worker + 分层预算 | dsh-ops | `ctf-rt` 请求信封；30s/128KB/64KB/10MB |
| crate 拆分 + 内核禁 unsafe | dsh-ops | `ctf-protocol/store/graph/exec/pty/shape/results` |
| Python CTF SDK（PTC） | dsh-ops | `ctf_session py` prelude：read/read_many/grep/stat/diff/run/graph/result |
| 结果引用/分页 | dsh-ops | `result.put/page/release`；`nextOffset/complete` |
| compact ranges/receipt | dsh-ops | `ctf_run` summary、artifact 行号、变更 receipt |
| 读取去重 | dsh-ops | 同一命令+artifact hash 在最近请求中出现 → `unchanged` |
| 渐进披露 | dsh-ops/pi | 3 工具默认；探针/skill/MCP 按需 |
| 信任模型 | pi-code/pi-agent-plugins | 项目资源默认不可信；headless 不加载 |
| 预编译+校验 | dsh-ops | `bin/<platform>/ctf-rt` + SHA256；无 postinstall 编译 |
| bench gates | dsh-ops | token/turns/time/bytes CI 阈值 |
| 小扩展可组合 | pi-agent-extensions | core/observer/tui 可选；默认只开 core |

### 3.1 `ctf_session py` SDK（优先级最高）

一次脚本完成：

```python
files = read_many([
    {"path": "chall", "offset": 1, "limit": 80},
    {"path": "libc.so.6", "offset": 1, "limit": 40},
])
sec = grep("checksec|canary|PIE", path=".", glob=["*.txt", "*.md"])
out = run("checksec --file=./chall", timeout=30)
graph("fact", description="chall: PIE off, NX on", source=out["command_id"])
```

返回结构化 JSON，模型只读结论；大结果 `result.page`。

### 3.2 结果预算

- `transport`: 128 KB serialized JSON。
- `model`: 64 KB escaped display。
- `result store`: 10 MB/result，100 MB/session。
- `timeout`: 30s worker；`ctf_run` 可 120s，但需显式。
- 超限返回 `partial` + `nextOffset`，不静默截断。

### 3.3 信任边界

- 项目 `.ctf`/`.pi` 的 skill/MCP/agents 默认不可信；首次需确认。
- headless 不加载未批准项目资源。
- MCP 按插件实例 trust；managed ledger 只删自己投影的条目。
- `allowedHosts` 每次执行重查。

---

## 4. 不借

- dsh-ops 的 31 工具/多 profile 安装器/panel/TUI。
- PDF/DOCX/CSV 原生解析进 v1；CTF 用外部工具。
- 18 API 全量 PTC；先 8–10 个。
- 多实例/8 pane/32 并发。
- pi-code 的全量 Claude 兼容层；只借信任/checkpoint/goal 思想。
- worktree isolation（CTF 每题独立 workspace）。

---

## 5. 实验

1. `ctf_session py` SDK vs 多条 `ctf_run`：tokens/turns/solve。
2. `result.page` vs 全文 artifact：tokens/恢复率。
3. 读取去重 on/off：tokens/重复读次数；确保不丢失变更。
4. compact ranges/receipt vs 原始输出：tokens/误解率。
5. 预编译二进制启动/RSS/整形 vs Node 基线。
6. bench gates 阈值是否误伤。

---

## 6. 来源

- dsh-ops: <https://github.com/T-Auto/dsh-ops>
- dsh-ops native PTC: <https://github.com/T-Auto/dsh-ops/blob/main/docs/native-ptc.md>
- dsh-ops result budgets: <https://github.com/T-Auto/dsh-ops/blob/main/docs/result-budgets.md>
- dsh-ops context dedup: <https://github.com/T-Auto/dsh-ops/blob/main/docs/context-read-dedup.md>
- dsh-ops file batching: <https://github.com/T-Auto/dsh-ops/blob/main/docs/file-batching.md>
- pi-code: <https://github.com/ilovepixelart/pi-code>
- pi-agent-plugins: <https://github.com/BlockedPath/pi-agent-plugins>
- pi-agent-extensions: <https://github.com/jayshah5696/pi-agent-extensions>
- pi-subagents: <https://github.com/nicobailon/pi-subagents>
- pi-web-access: <https://github.com/nicobailon/pi-web-access>
