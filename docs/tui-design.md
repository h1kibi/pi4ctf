# pi4ctf TUI 设计（pi 适配层）

> **TUI 不是内核。** 它只读 `.ctf/` 与内核状态，负责把「题目、队列、job、flag、预算」投影成可读界面。
> 不自建终端渲染器；使用 pi 已有的 TUI 组件、主题、键位与 overlay 机制。
>
> **状态：later 子设计。** 当前里程碑不做 TUI；本文保留为 adapter 层参考。
>
> 借鉴 omp 的是**信息结构**与**渲染纪律**，不是重写 omp 的 TUI。

---

## 0. 目标

1. 一眼看到：当前题目、当前 Intent、活跃 job、flag 状态、剩余预算。
2. 工具调用可读：`case`/`run`/`session` 各自有稳定的卡片，默认折叠，按需展开。
3. `/ctf` 打开一个只读 dashboard：Case / Queue / Jobs / Flags / Artifacts / Env。
4. 交互模式有 TUI；headless/RPC 不依赖 TUI，功能不缺失。
5. 渲染不在热路径做 I/O；不因为状态刷新拖慢模型。

## 1. 边界

| TUI 做 | TUI 不做 |
|---|---|
| 读 `case status`、`job inspect`、`graph` | 写 Fact/Intent/flag/状态 |
| 渲染状态、队列、job、flag、artifact | 执行命令、保存 artifact |
| 键位导航、折叠/展开、overlay | 自建 ANSI 渲染器 |
| 在 `ctx.mode === "tui"` 时启用 | 在 headless/RPC 里假装有 UI |
| 通过主题 token 着色 | 硬编码颜色、键位、宽度 |

TUI 的写操作只有一种：用户显式触发的 UI 动作（例如确认打开某个 artifact），仍然通过 adapter 调内核，不直接写 `.ctf/`。

## 2. 使用 pi 的四个挂载点

### 2.1 状态文本

`ctx.ui.setStatus("ctf", text)`：

```text
crypto · i3/5 · job 1 · flag 0 · 12:34
```

- 单行、短、稳定；不放大段文本。
- 无 UI 时是 no-op；不要让状态文本影响工具行为。
- key 固定为 `ctf`，清理时传 `undefined`。
- pi 的 `setStatus` 是 keyed text，不是 omp 的分段栏；分段信息放 HUD widget。`setFooter` 能做完整分段，但会替换 pi 内置 footer（model/context/git），v1 不用。

### 2.2 HUD widget

`ctx.ui.setWidget("ctf-hud", component, { placement: "aboveEditor" })`：

```text
╭ CTF  crypto  csaw2018-babycrypto ──────────────────────────╮
│ i3/5  SQLi probe          job 1 running   flag 0/1   12:34 │
│ f0012  nginx 1.24 @ 10.0.2.15:80       cmd-0012  0.42s     │
╰────────────────────────────────────────────────────────────╯
```

- 两行以内；宽度不足时按优先级裁剪。
- 默认 `compact`；`minimal` 只保留题目/Intent/时间；`full` 增加 Fact/命令摘要。
- 每 1 秒最多刷新一次；只在可见时刷新；状态 revision 不变则不重绘。
- 组件实现 `invalidate()`；状态变化后 `tui.requestRender()`。

### 2.3 工具卡片

使用 pi 的 `renderCall` / `renderResult`，不新增工具：

**`case`**

```text
case  f0012 +1 fact  i3/5  flag 0/1
```

展开后：project、goal、origin、deadline、queue head、最近事件、warnings。

**`run`**

```text
✓ cmd-0012  exit 0  0.42s  1.2 KB  wsl2  → artifacts/cmd-0012.log
```

展开后：purpose、argv/command、cwd、backend、network verdict、summary（前 12 行）、artifact 路径/行范围、truncated。

**`session`**

```text
● session s1  bash  seq 42  12 KB  alive
```

展开后：preset、cwd、最后输出、artifact 路径、exit 状态。

规则：

- 默认折叠；`expanded` 状态由 pi 提供。
- 运行中显示 spinner/耗时；完成显示 exit/duration/size。
- 错误用 `error` 主题色，截断用 `warning`；不要用颜色作为唯一信息。
- 大输出不内联；卡片只显示 summary + artifact 引用。
- 卡片不执行命令、不读大文件；数据来自工具结果 `details`。

### 2.4 `/ctf` dashboard overlay

`ctx.ui.custom(..., { overlay: true })`，只读：

```text
 CTF  babycrypto                         [1]Case [2]Queue [3]Jobs
 ─────────────────────────────────────────────────────────────
 Case      crypto · active · deadline 12:34 · backend wsl2
 Queue     i0004 active   i0005 pending   i0006 pending
 Jobs      job-0003 running  cmd-0012  0.42s
 Flags     0 accepted · 1 candidate
 Artifacts 7 files · 128 KB
 Env       wsl2 · kali · python 3.12 · gdb 15.1
 ─────────────────────────────────────────────────────────────
 j/k move   enter expand   r refresh   esc close
```

- Tab/数字切换；`j/k` 移动；`enter` 展开；`r` 刷新；`esc` 关闭。
- 使用注入的 `keybindings`，不硬编码按键。
- overlay 打开时才刷新；关闭后停止定时器。
- 不提供“直接改 Fact/flag”的编辑；只读。
- flag 确认/提交必须走显式命令，不在 dashboard 里一键自动提交。

## 3. 渲染纪律（borrowed from omp）

| omp 做法 | pi4ctf 落实 |
|---|---|
| 渲染器只做 viewport 差分，history 由产品决定 | 用 pi 的 TUI；不接管 history/scrollback |
| 组件返回稳定数组引用，容器做 memo | HUD/卡片缓存 `cachedWidth/cachedLines`，状态不变返回同一数组 |
| 宽度安全、ANSI-aware | 只用 `truncateToWidth`/`visibleWidth`/`wrapTextWithAnsi` |
| 状态栏分段 + preset + priority | HUD 三档 preset；窄屏按优先级隐藏段 |
| 状态栏缓存/TTL，禁止每帧跑 shell | 只在 revision 变化或 1s tick 时刷新；不做 `git status` 类每帧命令 |
| 工具卡片 renderer registry + fallback | 每个工具一个 renderer；失败回退到简单文本 |
| focus/overlay/cursor 显式 | 用 pi 的 `Focusable`/overlay；组件 `dispose()` 清定时器 |
| 主题 token 语义化 | 只用 `theme.fg/style`；不硬编码 ANSI |
| 组件 `dispose` 幂等 | 定时器、订阅、子进程在 dispose 中清理 |

不借：

- omp 的完整渲染引擎与 native/TSP 协议。
- 7 套状态栏 preset 与 powerline/nerd 依赖。
- 鼠标优先、图片协议、全屏多面板的复杂布局。
- 为 UI 单独维护一套状态机。

## 4. 数据流

```text
kernel status/job/graph  ──read-only──>  TuiStore (revision cache)
        ▲                                      │
        │ tool result / job event              │
   adapter ────────────────────────────────────┘
        │ setStatus / setWidget / custom / renderCall
        ▼
      pi TUI
```

- `TuiStore` 保存：project、status、queue head、active job、flag 摘要、last event revision。
- 工具结果返回 `details` 时，adapter 更新 `TuiStore`，再 `invalidate`。
- job 完成通过 `job.inspect` 或 adapter 事件更新；不轮询高频。
- 所有读取有超时（1s）；失败显示 `stale`，不阻塞主流程。

## 5. 预设

| preset | 内容 | 场景 |
|---|---|---|
| `minimal` | 题目、Intent、剩余时间 | 小终端、专注 |
| `compact` | + job、flag、最近 Fact | 默认 |
| `full` | + backend、artifact、env 摘要 | 调试/复盘 |

preset 通过 `CTF_TUI_PRESET` 或 `/ctf-tui` 切换；默认 `compact`。不做用户自定义主题编辑器。

## 6. 模式与降级

- `ctx.mode !== "tui"`：不挂 `setWidget`/`custom`；工具/状态功能照常。
- `ctx.hasUI` 为 false：`setStatus` 不发；日志写 stderr。
- RPC：`custom()` 不支持；只提供文本状态或 RPC 支持的 dialog。
- 终端宽度 < 60：只显示 `minimal`；卡片省略 artifact 路径。
- 主题缺失：用 pi 默认主题；不自己探测颜色。

## 7. 测试

- 组件 golden：40/80/120 宽度；长题目名、长路径、CJK、ANSI。
- 状态：无 job、job running、job failed、flag accepted、deadline 过期。
- 交互：overlay 打开/关闭、tab 切换、focus、`esc`、定时器 dispose。
- 性能：100 次状态更新不触发 100 次重绘；无每帧 shell。
- 真实终端：Windows ConPTY + Linux PTY 各跑一次 smoke。
- headless：`ctx.mode=json/print` 不挂 UI，工具仍可用。

## 8. 里程碑

| 阶段 | 交付 |
|---|---|
| T0 | `setStatus` + HUD widget + `case`/`run`/`session` 卡片 |
| T1 | `/ctf` overlay：Case/Queue/Jobs/Flags/Artifacts/Env |
| T2 | 三档 preset、宽度优先级、CJK/窄屏 golden |
| 后置 | 可选图形化 diff/图像、更多面板；不做 omp 克隆 |

## 9. 一句话

**TUI 是 adapter 的只读投影，不是第二个内核；用 pi 的渲染器，借 omp 的信息结构与渲染纪律。**
