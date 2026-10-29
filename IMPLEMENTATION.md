# pi4ctf 实现说明（TS walking skeleton）

> 对应施工基线 [`docs/design.md`](docs/design.md) 的**第一交付**（§9）。
> 行为冻结后按基线移植 Rust `rt`（docs/kernel-design.md）。
> 本版已按第一轮外部评审（C1–C6 / R1–R10）修复，192 项测试全绿。
>
> **最终验证（2026-10-29）**：`npm test` 在 Windows / Node 22.20.0 为 **188 pass / 4 skipped**
>（PTY 测试需要 POSIX 宿主）；GitHub Actions（ubuntu-latest / Node 22）为 **192/192、0 skipped**；
> `toolbox-digest.sh` 输出合法 JSON（构建期断言 ≤512B）；
> 验证环境 Docker 可用并存在一个 pwn 镜像；Kali sandbox 全量镜像未构建，
> R6 的镜像 gate 仍需在有 Docker 的机器上完成。
>
> 收尾补强：flag dedupe 的读取 + 追加 + 事件整体入项目锁；session manager
> 以 `project.root` 为 key，`root` / `root/.` 不再绕过 4-session 上限。
> 并发 flag 手工验证：5 个进程同时提交同一 flag → `1 accepted / 4 rejected`。

## 已交付（第一交付 6 项）

| # | 基线条目 | 实现 | 测试 |
|---|---|---|---|
| 1 | `run/exec.ts` + raw/shaped + 原子 artifact | `src/kernel/run/exec.ts` | `exec.test.ts` |
| 2 | `shape@1` / `signature@1` + fixture | `src/kernel/shape/{shape,signature}.ts` + `fixtures/shape/` | `shape.test.ts` / `signature.test.ts` |
| 3 | `ledger/store.ts` + claim/negative | `src/kernel/ledger/store.ts` | `ledger.test.ts` |
| 4 | `context/packet.ts` + plan | `src/kernel/context/packet.ts` | `packet.test.ts` |
| 5 | `flag` | `src/kernel/flag/flag.ts`（四层 + local oracle） | `flag.test.ts` |
| 6 | 4 动词 adapter | `src/adapter/protocol.ts` + `src/rt.ts` | `protocol.test.ts`（E2E） |

外加安全边界（ADR 0003）：`src/kernel/security.ts` + `security.test.ts`。

pi 集成（不在这 6 项内核交付内）：

- `extensions/ctf.ts`：注册 `run` / `session` / `claim` / `flag` 四个工具，`/ctf` 命令，
  并在 `before_agent_start` 注入 kernel packet；
- `skills/ctf/SKILL.md`：四动词工作流、quote/flag 规则、W1 边界；
- `package.json` 的 `pi` manifest 指向上述资源；已执行
  `pi install ./`；
- 安装后的 pi 是 standalone `pi.exe`，扩展用 `node` 启动 `dist/rt.js`（不是
  `process.execPath`）；`PI4CTF_NODE` / `PI4CTF_RT` 可覆盖；
- 验证环境：安装后的 pi 通过 `run` → `claim` → `flag` 完成合成闭环，
  `session` open/write/read/close 可用，`/ctf init` 能创建项目。

### 自动初始化 / 静态预检 / 进程观测

- **自动初始化**：`session_start` 在没有 `.ctf/project.json` 时，若目录含 ELF 或
  CTF marker，调用 `project.init`（origin=`auto-init`）；`PI4CTF_AUTO_INIT=0` 关闭，
  `=1` 强制。自动选择 backend：有 ELF 且 Docker 可用 → docker，否则 host；
  优先 `../<challenge>-oracle.json`，再 `../oracle.json`；有效 oracle 的 `flag`
  前缀用于推断 flagFormat。自动初始化后立即执行 preflight。
- **静态预检**：`case.preflight` 扫描 root 下 ELF/libc（depth 2，跳过 `.ctf/.git/node_modules/workspace`），
  纯 Node 解析 ELF header/notes/dynamic/sections，并对 PE/Mach-O/ZIP/JAR/APK/PCAP 做轻量识别；产出 `.ctf/chal.json`：
  arch、PIE、canary、NX、RELRO、build-id、NEEDED/RUNPATH、interpreter、libc version、otherFiles。
  packet 增加 `## Challenge metadata` 摘要；`case_preflight` 工具/`/ctf preflight`
  可手动刷新，不占执行预算。
- **oracle pin 收紧**：只有含非空 `flag` 或 64-hex `flagSha256` 的 oracle 才会被 pin；
  空/无关的 `../oracle.json` 记为未 pin；有 target 时 init/configure 还会校验 target/instanceId/expiresAt。
- **backend 可修复**：`case.configure` 支持 `backend` / `dockerImage` / `target`，可在 host/docker 或 target 之间迁移而不丢证据。
- **进程观测**：`proc` 只接受 live session id（`s0001`），支持 `maps` / `libs` / `mem`
  （≤16KB）；host 读 `/proc/<pid>`，docker 读容器内 PID 1。输出落
  `.ctf/artifacts/proc-*`，是 observation，不是 Fact；不占执行预算。
- **实例 target**：`project.json.target` 记录 `host/port/protocol/instanceId`；`run` 支持
  `target`/`env` 覆盖，自动注入 `HOST`/`PORT`/`TARGET`/`INSTANCE_ID`，并把 target
  写入 ProcessOutcome。声明 target 时 run 先做 TCP 可达性检查；不可达返回
  `TARGET_UNREACHABLE` 且不占预算（`skipTargetCheck` 用于 run 内自起靶机）。
  Java 挑战的 auto-init marker 含 `.jar/.class/.war/.jsp/.java`；`ctf_init` 工具提供显式初始化 fallback。
  若 oracle 带 `reset` HTTP hook，host 侧不可达会先调用 reset（最多 3 次/题，轮询 30s）；
  恢复后继续，不退还 slot；无 hook 不伪造恢复。
- **target-unreachable**：ECONNREFUSED/Connection refused/连接超时/ECONNRESET 等标记
  `semanticFailure=target-unreachable`，不进入利用路线负账本。
- **oracle 实例绑定**：oracle 可带 `target`/`instanceId`/`expiresAt`；case 有 target 时，oracle
  必须匹配；有 instance 时，oracle 必须带 instanceId；无 instanceId 时，oracle 必须带 expiresAt。flag provenance 只接受当前
  target/instance 的 artifact，旧实例 artifact 不能给新实例 flag 做证据。
- **Java/JDK**：preflight 读 `.class` 的 major version（52=JDK8、55=JDK11），提示兼容性；镜像需另配，不自动下载。
- **flagFormat**：默认是通用 CTF 形态（`NSSCTF{}`/`flag{}` 等任意常见前缀；裸 token 需显式 flagFormat），不再假设
  `flag` 头；显式自定义格式仍严格。format/oracle 拒绝只对同一
  format+oracleHash+target+instance 上下文 definitive，reconfigure 后可重试。
- **synthetic**：`run.synthetic` / `artifact.ingest.synthetic`；claim/fact/flag 记录
  synthetic，packet 隐藏 synthetic facts，`case.complete` 和真实 flag 拒绝 synthetic。
- **artifact 检索**：`case_evidence` / `case.evidence` 支持 `grep/context/maxMatches/head/tail`，父 probe-batch 会返回 children，grep 自动遍历 children；
- **probe 部分结果**：`run.probes` 返回 `completed/timedOut/notRun/incomplete/errors`；单 item 错误不 reject 整批；
- **环境记忆**：`env_memory` 记录当前 host/docker/wsl 的工具路径/版本；probe 的 absent 只追加负记忆，不删除已知工具（删除只由 forget 执行），工具存在时 recall 仍返回同名 absent 并标注 reason=not-on-path；probe 的 null version 不覆盖已有非 null version；absent 带 expiresAt/expired，旧记录读取时迁移 origin=legacy/pathSource/onPath；tool 记录返回 pathExists/verifiedAt/declaredAt/versionSource；wrapper 修复记录 wrapperPath/wrapperTargetMissing/pathRepaired；id 支持 `A-Za-z0-9._+-` 和可选 `@major`，version 允许空格/括号；store 在宿主 `$PI4CTF_HOME/envs/<userNs>/`（默认 `~/.pi4ctf`），容器不挂载；`probe` 走 runInternal 且不占预算；内置表覆盖 jdk/python/gdb/jadx/ghidra，未知 id 走通用 PATH/`--version` probe；Windows 保持 `where` 的 PATH 顺序；`.cmd/.bat` 通过 `cmd.exe` 执行，带 Windows shebang 的 extensionless 脚本用解释器执行，POSIX/MSYS shim 跳过；Docker 路径用 POSIX 归一化；版本只在 exit=0 时解析，优先 stdout，并支持多组版本参数；`case.doctor` 读 env-memory 视图。
- **preflight 卫生**：每次 session_start 刷新；忽略 `core*`、`*.core`、压缩包、
  `workspace/`，支持 `.ctfignore`；识别非 ELF 格式并给出轻量 arch/entry/archive 摘要到 `otherFiles`（`chal.json` 为 cap 内索引，packet 只给 root/generated 摘要，`case_preflight` 返回 rootFiles/generated 数组；files=所有 ELF，otherFiles=所有非 ELF，rootFiles=非 generated 根文件，generated=workspace/build）；根目录新文件始终视为附件材料；只有 `workspace/` 或 `includeBuild=true` 输出目录为 generated；根目录不做后缀/mtime 启发式；`workspace/` 默认忽略，`includeWorkspace=true` 才扫描且优先占名额；`build/out/dist/target/obj/__pycache__/screenshots/shots` 默认忽略；达到文件 cap 写 note；`chal.json` 记录 endpoint。

评审回归：`src/test/regressions.test.ts` 覆盖 C1/C2/C4/C6/R2/R4/R7/R8；
`rt-session` 覆盖 C3/C4；`session` 覆盖 C5/R9；完整 192 项由 `npm test` 统一跑。

## 评审修复对照（C1–C6 / R1–R10）

| 项 | 修复 | 回归测试 |
|---|---|---|
| C1 scope 绕过 | URL 扫描改为**全 token 内容匹配**（引号内、脚本体内都覆盖）、userinfo 取最后一个 `@` 之后的 host、含 `://` 但解析不出 host 的 token **fail-closed 拦截** | `regressions.test.ts` C1×5 |
| C2 symlink 逃逸 | `readArtifact` 逐段 `lstat` 拒 symlink + `realpath` 必须落在 `.ctf/` 内 | C2 |
| C3 session 崩溃 | open 前置 `commandExists` 快速失败（支持绝对路径），`child.on('error')` 兜底清理 | session + rt-session C3 |
| C4 4-session 绕过 | rt session server 按**规范化项目根**（`project.root`）缓存 `SessionManager`，上限为进程内项目级；不同路径写法不再产生新 manager | rt-session C4 |
| C5 env 泄露 | session 与 run 共享 `baseEnv()` allowlist，仅追加 `CTF_PROJECT` | session env 测试 |
| C6 破活锁 | `breakStale` 只在持有 pid 已死（`kill(pid,0)`）时破锁；活锁永不破 | C6 |
| R1 PowerShell 语义 | command 模式默认 `bash -lc`（无 bash → `UNSUPPORTED`），PowerShell 仅显式指定；signature/target/canonicalKey 一律基于**逻辑用户命令**而非 wrapper | exec closed-port |
| R2 伪造差分 | differential/time-based 强制所有腿 `argvTemplate` 相同（payload 槽已归一）+ 同 target，不同模板即拒 | R2 |
| R3 pipe 非 PTY | 见下方「已知限制」——W1 不把 session 算完成 | — |
| R4 截断静默 | `StreamInfo.outputTruncated` 落 ProcessOutcome + artifact meta + run.exec 事件 | R4（72MB 实测） |
| R5 原子性 | writePlan/handoff/flag.txt/session 状态统一 `atomicWriteFile`；`flags.jsonl` 的 **dedupe 读取 + 追加 + 事件**整体收进项目锁 | 既有套件 |
| R6 镜像不可复现 | 基镜像 digest ARG 钉死（placeholder 未替换则拒绝构建）、Ghidra sha256 校验、移除 ENTRYPOINT（argv 直跑）、toolbox digest 修复为**合法紧凑 JSON**（构建期断言 ≤512B） | `build-image.sh` gate 0 |
| R7 假阳性测试 | closed-port 测试改为诚实断言 nonzero-exit；no-output-when-expected 用真实空 body 200 服务覆盖 | R7 |
| R8 signature 偏差 | 简单字符集补 `=`，`key=短值` literal、`key=长值` payload，与 spec 一致 | R8 |
| R9 read 阻塞 | session read 改 Promise + `setTimeout` 轮询（150ms 静默窗），不再 `Atomics.wait` 卡事件循环 | session 全套 |
| R10 孤儿/O(n²) | stdin 超限在 spawn **前**拒绝；exec/session 捕获改 chunk 数组、结束一次性 concat | 既有套件 |

Optional 项同样已修：flag 占位符正则大小写不敏感、packet `clip` 改 UTF-8 字节感知（CJK 不再超 16KB）、`TURN_BUDGET` 从 types 共享（packet 与 adapter 同源）、`oracleRef` 收紧（必须相对路径、落在题目父目录内、不得指向 `.ctf/`）。

## Pwn 环境验证

使用环境中的 pwn 镜像作为 Docker backend：

```text
pwntools, gdb 13.1 + GEF, one_gadget 1.10, ropper 1.13,
ROPgadget 7.7, checksec, patchelf, socat, nc, python3
```

初始化：

```text
/ctf init 'flag\{[^}]+\}' ../oracle.json docker pwn <pwn-image>
```

- `run` 在容器内执行；`/challenge` 只读、`/challenge/workspace` 可写；
- `session` 也已支持 docker backend；pwn 交互在容器内跑；
- 目标服务若在宿主机，容器内用 `host.docker.internal:<port>`；
- 该镜像没有 radare2/pwndbg，使用 GEF + objdump/readelf；需要 r2 时可派生镜像；
- 验证：CTFTiny `baby_boi` 在 pwn 容器内经 ret2libc 解出，
  `run` 20 次、约 141s，claim + flag 全部 accepted；
- `session` docker backend 也已验证：`python3 -i` 在容器内保持交互；
- docker run/session 增加 `--cap-add SYS_PTRACE`，`proc mem` 可读容器 PID 1
  （实测 `python3 -i` 的 maps + mem 返回 ELF 头）；host backend 的 mem 仍受
  `kernel.yama.ptrace_scope` 限制。

## 预算与终止条件（外置，代码判定）

`run` 动词入口由内核强制（design.md §6，模型自评不算）：

- **turn 预算**：30 个 execution slots（`run` / `session.open` / `artifact.ingest`，`TURN_BUDGET`；一次 `run` 占一个 slot，`probes` 批内 1–16 item），超出返回 `LIMIT`；`case.restart` 可重置预算，最多 3 次，`case.close` 后 `run` 返回 `CONFLICT`；packet 显示 remaining/health + 同 category median（`PI4CTF_STATS_PATH`，默认 `~/.pi4ctf/solve-stats.jsonl`）；
- **代理环境**：默认与 pi bash 工具一致，保留 `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`（`NO_PROXY` 默认 `localhost,127.0.0.1,::1`）；`PI4CTF_INHERIT_PROXY=0` 才剥离；
- **Windows command 模式**：`run` 的 `command` 写入临时脚本再 `bash -l <script>`，避免 WSL 在 argv 层展开 `$var`；host 噪声 stderr 被过滤；
- **vision**：`deepseek_vision` 把 image item 的 raw bytes 以 data URL 发给 `deepseek-flash` vision（无需 tesseract）；
- **HTTP primitive**：`run.probes[].http` 支持 cookie jar、默认不跟随重定向、可选 raw socket、二进制 body artifact；
- **kernel probes**：`run.probes` 执行 1–16 个 probe（`concurrency` 1–4，默认顺序；`timeoutMs` 为 batch deadline），item 由 kernel 分类/负账本、独立 observation、支持 item differential；
- **evidence/1**：`run` 解析脚本 NDJSON item；`items/cmd-NNNN.NNNN.json` + item artifacts；`case.evidence` 受控读取；script-declared item 只能 interpreted，不产 Fact；
- **project configure**：`case.configure` 可修复 flagFormat / oracleRef / backend / dockerImage / target；pin 时校验新 target，或仅改 oracle 时的当前 target；无 port/UDP 不伪造可达，docker host 侧失败降级为 warning；pin 不接受 skip，不丢证据；
- **oracle pin**：`project.init`/`configure` 只对含 `flag`/64-hex `flagSha256` 的 oracle 记录 SHA-256，并在 pin 前校验 target/instanceId/expiresAt；缺失、无效或初始化后创建/修改的 oracle 在 layer4 拒绝（防自证）；
- **allowedHosts**：loopback（localhost/127.*/::1）始终放行；`case.configure` 可替换 allowedHosts。
- **claim 便利性**：quote 可省略 span，内核用唯一 substring 定位；grep 返回 start/end/matched。
- **派生 artifact**：`artifact.ingest` 支持 `transform=hex|base64`，meta/outcome 记录 sourceSha256 + derivedFrom。
- **probe bodyFile**：HTTP probe 从项目文件读 body，body digest 进入 route signature；`deepseek_search` content 默认 4000 chars。
- **负账本**：`exec-local`（python/node -c）不入负账；`family=environment` 的条目单独展示为 environment incidents，不当作路线 dead end；`case.restart`/`case_clear_negatives` 清理 transient（soft）条目，hard 保留；
- **session 预算**：`session.open` 消耗 1 次 `run` 预算，I/O 不计；预算耗尽后不能新开 session；
- **外部证据**：`artifact.ingest` 把外部文件复制进 `.ctf/artifacts` 并生成 outcome/observation，claim/flag 可使用；
- **preflight / proc**：`case.preflight`、`proc` 是静态/观测原语，不消耗 execution slots；`proc` 必须绑定 live session；
- **packet delta**：`case.context` 接受 `seenOutcomes`，已注入的 outcome 不再重复；
- **deadline**：`project.json.deadlineMs` 临近（60s 安全边际）返回 `TIMEOUT`；
- **签名门**：transient 失败按 TTL 阻断（过期写一次性 `unblocked` 审计事件并标记条目，
  重跑失败重新武装），确定性失败硬阻断返回 `CONFLICT`；
- **flag/oracle**：`case.complete` 需 ≥1 verified Fact——这是设计语义（"complete 只认
  verified Fact"，design.md §3/§7），flag 是否 accepted 是独立账本状态，二者不耦合。

## 信任边界的诚实声明

`checkRunScope` 是**辅助门**而非安全边界：字符串解析不可能追上 shell 语法全集。
已覆盖的绕过面（引号 URL、脚本内 URL、userinfo、不可解析 `://` fail-closed）都有回归
测试，但**可靠的 egress 隔离依赖 docker backend 的网络策略**（bridge + 不挂宿主网络），
这也是设计把 Kali sandbox 定为 P0 的原因。host backend 仅用于开发/测试。

## 与基线的偏差（TS skeleton 已知限制）

1. **session 默认管道，POSIX 可选 PTY**：契约（open/write/read 增量/resize/close、
   artifact、上限 4、EOF 清理）不变；`session open tty:true` 在 POSIX 宿主上用
   `python3` 分配伪终端并在 exec 前关闭 echo，覆盖 `isatty` 与 `/dev/tty`。Windows 仍是
   pipe-only；`resize` 在 tty 会话上转发（初始 80×24，SIGWINCH），管道会话只记录；
   tty 主机会话的 `proc` 读取不可用。Docker+PTY（宿主 PTY + `docker run -i -t`）以及
   backend 的 `/challenge` bind mount 已在 Docker Desktop 的 socket harness 上端到端验证。
2. **异族 verifier 未接**：谓词 `check:"verifier"` 路径降级 `interpreted` 不产 Fact。
   Fact 已记录 `verifiedBy`（`predicate` / `verifier`）和可选的 `verifier.model` /
   `promptVersion`，接入时必须带这套元数据；当前所有 Fact 都是 `predicate`。
3. **docker backend 需用户提供 pwn 镜像**；Kali 全量镜像仍带可复现性 gate，
   需在有 Docker 的机器上完成 `build-image.sh`（钉 digest → 双构建比对）。
4. **async job（`run.async`/`job.*`）未实现**：不在第一交付清单，随 Rust 阶段补。
5. 卡 + case / 评测矩阵 / race：W2 交付，未实现（基线明确）。
6. **proc 的 docker 视角是容器 PID 1**：若目标由 shell/launcher 再 fork，需要先让
   session 直接执行目标，或后续补容器内 PID 选择；真实 PTY 仍随 Rust 交付。
7. **preflight 是静态元数据**：不推断实际运行 libc/seccomp；运行时仍以
   `proc maps` + build-id/页对齐校验为准。
8. **target.up/down 仍是环境层**：当前用 `session` 承载常驻 socat/服务，再由
   `run` 的 target/env 连接；没有跨进程 target 生命周期管理器。
9. **没有 live oracle 协议**：静态 oracle 只能靠 target/instance 绑定避免旧实例复用；
   平台若只提供在线提交，需要外部 harness 写入 target-bound oracle。

## 运行

```bash
npm install
npm run build
npm test                    # 192 项；Windows 上 4 个 PTY 测试自动跳过

# one-shot JSON 协议（kernel-design §4.1）
echo '{"op":"project.init","root":"chall-dir","input":{"id":"c1","backend":"host"}}' | node dist/rt.js
node dist/rt.js --op run --root chall-dir --input '{"argv":["curl","-s","http://127.0.0.1:8080/"]}'
node dist/rt.js --op case.context --root chall-dir

# session（JSON-lines 长会话；4 动词的 session 腿）
node dist/rt.js --session
```

`.ctf/` 目录结构、错误码表、预算（120s/命令、600s 上限、64MiB artifact 上限且
截断必落盘、16KB packet）见 `docs/kernel-design.md` §2/§4/§5。

## Kali sandbox（P0 脚手架）

- `sandbox/Dockerfile.kali`：ARG 钉死基镜像 digest（未钉死则拒绝构建）、Ghidra
  sha256 校验、无 ENTRYPOINT（内核 argv 直跑）、`/challenge:ro` +
  `/challenge/workspace:rw`、bridge 网络。
- `sandbox/scripts/toolbox-digest.sh`：构建期生成镜像内 zero-LLM toolbox digest；它只描述镜像，不进入 runtime packet；用户环境工具由 `env_memory` 记录。
- `sandbox/scripts/build-image.sh`：gate 0 检查 digest 钉死 → 构建 → 双构建同 digest
  比对 → 导出 toolbox digest。
- 无 Docker 时默认 backend=docker 报 UNSUPPORTED（doctor 提示）；开发/测试用
  `backend:"host"`。

## 下一步（对齐 W1 剩余）

1. 5 题 first contact（web 盲注 / crypto RSA / pwn ret2win / rev UPX /
   forensics pcap）容器化 + 逐题标注识别/执行失败；
2. 有 Docker 的机器上完成 `build-image.sh`（digest 钉死值写入 Dockerfile）；
3. PTY（ConPTY/Unix）随 Rust 内核交付；每-claim 预算与 route drift 检测。
