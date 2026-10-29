# pi4ctf 多 item evidence 协议设计 v2

> 状态：**Phase 1 + Phase 2 已实现**。  
> 取代：[`multi-item-evidence-design.md`](./multi-item-evidence-design.md)  
> 对抗性评审：[`reviews/multi-item-evidence-adversarial-review.md`](./reviews/multi-item-evidence-adversarial-review.md)  
> 评审结论：**Revise**。v1 不能按原顺序实现。

## 1. 评审后的结论

v1 的三个根本问题：

1. **脚本声明的 item 不是 kernel observation**。脚本可以打印“server returned 200”，sha256 只能证明字节没变，不能证明是服务器说的；却可以铸造 Fact。
2. **没有受控的 item 读取路径**。模型只能绕过 kernel 用宿主的 `read` 读 artifact，破坏 `<UNTRUSTED_DATA>`/注入扫描/预算。
3. **用 item 包装会绕过负账本和 hazard table**。`exec-local` 本来就不入负账，item 失败又不入，等于用 wire format 删掉终止条件。

v2 因此不再把“脚本输出多个 item”直接当成可验证证据。协议拆成两个明确通道：

| 通道 | 生产者 | 能否产生 Fact | 用途 |
|---|---|---|---|
| **script-declared evidence** | 模型脚本 | **不能** | 探索、索引、可读的中间证据 |
| **kernel probes** | kernel 执行 | **能** | 可验证的 HTTP/命令证据 |

Phase 1 只做 script-declared evidence，且**不铸造 Fact**。  
Phase 2 才做 kernel probes，恢复 hazard/negative 语义。

---

## 2. 不可协商的修订

### 2.1 provenance 是字段，不是暗示

每个 item 必须有：

```ts
provenance: "script-declared" | "kernel"
```

- `script-declared`：脚本自报；只能用于 artifact/read/探索；不能进入 Fact。
- `kernel`：kernel 亲自执行/分类；可以有 `semanticFailure`、`negative`，可以支撑 Fact。

`claim.refs` 指向 `script-declared` item 时：

- 只允许 `claimType: "interpreted"`；
- **不得创建 Fact**；
- 可以进入 packet 作为 open/interpreted claim；
- 不能作为 `flag` 的 evidenceRefs。

这是 F1 的直接修复。

### 2.2 item 读取必须有受控路径

新增 internal op（不是第 5 个动词）：

```text
case.evidence
  input: { ref: "cmd-0001.0003", offset?: number, limit?: number }
  output: { text, encoding, bytes, span, truncated, injectionMarkers }
```

同时提供 extension tool `case_evidence`（内部 API 的薄包装）。

- 返回内容必须包 `<UNTRUSTED_DATA>`（或等价结构）；
- 默认 `limit=2048` 字节，最大 `16384`；
- 支持 item ref 和 parent ref；
- 不接受任意 path，只接受 `cmd-NNNN[.NNNN]`；
- packet 里额外放 **最多 3 个 item 的 256B excerpt**，避免模型必须立刻读。

这解决 F2/F5 的读取和边界问题，也让“读 item 37”有可治理的路径。

### 2.3 label 不得出现在 trusted packet 区域

- `label` 仅用于 UI/用户，不进入 packet 的 trusted section；
- 若显示，必须在 `<UNTRUSTED_DATA>` 内；
- 仅允许 `[\x20-\x7E]`，长度 ≤64；
- 不渲染 `status`（脚本自报状态一律不显示为事实）。

### 2.4 quote 必须绑定 ref

新增：

```ts
allowedShapedRefs(ref):
  parent -> { parent.stdout.shapedRef, parent.stderr.shapedRef }
  item   -> { item.stdout.shapedRef, item.stderr.shapedRef }
```

`claim.submit` 必须验证：

```text
for each quote:
  quote.shapedRef ∈ allowedShapedRefs(claim.refs)
```

并验证 ref 语法：

```text
^cmd-\d{4}(\.\d{4})?$
```

这修复 F5，阻止“quote 引用 item-2、refs 却写 item-1”或直接引用 `.ctf/flag.txt`。

### 2.5 item 失败必须进入可终止路径

对 `kernel` item：

- 每个 item 都有 kernel-owned `exit`/`processFailure`/`semanticFailure`；
- `server-error` / `client-blocked` 等进入 item 汇总；
- 聚合结果进入 parent/负账本；
- 同一 parent 的 item 签名要能参与 route 阻断，否则负账本被绕过。

对 `script-declared` item：

- 不产生 `NegativeEntry`；
- 也不允许通过 item 失败“洗白”已 hard-block 的 route；
- script-declared item 只能作为探索材料。

### 2.6 truncation 是派生不变量

```ts
truncated =
  parent.timedOut ||
  parent.stdout.outputTruncated ||
  scannedBytes > MAX_SCANNED ||
  lineBytes > MAX_LINE ||
  itemBytes > MAX_ITEM_BYTES ||
  totalItemBytes > MAX_TOTAL_ITEM_BYTES ||
  (planned !== null && (parsed !== planned || endMissing)) ||
  protocolError !== null
```

不能出现“timeout 但 `truncated=false`”。

### 2.7 caps 要自洽

v1 的 64 × 256 KiB 与 8 MiB 总 cap 自相矛盾，且 claim 只有 16 refs/8 quotes。

v2：

```text
maxItems = 16              // 对齐 claim refs 上限
maxItemBytes = 256 KiB
maxTotalItemBytes = 4 MiB
maxLineBytes = 512 KiB
maxScannedBytes = 16 MiB   // 包含 noise / 未接受行
maxClaimRefs = 16
maxClaimQuotes = 8
```

14 条探测可以完整放进一个 run；超过 16 条必须拆 run 或由模型自行汇总。

### 2.8 parser 细节

- 去 UTF-8 BOM；
- `\r\n` 归一化为 `\n`；
- 最后一行无 `\n` 也要解析；
- 空行/非 evidence 行进 noise，不中断；
- duplicate `begin`、item after `end`、second `end` 明确为 `protocolError`；
- `Bail out!` 作为显式 abort 记录，不和静默截断混淆；
- 不提供 `evidence:"auto" | "off"` 这类模型旋钮；只识别精确的 `pi4ctf:"evidence/1"` 行，noise 原样保留在 parent raw。

### 2.9 span 单位

现有 `checkQuote` 使用 JS `String#slice`，所以 span 是 **UTF-16 code units**。  
v2 明确写死这一点；Python 生成器若用 code point 偏移必须自行转换。

### 2.10 二进制

- binary item 支持 raw/sha256/provenance；
- shaped 是现有 hex 预览（前 4096B），**不能**用作完整 quote；
- binary item 不允许 `output.contains` 类 quote，除非显式允许 hex 区间；
- flag provenance 仍扫描 raw artifacts。

---

## 3. v2 的两个通道

### 3.1 script-declared evidence（Phase 1）

一次 `run` 一个脚本，脚本输出 NDJSON：

```json
{"pi4ctf":"evidence/1","type":"begin","count":2}
{"pi4ctf":"evidence/1","type":"item","label":"baseline","kind":"http","stdout":"HTTP/1.1 200 OK\n"}
{"pi4ctf":"evidence/1","type":"item","label":"payload","kind":"http","stdout":"HTTP/1.1 500\n"}
{"pi4ctf":"evidence/1","type":"end","count":2}
```

性质：

- `provenance:"script-declared"`；
- 可以读、可以引用 artifact、可以形成 interpreted claim；
- **不能**铸造 Fact；
- 不进入 negative ledger；
- item `kind/status` 都不可信，仅 `declaredKind`。

### 3.2 kernel probes（Phase 2）

如果需要一个**可验证**的 14 项矩阵，使用 kernel 执行，而不是脚本自报：

```json
{
  "op": "run",
  "input": {
    "probes": [
      {"label": "baseline", "argv": ["curl", "-sS", "http://.../"]},
      {"label": "payload", "argv": ["curl", "-sS", "http://.../?x=1"]}
    ]
  }
}
```

规则：

- kernel 顺序执行 probes，每个 probe 一个进程；
- 每个 probe 有 kernel-owned `exit/processFailure/stdout`；
- item `provenance:"kernel"`；
- kernel 可以 `classify` item body（HTTP status/hazard）；
- 失败进入 negative ledger；
- 一次 run 消耗 **1 个执行槽**，但 `maxProbes=16`；
- 这是对“30 次预算 vs 14 项证据”的真正解法；script-declared 只是补充文本。

> 由于 4 动词约束，`probes` 是 `run` 的输入扩展，不是 `run.batch` 新动词。  
> 若实现成本过高，Phase 2 可以延后；但**不能**用 script-declared item 伪造 Fact。

---

## 4. 数据模型

```ts
interface ProcessOutcome {
  // existing fields...
  items?: {
    protocol: "evidence/1";
    provenance: "script-declared" | "kernel";
    planned: number | null;
    parsed: number;
    emitted: number;
    truncated: boolean;
    protocolError: string | null;
    ids: string[];
  };
}

interface EvidenceItem {
  id: string;                  // cmd-0001.0003 (one canonical spelling)
  parentOutcomeId: string;
  index: number;
  label: string;               // ASCII display only
  provenance: "script-declared" | "kernel";
  declaredKind: string;        // untrusted
  kind: "http" | "binary" | "text" | "unknown"; // kernel-derived
  status: string | number | boolean | null;     // display only; never Fact
  encoding: "utf8" | "base64";
  stdout: StreamInfo;
  stderr: StreamInfo;
  meta: Record<string, string | number | boolean | null>;
  semanticFailure: string | null; // kernel only
  truncated: boolean;
}
```

约束：

- item id 从 parent id 派生；**绝不调用 `allocId('command')`**；
- item 文件：`items/cmd-0001.0003.json`；
- artifact：`artifacts/cmd-0001.item-0003.stdout.raw.log`（artifact 名可与 id 拼写不同，但 resolver 只接受 canonical id）；
- `meta` 只允许 scalar / scalar[]，禁止 `__proto__`/`constructor`/`prototype`；
- `status` 不进入 packet 的 trusted 区域。

---

## 5. claim / Fact / packet

### 5.1 claim

- `script-declared` item：只允许 `interpreted`，不产生 Fact；
- `kernel` item：可产生 Fact；
- `claim.refs` 允许 parent/item 混用，但必须通过 ref grammar；
- quote 必须绑定 ref 的 artifact；
- `Fact` 增加 `artifactHashes`（至少包含 quote 引用的 raw/shaped sha256），否则 Fact 无法回验。

### 5.2 packet

- parent outcome 只显示 summary；
- item excerpt 最多 3 条 × 256B，且都在 `<UNTRUSTED_DATA>` 内；
- 不显示 label/status 在 trusted 区；
- budget 行显示 `items: 3`；
- `recentOutcomes` 以 parent 为单位，item refs 用于 open claim 的显示，但不把 64 个 item 当 64 个 outcome。

### 5.3 differential

`http.length_delta` 只对 **kernel items** 启用：

- 两个 item 必须同 parent、同 kernel-derived kind、同 target；
- length = item raw body bytes，不是 NDJSON envelope；
- `requireSameTemplate` 对 items 改为 `same parent + same target + same kind`。

script-declared item 的 differential 只能作为 `interpreted`，不能产 Fact。

---

## 6. 评审问题 → v2 处理

| 评审项 | v2 处理 |
|---|---|
| F1 script item 伪造 Fact | provenance + interpreted-only |
| F2 无读取路径 | `case.evidence` + 3×256B packet excerpts |
| F3 label 注入 | ASCII、wrapped、不显示 status |
| F4 负账本/hazard 绕过 | kernel probes 保持 classification/negative；script items 不产 Fact |
| F5 quote/ref 不绑定 | `allowedShapedRefs` + ref grammar |
| S1 differential 不可用 | kernel items + raw body bytes |
| S2 无 Observation | kernel item 有自己的 classification；script item 无 Fact |
| S3 recent exemption | item refs 映射到 parent；open claim 保留 |
| S4 truncation 错 | 派生不变量 + timeout |
| S5 item 烧预算 | item id 从 parent 派生，不调 allocId |
| S6 meta 污染 | scalar-only、键黑名单 |
| S7 binary quote | 明确只做 provenance |
| S8 span 单位 | UTF-16 code units |
| S9 cap 矛盾 | 16 items / 256KiB / 4MiB / 512KiB line / 16MiB scanned |
| S10 parser 矛盾 | 统一 protocolError/truncated；BOM/CRLF/EOF/Bail out |
| S11 auto 旋钮 | 删除；精确前缀 |
| S12 packet 预算 | 3 excerpts + 独立 items budget |
| S13 shaping 不绑定 | item raw/shaped + `artifactHashes`；binary no quote |

---

## 7. 第一实现 slice

按评审建议，**不要**先做 claim/predicate。先做：

1. `src/kernel/evidence/items.ts`：
   - parser、BOM/CRLF/EOF、scanned bytes、derived truncated、Bail out；
2. item artifacts + `ProcessOutcome.items`（planned/parsed/emitted/truncated/ids）；
3. `provenance:"script-declared"`；
4. `case.evidence` 读取（bounded + wrapped）；
5. `allowedShapedRefs` + ref grammar；
6. `run` 响应只带 3 个 item excerpt + counts；
7. 测试：
   - parser edge cases；
   - quote/ref mismatch；
   - label injection；
   - budget unchanged；
   - legacy outcome/claim。

这一 slice 完成后，模型可以**看**和**引用** item，但脚本 item 不能伪造 Fact。  
kernel probes / Fact / differential 是 Phase 2。

---

## 8. 验收

- 14 item script：1 个执行槽，16 cap 内；
- 每个 item 可通过 `case.evidence` 读取且 wrapped；
- script item 不能产生 Fact；
- quote 的 shapedRef 必须属于 ref；
- label 不能伪造 packet section；
- truncated 在 timeout/line cap/count mismatch 时为 true；
- parent raw 完整；
- 老 outcome/claim 继续工作；
- 16 item / 4 MiB / 512 KiB line 边界有 fixture；
- `case.restart` 不重编号 item；
- `flag` provenance 能扫 item raw；
- binary quote 被明确拒绝。

---

## 9. 参考

v1 的引用保留，但修正：

- TAP 14：plan 的截断语义；另外应借鉴 `Bail out!`，不要只借 plan。
- SARIF：run/results/artifacts 分离；同时借鉴 `invocations.executionSuccessful`/notifications 表达 partial run。
- OpenTelemetry：span parent/child 与 attributes；不要用 arbitrary scalar status 冒充 OTel status enum。
- PROV-DM：item 与 parent outcome 是同一 activity 生成的两个 entity（siblings），不是 entity-parent 父子；应记录 `wasGeneratedBy` 到 activity。
- RFC 7464：它使用 RS 正是为了避免 newline 歧义；本协议使用 NDJSON 的理由应是“producer 是 `JSON.stringify`，newline 已转义”，而不是引用 RFC 7464 来支持换行分帧。


---

## 10. 实现状态

已实现：

- `src/kernel/evidence/items.ts`：`evidence/1` parser，BOM/CRLF/EOF、scanned/line/item/total caps、planned/parsed/emitted、truncated、Bail out、label sanitization、base64；
- `ProcessOutcome.items` + `items/cmd-NNNN.NNNN.json` + item raw/shaped/meta artifacts；
- `case.evidence` internal op + `case_evidence` tool；
- `allowedShapedRefs` + ref grammar；
- script-declared item 只能 `interpreted`，不产 Fact；
- `run` response 带 item summaries；packet 带 item count/truncation summary + 最多 3 条 256B wrapped excerpt；
- tests in `src/test/items.test.ts`。

Phase 2 已实现：

- kernel-executed `probes`（item 独立 observation 文件）（1–16，一次 run 一个执行槽）；
- kernel item classification / negative ledger；
- item differential over raw body bytes；
- `Fact.artifactHashes`。
