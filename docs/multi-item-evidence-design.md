# pi4ctf 多 item evidence 协议设计

> 状态：**v1 提案，已被 `multi-item-evidence-design-v2.md` 修订取代**。  
> 目标：让一次 `run` 产生多个可独立引用的 evidence item，同时不破坏 4 动词、4 记录、预算和不可信边界。

## 1. 结论

采用：

```text
Parent ProcessOutcome
  └─ EvidenceItem[]  (evidence/1 NDJSON envelope)
```

- 一次 `run` 仍然只消耗 **1 个执行预算**；
- 一次 `run` 可以产出 **最多 64 个 item**；
- 每个 item 有自己的 raw/shaped artifact、sha256、label、kind、stdout/stderr；
- claim 可以引用 `cmd-0001.0003`，而不是只能引用整个 `cmd-0001`；
- item 是 `ProcessOutcome` 的**子证据**，不是新的顶层 ledger 记录；
- 不新增第五个动词。

---

## 2. 问题

当前模型：

```text
run -> one ProcessOutcome -> one stdout artifact
```

对多探测题不合适：

- 一个 Python 脚本做 14 条 HTTP 探测，结果是一大坨 stdout；
- claim 只能引用整段 artifact；
- 30 次预算迫使脚本变大，但证据粒度反而变粗；
- shaping 折叠重复行后，14 条探测可能只剩一条；
- 反复读 raw artifact 才能区分哪一条返回什么。

目标不是“让一次 run 跑更多命令”，而是：

> **一次进程执行可以携带多个可追溯的证据单元。**

---

## 3. 约束

1. **4 动词不扩张**：不使用 `run.batch` 作为新动词；扩展 `run` 的输入/输出。
2. **4 记录不扩张**：`EvidenceItem` 是 `ProcessOutcome` 的子结构，不是第五条信仰记录。
3. **预算不失控**：父进程 1 次；item 不按命令计费，但有硬上限。
4. **不可信默认**：item 的 label/kind/status/stdout 都是不可信数据；不能改变 scope/budget/flag。
5. **可恢复**：缺少 `end`、数量不匹配、过大、进程被 kill，都必须显式记录，不能静默丢失。
6. **向后兼容**：旧 outcome 没有 items；旧 claim refs 继续有效。
7. **证据可锚定**：每个 item 的 quote 必须能在 item 的 shaped artifact 上精确 `span`。
8. **shaping 不倒退**：item body 走现有 `shape@1`；父 stdout 仍保留原始 NDJSON。

---

## 4. 外部先例

### 4.1 TAP 14

TAP 14 的关键设计：

- 一个 TAP document 包含多个 **Test Point**；
- 有 `1..N` **Plan**，用于检测输出被截断或损坏；
- Test Point 后可以有 2 空格缩进的 YAML diagnostics；
- 支持 4 空格缩进的 **Subtest** 层次。

它证明了：

- “一次执行 -> 多条结果”是成熟的；
- **plan/count** 对截断检测很重要；
- 但 TAP 是行文本协议，不适合二进制和任意结构化 metadata。

### 4.2 SARIF 2.1.0

SARIF 以 `run` 为单位，包含 `results`、`artifacts`、`tool`、`invocations`；每条 result 有 rule、message、locations、fingerprints 等。

它证明了：

- 一个执行 run 可以有多个 result；
- artifact 和 result 应该分离引用；
- 每条结果需要自己的定位/指纹。

但 SARIF 面向静态分析，schema 很重，不适合作为 CTF 运行时协议。

### 4.3 OpenTelemetry

OpenTelemetry 的 trace 是 span 的 DAG；span 有 parent、attributes、events、status；批量操作可以用 **Links** 表示多个 initiating spans。

它证明了：

- 父/子关系适合“一个 run -> 多个 item”；
- item 可以有独立属性/状态；
- 批量产生的子项适合用链接而不是伪造父子关系。

但完整 trace/span/OTLP 对 pi4ctf 过重。

### 4.4 W3C PROV

PROV-DM 的核心概念：

- `Entity`：被生成/使用的东西；
- `Activity`：发生的过程；
- `Agent`：负责的实体；
- `Derivation` / `wasGeneratedBy` / `used`：来源关系。

它证明了：

- parent `ProcessOutcome` 应保留 `wasGeneratedBy` 语义；
- item 应记录来自哪个 parent activity；
- claim quote 应指向 entity（artifact/item），而不是只指向文本。

### 4.5 JSON Text Sequences / RFC 7464

RFC 7464 定义了用 record separator 分隔的 JSON text sequence，适合流式消息。  
我们不需要完整 RS 语义，但采用其“**一行一个可独立解析的 JSON 记录**”原则。

### 4.6 综合

| 来源 | 借用 | 不借用 |
|---|---|---|
| TAP 14 | plan/count、test point、truncation 检测 | 行语法、YAML diagnostics、缩进 subtest |
| SARIF | run/results/artifacts 分离、结果级定位 | 完整 schema、静态分析规则 |
| OpenTelemetry | parent/child、attributes、status、batch links | OTLP、采样、完整 trace 后端 |
| PROV | entity/activity/derivation 的来源语义 | RDF/OWL 全套 |
| RFC 7464 | 一行一个 JSON record | RS 字节帧、MIME 细节 |

---

## 5. 候选方案

### A. `run.batch`：一次调用多条命令

```json
{"op":"run.batch","items":[{"argv":[...]},{"argv":[...]}]}
```

问题：

- 预算按 batch 还是 item？按 batch 会绕过 30 次；按 item 又回到原问题；
- 每个 item 是独立进程，超时/并发/输出上限复杂；
- 不是“一个脚本多个证据”，而是“多个 run 合并 API”。

**不选。**

### B. TAP 文本流

脚本输出 TAP；kernel 解析 test points。

问题：

- TAP 不能自然承载二进制/大 body；
- YAML diagnostics 解析复杂；
- 与现有 `shape@1`/JSON 模型不一致。

**不选为主协议。**

### C. SARIF

脚本输出 SARIF results。

问题：

- schema 太重；
- 需要 rule/location 语义；
- CTF 探针不是静态分析 finding。

**不选。**

### D. NDJSON `evidence/1` envelope（选中）

一行一个 JSON record：

- 可流式解析；
- body 可 UTF-8 或 base64；
- plan/count 可检测截断；
- item 元数据与 body 分离；
- 与 JSON/TS 现有栈一致。

**选中。**

### 5.5 设计轮次

**Round 1：先定预算。**

候选 `run.batch` 会让“1 次 batch”与“N 个命令”产生歧义。  
如果 batch 计 1，预算可被无限绕过；如果按 item 计，又回到 30 次的问题。  
因此先确定：**item 不是命令，item 只能是同一父进程产出的证据切片**。

**Round 2：再定 wire。**

TAP/SARIF 都能表达多结果，但都不适合“二进制 + 自定义 metadata + 现有 JSON 栈”。  
选择 NDJSON envelope，保留 TAP 的 plan/count 思想和 SARIF 的 result/artifact 分离。

**Round 3：做对抗性审查。**

假设脚本故意：

- 输出 1000 个 item；
- 伪造 `status=200`；
- 在 label 中注入路径；
- 提前 `end` 或省略 `end`；
- 输出 100 MiB base64；
- 在 body 中写 “ignore previous instructions”。

对应限制：64 item、256 KiB/item、8 MiB 总、label 不参与路径、plan 不匹配标记截断、metadata untrusted、body 包 untrusted。

**Round 4：确认最小实现。**

首版只做：

```text
parent items
item artifacts
item refs
quote anchoring
packet summary
```

不把 `kind/status` 变成谓词，不做 item negative；避免把不可信 metadata 提升为 belief。

---

## 6. 选中的协议

### 6.1 名称

```text
evidence/1
```

parent `ProcessOutcome.items.protocol = "evidence/1"`。

### 6.2 wire format

每一行是一个 JSON object，UTF-8，最大 512 KiB/行。

begin（可选，但推荐）：

```json
{"pi4ctf":"evidence/1","type":"begin","count":3}
```

item：

```json
{
  "pi4ctf": "evidence/1",
  "type": "item",
  "label": "baseline",
  "kind": "http",
  "status": 200,
  "encoding": "utf8",
  "stdout": "HTTP/1.1 200 OK\n...",
  "stderr": "",
  "meta": {"target": "http://..."}
}
```

end（有 begin 时必需）：

```json
{"pi4ctf":"evidence/1","type":"end","count":3}
```

二进制 item：

```json
{
  "pi4ctf": "evidence/1",
  "type": "item",
  "label": "snapshot",
  "kind": "binary",
  "encoding": "base64",
  "stdout_b64": "iVBORw0KGgo..."
}
```

规则：

- `pi4ctf` 必须是 `evidence/1`；
- `type` ∈ `begin | item | end`；
- `begin.count` / `end.count` 可缺省；有 begin 时建议给出；
- `stdout` 与 `stdout_b64` 互斥；
- `stderr` / `stderr_b64` 同理；
- `label` ≤128 chars，仅显示；不参与路径/策略；
- `kind` ≤32 chars，仅提示；不参与权限/预算；
- `status` 可为任意 JSON 标量，但**不是内核事实**；
- `meta` 可省略，最大 4 KiB；
- 非 `evidence/1` 行是 **noise**，保留在父 raw artifact，不生成 item。

### 6.3 parser state machine

```text
start
  ├─ first evidence line = begin -> planned
  ├─ first evidence line = item  -> loose
  └─ no evidence line           -> off

planned:
  begin -> items* -> end
  missing end                -> truncated=true
  count mismatch             -> truncated=true

loose:
  items*
  no end required; truncated=false
```

限制：

- 重复 `begin`：协议错误，停止解析；
- `end` 后的 item：忽略并标记 `itemsProtocolError`；
- 超过 64 item：截断，`itemsTruncated=true`；
- 单 item stdout/stderr 超过 256 KiB：截断该 item，记录 `itemTruncated`；
- 总 item body 超过 8 MiB：停止，记录截断；
- 非法 base64：该 item 标记 `itemInvalid`，不写入 body artifact。

### 6.4 parent / item 数据模型

```ts
interface ProcessOutcome {
  // existing fields...
  items?: {
    protocol: "evidence/1";
    mode: "planned" | "loose";
    count: number;
    truncated: boolean;
    protocolError: string | null;
    ids: string[];
  };
}

interface EvidenceItem {
  id: string;                 // cmd-0001.0003
  parentOutcomeId: string;    // cmd-0001
  index: number;              // 1-based
  label: string;
  kind: string;
  status: unknown;
  encoding: "utf8" | "base64";
  stdout: StreamInfo;
  stderr: StreamInfo;
  meta: Record<string, unknown>;
  invalid: string | null;
  truncated: boolean;
}
```

约束：

- `EvidenceItem` 不是新的顶层 ledger 记录；它存在于 `items/` 子目录，并挂在 parent outcome 上；
- parent `stdout` 仍是原始 NDJSON（raw），`shape@1` 后的 parent 只用于摘要；
- item `stdout`/`stderr` 走现有 `shape@1`，各有 raw/shaped/meta；
- 父 `items.ids` 只存 ID，防 parent JSON 膨胀；
- item `id` 由 kernel 生成，脚本不能指定；
- 当 `items` 存在时，parent `classify` 只做容器级判断，不把 NDJSON 里的 HTTP 文本当成 parent 的 HTTP 语义；item 语义留给后续 item predicate。

### 6.5 artifact layout

```text
.ctf/
  outcomes/cmd-0001.json
  items/cmd-0001.0003.json
  artifacts/cmd-0001.stdout.raw.log
  artifacts/cmd-0001.stdout.shaped.log
  artifacts/cmd-0001.item-0003.stdout.raw.log
  artifacts/cmd-0001.item-0003.stdout.shaped.log
  artifacts/cmd-0001.item-0003.stdout.meta.json
```

- item artifact 名由 kernel 生成，不使用 label；
- item `StreamInfo` 格式与现有 `ProcessOutcome.stdout` 一致；
- binary item：raw 保存原字节；shaped 用现有 hex 预览；
- parent raw 保存完整 NDJSON，便于审计；
- item raw/shaped 是 claim 的首选引用。

### 6.6 refs

新增 item ref：

```text
cmd-0001          # parent outcome
cmd-0001.0003     # item 3
```

规则：

- `claim.refs` / `Fact.observationRefs` 可混用 parent/item；
- `Ledger.getEvidence(ref)` 解析 parent 或 item；
- item ref 的 parent 必须存在；
- `quote.shapedRef` 指向 item 的 shaped artifact；
- flag provenance 扫描所有 item raw/shaped；
- `recentOutcomes` 仍以 parent 为单位，不把 64 个 item 当成 64 个 outcome。

### 6.7 claim / predicate

- `claim.refs` 指向 item 时，quote 必须匹配该 item 的 shaped artifact；
- `ClaimVerifier.loadContext` 对 item ref 返回 parent + item；
- `process.exit-zero` 使用 parent exit/processFailure；
- `output.contains` 使用 item quote；
- `http.length_delta` 的首版不自动使用 item `status`（不可信）；后继可加 item body length 支持；
- `Fact.observationRefs` 保留原 ref 字符串（parent 或 item）；
- 同一 claim signature 仍由 refs 排序组成，item ref 参与签名。

### 6.8 packet

parent 摘要仍进入 recent outcomes：

```text
### cmd-0001 exec-local exit=0 412ms failure=null
items: 3 (planned, ok)
labels: baseline, payload, final
artifacts: ...
```

- 不把每个 item 的 body 放进 packet；
- item label/status 只做显示，不作为事实；
- budget 行增加 `items: 3`；
- open claims 引用 item 时显示 item ref。

### 6.9 预算

- `run` 1 次 = 1 个执行槽；
- item 不额外扣执行槽；
- `maxItems=64`；
- 单 item 256 KiB；总 item body 8 MiB；
- 超限时保留前 N 个并标记 `itemsTruncated`；
- 这样解决“脚本里 14 条探测”问题，同时不能靠 1000 个 item 绕过预算。

### 6.10 失败语义

- parent `processFailure` 不变（timeout/nonzero/no-output）；
- item 自身**不产生** negative entry；
- item 解析失败只影响 `items`，不改变 parent；
- `begin`/`end` 不匹配 -> `itemsTruncated`，但仍保留已解析 item；
- parent raw 始终保留，便于事后审计。

### 6.11 安全

- `label` / `kind` / `status` / `meta` 全部 untrusted；
- 不允许 item 设置 `allowedHosts`、budget、flag、scope；
- parser 只接受固定字段；未知字段忽略；
- base64 解码前检查长度；不接受嵌套/递归结构；
- item artifact 路径由 kernel 生成，不使用 label；
- item body 在 packet 中仍包 `<UNTRUSTED_DATA>`（或只显示摘要）；
- claim quote 是数据，不是指令。

---

## 7. 示例

### 7.1 脚本输出

```python
import json, sys

def item(label, stdout, stderr="", **meta):
    print(json.dumps({
        "pi4ctf": "evidence/1",
        "type": "item",
        "label": label,
        "kind": "http",
        "stdout": stdout,
        "stderr": stderr,
        "meta": meta,
    }, ensure_ascii=False))

print(json.dumps({"pi4ctf":"evidence/1","type":"begin","count":2}))
item("baseline", "HTTP/1.1 200 OK\nlen=20\n")
item("payload", "HTTP/1.1 500 Internal Server Error\n")
print(json.dumps({"pi4ctf":"evidence/1","type":"end","count":2}))
```

### 7.2 parent outcome

```json
{
  "id": "cmd-0001",
  "intentClass": "exec-local",
  "exit": 0,
  "items": {
    "protocol": "evidence/1",
    "mode": "planned",
    "count": 2,
    "truncated": false,
    "protocolError": null,
    "ids": ["cmd-0001.0001", "cmd-0001.0002"]
  }
}
```

### 7.3 claim

```json
{
  "claimType": "differential",
  "refs": ["cmd-0001.0001", "cmd-0001.0002"],
  "quotes": [
    {
      "shapedRef": "artifacts/cmd-0001.item-0001.stdout.shaped.log",
      "span": {"start": 0, "end": 20},
      "text": "HTTP/1.1 200 OK\nlen=20\n"
    }
  ]
}
```

---

## 8. 施工计划

### Phase 0：协议冻结

- 写 JSON Schema / TypeScript 类型；
- 固化 `evidence/1` 示例和 fixture；
- 确认 item/budget/truncation 语义；
- 不写实现。

### Phase 1：parser + artifacts

- `src/kernel/evidence/items.ts`；
- 解析 NDJSON、begin/end、count、截断；
- 写 item raw/shaped/meta；
- parent `items` 摘要；
- `run` 支持 `evidence: "auto" | "off"`；
- 测试：2/64 item、binary、truncated、bad base64、noise。

### Phase 2：refs + claim

- `Ledger.getEvidence(ref)`；
- `ClaimVerifier` 支持 item ref；
- claim quote 在 item shaped artifact 上校验；
- `Fact.observationRefs` 接受 item；
- packet 显示 item 摘要；
- 测试：item quote accepted/rejected、parent/item 混用。

### Phase 3：predicate + flag

- `output.contains` item；
- `process.exit-zero` 继承 parent；
- `http.length_delta` 可选 item body；
- flag provenance 扫描 item artifacts；
- 测试：item-only evidence 的完整 claim -> flag。

### Phase 4：模型层

- `run` tool 增加 `evidence` 参数说明；
- skill 增加 `evidence/1` 示例；
- docs / changelog；
- 可选：`rt` 增加 `--evidence` 校验。

---

## 9. 验收

- 一次脚本产 14 items：parent 1 个预算，14 个 item artifact；
- 每个 item quote 可精确锚定；
- claim 可只引用 item；
- `begin/count/end` 不匹配 -> `itemsTruncated`；
- 65th item 被截断，parent 保留；
- binary PNG item raw 字节完整，sha256 正确；
- 旧 outcome / 旧 claim 不破坏；
- item 的 label/status 不能改变 scope/budget/flag；
- 30 次预算不可被 item 绕过（item 不扣预算但有硬上限）。

---

## 10. 未决问题

1. `begin/end` 是否强制？
   - 建议：推荐但非强制；有 begin 才做 count 校验。
2. 单 item 上限 256 KiB 是否足够？
   - 需要看 PNG/HTTP body；可后续配置。
3. `kind` 是否应由 kernel 定义枚举？
   - 首版允许任意短字符串，仅提示；避免把不可信数据变成策略。
4. `http.length_delta` 是否允许 item body？
   - 首版先做 item quote + `output.contains`；差分后续。
5. 是否给 item 独立 negative entry？
   - 不；item 是 parent 的细节，negative 仍作用于 parent route。
6. item 是否进入 `recentOutcomes`？
   - 只进 parent 摘要，避免 64 个 item 淹没 packet。

---

## 11. 参考

- TAP 14 specification: <https://testanything.org/tap-version-14-specification.html>  
  - Plan / Test Point / Subtest / truncation 语义。
- SARIF 2.1.0 OASIS Standard: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html>  
  - run / results / artifacts / result locations。
- OpenTelemetry Overview: <https://opentelemetry.io/docs/specs/otel/overview/>  
  - trace/span、parent/child、attributes、events、batch links。
- W3C PROV-DM: <https://www.w3.org/TR/prov-dm/>  
  - entity / activity / agent / derivation。
- RFC 7464 JSON Text Sequences: <https://datatracker.ietf.org/doc/html/rfc7464>  
  - 一行一个 JSON record 的流式记录原则。
