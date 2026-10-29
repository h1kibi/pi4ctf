# pi4ctf 设计文档

> **唯一施工基线：[`design.md`](design.md)。**
>
> 其他文档要么是详细参考，要么是 later 子设计，要么是历史归档。冲突时以 `design.md` 为准。

---

## 当前文档

| 文档 | 状态 | 用途 |
|---|---|---|
| [`design.md`](design.md) | **施工基线** | 4 动词 / 5 机制 / 4 记录 + 能力层；先读这一份 |
| [`kernel-design.md`](kernel-design.md) | 详细参考 | `rt` 内核的进程、文件、证据、状态与扩展缝；先 TS 后 Rust |
| [`memory-design.md`](memory-design.md) | later | 文件型 verified lesson；当前里程碑不做 |
| [`tui-design.md`](tui-design.md) | later | adapter 层只读投影；当前里程碑不做 |
| [`adr/`](adr/) | 已接受决策 | 可复查的架构决策记录 |

## 阅读顺序

1. [`design.md`](design.md)：为什么做、做什么、先做什么；
2. [`kernel-design.md`](kernel-design.md)：内核怎么实现；
3. [`adr/`](adr/)：关键决策为什么这么定；
4. 需要时再看 later 子设计与历史归档。

## 历史归档

[`archive/`](archive/) 保存 v1–v4 设计，只用于追溯，不作为施工依据：

- [`archive/final-design.md`](archive/final-design.md)：v1；
- [`archive/design-v2.md`](archive/design-v2.md)：v2 完整研究；
- [`archive/design-v2-core.md`](archive/design-v2-core.md)：v2 机制收紧；
- [`archive/design-v3.md`](archive/design-v3.md)：v3 内核；
- [`archive/design-v4.md`](archive/design-v4.md)：v4 能力层。

## 文档纪律

- 不再新增 `design-vN.md`；设计变更直接改 `design.md`，历史进 `archive/`。
- 新子设计必须有明确状态：`active` / `later` / `archived`。
- 任何“施工基线”只能有一份；其他文档必须引用它，不能并列。
