# 历史设计归档

> **不作为施工依据。** 当前唯一施工基线是 [`../design.md`](../design.md)。

这些文档保留了 pi4ctf 从 v1 到 v4 的推演过程，便于追溯“为什么最后是现在这套”。

| 文档 | 版本 | 说明 |
|---|---|---|
| [`final-design.md`](final-design.md) | v1 | 早期完整设计；3 工具、证据循环 |
| [`design-v2.md`](design-v2.md) | v2 | 完整研究与辩论细节 |
| [`design-v2-core.md`](design-v2-core.md) | v2-core | less-is-more 审计后的 4/5/4 机制层 |
| [`design-v3.md`](design-v3.md) | v3 | 内核冻结：4 动词 / 5 机制 / 4 记录 |
| [`design-v4.md`](design-v4.md) | v4 | 能力层：模型、sandbox、卡/case、race |

## 关系

```text
final-design (v1)
  → design-v2
  → design-v2-core
  → design-v3（内核冻结）
  → design-v4（能力层）
  → ../design.md（统一）
```

## 链接说明

归档文档里的相对链接已尽量指向当前文档。历史调研在仓库根目录的 [`../../archive/research/`](../../archive/research/)。
