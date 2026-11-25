# 字段定义

| 字段 | 类型 | 说明 |
|---|---|---|
| `order_id` | text | 业务字段 |
| `line_id` | text | 主键 |
| `line_amount` | money | 业务字段 |
| `discount_total` | money | 业务字段 |
| `return_qty` | int | 业务字段 |
| `qty` | int_positive | 业务字段 |
| `unit_refund` | money | 业务字段 |
| `freight` | money | 业务字段 |
| `payment` | money | 业务字段 |

空字符串、`-`、`NA`、`null` 和 `未提供` 按空值处理。金额字段在整理层转为整数分或整数最小单位；日期按 ISO 日期解析；带时间的字段按本地时间解析。标识字段保持为文本，前导零不会被去除。
