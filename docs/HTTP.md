# 接口

- `GET /`：工作台。
- `GET /api/catalog`：阶段、字段和样例。
- `POST /api/stages/{stage}`：按阶段返回处理结果。
- `POST /api/runs`：执行完整批次并保存草稿。
- `GET /api/runs/{id}`：读取批次。
- `POST /api/runs/{id}/review`：签发或暂缓，提交 `decision`、`comment`、`expected_revision`。
- `GET /api/runs/{id}/evidence`：下载已签发证据（整批）。
- `GET /api/verify-key`：下载 Ed25519 核验公钥与 `key_id`（复核方的离线信任锚）。
- `GET /api/runs/{id}/orders`：已签发批次的订单号清单（仅订单号，不含金额）。
- `GET /api/runs/{id}/receipts/{order_id}`：下载该批次内单个订单的离线可验凭证（JSON 附件）。
- `GET /api/examples/{profile}`：下载样例。
- `GET /healthz`：健康检查。

### 单订单凭证的状态码

| 状态码 | code | 含义 |
|---|---|---|
| 409 | `NOT_APPROVED` | 批次尚未签发，不出具凭证 |
| 404 | `ORDER_NOT_IN_BATCH` | 订单不属于该批次 |
| 409 | `BATCH_RECORDS_MISSING` | 旧批次缺少订单级签发记录，无法核实签发金额，拒绝出具可验凭证 |
| 404 | `RUN_NOT_FOUND` | 批次记录已丢失 |
