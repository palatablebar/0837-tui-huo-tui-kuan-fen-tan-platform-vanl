# 单订单凭证与离线核验

退款争议中，外部复核方可能在工作台离线、甚至工作台数据已丢失的情况下核验：
某订单在某已签发批次里的退款金额有没有被改过。本文件说明凭证结构、
信任模型与离线核验方法。

## 威胁模型与保证

- 复核方只信任一样东西：事先通过可信渠道保存的工作台 **Ed25519 公钥**
  （`GET /api/verify-key`，其指纹为 `key_id`）。
- 凭证文件本身完全不可信，里面的任何字段都可能被篡改，全部要重算核验。
- 凭证只包含**所选订单**的数据和 Merkle 兄弟哈希，不含其他订单的订单号、
  金额或可识别信息，下载单订单凭证不会泄露整批内容。
- 以下任一篡改都会导致核验失败：
  - 改订单号、改退款金额、改行明细：订单叶哈希变化，Merkle 根对不上；
  - 改 Merkle 证明或批根：重算根与签名根不一致，或签名核验失败；
  - 改签名：Ed25519 验签失败；
  - 连 `key_id`、批根、签名整套验真材料一起换成伪造密钥：与复核方保存的
    信任锚公钥指纹不匹配（`KEY_ID_MISMATCH`）。
- 签名消息绑定了 `run_id`、来源文件摘要 `source_sha256` 与复核版本号
  `review_revision`，凭证无法跨批次、跨来源套用。

## 凭证结构（`workbench-order-receipt/v1`）

```json
{
  "schema": "workbench-order-receipt/v1",
  "run_id": "批次ID",
  "source_sha256": "来源CSV摘要",
  "review_revision": 1,
  "key_id": "核验公钥的SHA-256指纹",
  "batch": { "batch_root": "Merkle批根", "tree_size": 4 },
  "order": {
    "order_id": "O1",
    "refund_cents": 4500,
    "payment_cents": 20000,
    "freight_refund_cents": 0,
    "verdict": "PASS",
    "reason": "BALANCED",
    "lines": [{"line_id": "O1L1", "refund_cents": 4500, "alloc_discount_cents": 1000}]
  },
  "merkle_proof": { "leaf_index": 0, "path": [{"side": "right", "hash": "..."}] },
  "signature": "批根声明的Ed25519签名(hex)"
}
```

金额一律使用整数分（最小货币单位），避免浮点边界争议。

## 离线核验步骤

1. 在可信网络环境一次性获取并保存信任锚：
   `curl -o verify-key.json /api/verify-key`，核对 `key_id` 后离线保管。
2. 争议时取得该订单的凭证 JSON 文件（工作台在线时从
   `GET /api/runs/{id}/receipts/{order_id}` 下载，或由对方提供）。
3. 在离线机器上运行（只用 Python 标准库，无需安装任何依赖）：

```bash
python tools/verify_receipt.py receipt-O1.json --key verify-key.json \
       --order O1 --refund-cents 4500
```

退出码 `0` 表示核验通过并打印核验摘要；`1` 表示凭证无法通过核验
（输出 `code` 指明失败环节）；`2` 表示输入文件无法读取。

核验逻辑与工作台签发时的自验共用 `app/receipts/verify.py`，
`tools/verify_receipt.py` 只是它的命令行封装，可连同 `app/` 一起
拷贝到气隙环境，全程无网络访问。

## 数据保留边界

- 凭证由已签发批次的固定内容**确定性派生**，不单独落库：同一批次同一订单
  重复下载得到逐字节一致的文件，签发/下载重试不会产生第二份凭证。
- 若批次记录（含订单级承诺）已丢失，无法重建 Merkle 批根与包含性证明，
  接口返回 `BATCH_RECORDS_MISSING`，**拒绝出具可验凭证**，而不是给出
  无法验证的文件。
- 签名私钥保存在工作台本地（`WORKBENCH_SIGNING_KEY`，默认数据卷内，
  权限 600，不进仓库）；公钥可以公开，私钥无法从公钥或凭证反推。
