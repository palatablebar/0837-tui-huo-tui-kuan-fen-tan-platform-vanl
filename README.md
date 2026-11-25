# 退货退款分摊台

电商财务结算员处理退款分摊与尾差守恒的本地工作台。样例、规则和复核记录都在项目内，不依赖外部服务。

## 启动

```bash
docker compose up --build
```

打开 `http://127.0.0.1:${PORT:-18520}`。默认端口见 `docker-compose.yml`。

## 验证

```bash
docker compose exec -T app pytest -q
docker compose config --quiet
```

## 操作

1. 在左侧选阶段，查看采信、整理、计算、判定和对账结果。
2. 选择 `dirty` 样例观察坏行和隔离原因。
3. 换 `clean` 样例执行批次，填写复核意见后签发。
4. 下载证据 JSON，核对来源摘要、指标和签发版本。
5. 在「单订单凭证」区选择订单下载离线可验凭证；外部复核方用核验公钥通过
   `python tools/verify_receipt.py 凭证.json --key verify-key.json` 离线验真。

业务规则见 `docs/BUSINESS-RULES.md`，字段定义见 `docs/DATA-DICTIONARY.md`，
单订单凭证的结构、威胁模型与离线核验见 `docs/RECEIPTS.md`。
