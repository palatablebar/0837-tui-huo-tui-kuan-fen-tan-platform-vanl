"""单订单凭证的签发服务。

凭证不是独立保存的新记录，而是从**已签发批次**的固定内容确定性派生：
同一批次同一订单，任何时候下载得到逐字节一致的凭证文件，
因此签发/下载重试都不会产生第二份凭证。
批次记录丢失时无法重建批根与证明，直接拒绝出具可验凭证。
"""
import json

from app.domain_errors import DomainIssue
from app.receipts.batch import build_receipt, build_tree, merkle_proof
from app.receipts.verify import verify_receipt
from app.security.keys import load_signing_key


def _orders_from_run(run: dict) -> list:
    orders = run.get("orders")
    if not isinstance(orders, list) or not orders:
        # 旧批次缺少订单级签发记录：无法核实该订单的签发金额
        raise DomainIssue("BATCH_RECORDS_MISSING", 409)
    return orders


def build_batch_manifest(run: dict, signing_key) -> dict:
    """对已签发批次构建 Merkle 批根并用本机私钥签名（纯内存，不落新表）。"""
    orders = _orders_from_run(run)
    tree = build_tree(orders)
    batch = {
        "run_id": run["run_id"],
        "batch_root": tree["root"],
        "tree_size": tree["size"],
        "source_sha256": run["source"]["sha256"],
        "review_revision": run["revision"],
    }
    from app.receipts.batch import signing_message
    signature = signing_key.sign(signing_message(batch))
    return {"tree": tree, "batch": batch, "signature": signature, "key_id": signing_key.key_id}


def issue_order_receipt(run: dict, order_id: str, signing_key=None) -> dict:
    if run is None:
        raise DomainIssue("RUN_NOT_FOUND", 404)
    if run["status"] != "APPROVED":
        raise DomainIssue("NOT_APPROVED", 409)
    orders = _orders_from_run(run)
    order = next((item for item in orders if item["order_id"] == order_id), None)
    if order is None:
        raise DomainIssue("ORDER_NOT_IN_BATCH", 404)
    key = signing_key or load_signing_key()
    manifest = build_batch_manifest(run, key)
    proof = merkle_proof(manifest["tree"], order_id)
    receipt = build_receipt(run["run_id"], manifest["batch"], order, proof,
                            manifest["key_id"], manifest["signature"])
    # 签发时自验一遍：能被信任锚核验通过的凭证才允许交付
    trust_anchor = {"key_id": key.key_id, "public_key": key.public.hex()}
    verify_receipt(json.dumps(receipt, ensure_ascii=False), trust_anchor,
                   expected_order_id=order_id, expected_refund_cents=order["refund_cents"])
    return receipt


def list_order_ids(run: dict) -> list:
    if run is None:
        raise DomainIssue("RUN_NOT_FOUND", 404)
    if run["status"] != "APPROVED":
        raise DomainIssue("NOT_APPROVED", 409)
    return [item["order_id"] for item in _orders_from_run(run)]
