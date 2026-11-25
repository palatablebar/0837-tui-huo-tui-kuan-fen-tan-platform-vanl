"""已签批次的单订单凭证。

设计要点
--------
1. 批次签发时对全部订单的承诺（order_id + 退款金额等）建 Merkle 树，
   批根 ``batch_root`` 由工作台 Ed25519 私钥签名。
2. 单订单凭证只携带该订单自身的数据与 Merkle 证明（兄弟哈希），
   不含其他订单的任何金额或标识，整批凭证不会随单订单文件泄露。
3. 离线核验只依赖：凭证 JSON + 复核方事先保存的工作台公钥（信任锚）。
   换订单、改金额、改证明、换批根、换签名、换 key_id 任一处被改，
   哈希链或签名核验都会失败。
4. 凭证内容全部来自已签发批次的固定记录，构造是确定性的；
   重复下载得到逐字节一致的文件，签发重试不会新增凭证。
"""
import hashlib
import json

LEAF_PREFIX = b"\x00workbench-receipt-leaf\x00"
NODE_PREFIX = b"\x01workbench-receipt-node\x01"
SIGN_PREFIX = b"workbench-batch-root/v1\x00"
RECEIPT_SCHEMA = "workbench-order-receipt/v1"


def canonical_bytes(value) -> bytes:
    """所有哈希共用的规范编码：sort_keys 固定键序、无多余空白。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def order_commitment(order: dict) -> dict:
    """订单进入批根的承诺内容。金额以整数分（最小单位）固化。"""
    return {
        "order_id": order["order_id"],
        "refund_cents": int(order["refund_cents"]),
        "payment_cents": int(order["payment_cents"]),
        "freight_refund_cents": int(order["freight_refund_cents"]),
        "verdict": order["verdict"],
        "reason": order["reason"],
        "lines": [
            {
                "line_id": line["line_id"],
                "refund_cents": int(line["refund_cents"]),
                "alloc_discount_cents": int(line["alloc_discount_cents"]),
            }
            for line in order.get("lines", [])
        ],
    }


def leaf_hash(order: dict) -> str:
    return sha256(LEAF_PREFIX + canonical_bytes(order_commitment(order)))


def _node_hash(left: str, right: str) -> str:
    return sha256(NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


def build_tree(orders: list) -> dict:
    """按 order_id 排序后构建 Merkle 树。

    返回 leaves（与排序后订单一一对应的叶哈希）、root 与 size。
    空批次没有可承诺内容，直接报错而不是给出可被误用的固定根。
    """
    if not orders:
        raise ValueError("EMPTY_BATCH")
    order_ids = [str(item["order_id"]) for item in orders]
    if len(set(order_ids)) != len(order_ids):
        # 计算层按订单聚合，正常不会出现重复；防御性拦截避免生成有歧义的树与证明
        raise ValueError("DUPLICATE_ORDER_ID")
    ordered = sorted(orders, key=lambda item: str(item["order_id"]))
    leaves = [leaf_hash(order) for order in ordered]
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]  # 奇数节点复制自身
            nxt.append(_node_hash(left, right))
        level = nxt
    return {"order_ids": [item["order_id"] for item in ordered], "leaves": leaves,
            "root": level[0], "size": len(leaves)}


def merkle_proof(tree: dict, order_id: str) -> dict:
    """生成单订单的包含性证明，只含兄弟哈希与方向，不含任何其他订单内容。"""
    leaves = list(tree["leaves"])
    try:
        index = tree["order_ids"].index(order_id)
    except ValueError:
        raise KeyError(order_id)
    path = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if idx % 2 == 0:
            sibling = level[idx + 1] if idx + 1 < len(level) else level[idx]
            path.append({"side": "right", "hash": sibling})
        else:
            path.append({"side": "left", "hash": level[idx - 1]})
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_node_hash(left, right))
        level = nxt
        idx //= 2
    return {"leaf_index": index, "path": path, "root": level[0]}


def root_from_proof(leaf: str, proof: dict) -> str:
    """仅凭叶哈希与证明重算批根——离线复核方走的就是这条路。"""
    current = leaf
    for step in proof["path"]:
        sibling = step["hash"]
        if step["side"] == "left":
            current = _node_hash(sibling, current)
        elif step["side"] == "right":
            current = _node_hash(current, sibling)
        else:
            raise ValueError("BAD_PROOF_SIDE")
    return current


def signing_message(batch: dict) -> bytes:
    """被私钥签名的批根声明。把批次数值一并纳入签名，防止套用到别的批次。"""
    payload = {
        "schema": "workbench-batch-root/v1",
        "run_id": batch["run_id"],
        "batch_root": batch["batch_root"],
        "tree_size": int(batch["tree_size"]),
        "source_sha256": batch["source_sha256"],
        "review_revision": int(batch["review_revision"]),
    }
    return SIGN_PREFIX + canonical_bytes(payload)


def build_receipt(run_id: str, batch: dict, order: dict, proof: dict, key_id: str, signature: bytes) -> dict:
    """组装单订单凭证。全部字段可被离线核验，不含任何其他订单数据。"""
    return {
        "schema": RECEIPT_SCHEMA,
        "run_id": run_id,
        "source_sha256": batch["source_sha256"],
        "review_revision": int(batch["review_revision"]),
        "key_id": key_id,
        "batch": {
            "batch_root": batch["batch_root"],
            "tree_size": int(batch["tree_size"]),
        },
        "order": order_commitment(order),
        "merkle_proof": proof,
        "signature": signature.hex(),
    }
