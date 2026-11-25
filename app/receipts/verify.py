"""单订单凭证的离线核验逻辑。

本模块只依赖 Python 标准库与 ``app.receipts.batch`` 的纯函数，
``tools/verify_receipt.py`` 会把同一套逻辑暴露给外部复核方在离线机器上运行。
核验需要两样输入：

1. 凭证 JSON 文件（自带订单数据、Merkle 证明、批根、签名、key_id）；
2. 复核方事先保存的信任锚：工作台公钥（32 字节原始公钥，或
   ``GET /api/verify-key`` 返回的 JSON）。公钥不内嵌在凭证里，
   所以把凭证里的 key_id、批根、签名整套验真材料一起换掉也骗不过核验。
"""
import hashlib
import json

from app.receipts.batch import (
    RECEIPT_SCHEMA,
    canonical_bytes,
    leaf_hash,
    root_from_proof,
    signing_message,
)
from app.security import ed25519


class ReceiptError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def load_receipt(raw) -> dict:
    if isinstance(raw, (bytes, str)):
        try:
            receipt = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReceiptError("RECEIPT_NOT_JSON", str(exc))
    else:
        receipt = raw
    required = {"schema", "run_id", "source_sha256", "review_revision", "key_id",
                "batch", "order", "merkle_proof", "signature"}
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        raise ReceiptError("RECEIPT_MALFORMED", "缺少凭证必备字段")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise ReceiptError("RECEIPT_SCHEMA_UNKNOWN", receipt.get("schema", ""))
    return receipt


def load_trust_anchor(raw) -> tuple[str, bytes]:
    """接受 /api/verify-key 的 JSON 或裸 32 字节公钥（hex/base64/raw）。"""
    if isinstance(raw, dict):
        if "key_id" not in raw or "public_key" not in raw:
            raise ReceiptError("TRUST_ANCHOR_MALFORMED")
        return raw["key_id"], _decode_key_bytes(raw["public_key"])
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        return load_trust_anchor(json.loads(raw))
    return None, _decode_key_bytes(raw)


def _decode_key_bytes(value) -> bytes:
    if isinstance(value, bytes) and len(value) == 32:
        return value
    if isinstance(value, str):
        try:
            if len(value) == 64:
                return bytes.fromhex(value)
            import base64
            decoded = base64.b64decode(value)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    raise ReceiptError("TRUST_ANCHOR_MALFORMED", "公钥必须是 32 字节 Ed25519 公钥")


def verify_receipt(receipt_raw, trust_anchor, expected_order_id=None,
                   expected_refund_cents=None) -> dict:
    """完整离线核验。成功返回核验摘要 dict，失败抛 :class:`ReceiptError`。"""
    receipt = load_receipt(receipt_raw)
    anchor_key_id, public_key = load_trust_anchor(trust_anchor)

    # 1) key_id 必须与复核方保存的信任锚一致——防止连验真材料一起替换
    actual_key_id = hashlib.sha256(public_key).hexdigest()
    if receipt["key_id"] != actual_key_id:
        raise ReceiptError("KEY_ID_MISMATCH", "凭证 key_id 与信任锚公钥不匹配")
    if anchor_key_id and anchor_key_id != actual_key_id:
        raise ReceiptError("TRUST_ANCHOR_MISMATCH", "信任锚内部 key_id 与公钥不一致")

    # 2) 订单承诺重算叶哈希，再沿 Merkle 证明重算批根
    proof = receipt["merkle_proof"]
    if not isinstance(proof, dict) or "path" not in proof or "leaf_index" not in proof:
        raise ReceiptError("MERKLE_PROOF_INVALID", "证明缺少 path 或 leaf_index")
    if not isinstance(proof["path"], list) or not isinstance(proof["leaf_index"], int):
        raise ReceiptError("MERKLE_PROOF_INVALID", "证明字段类型错误")
    tree_size = int(receipt["batch"]["tree_size"])
    if tree_size <= 0 or proof["leaf_index"] < 0 or proof["leaf_index"] >= tree_size:
        raise ReceiptError("MERKLE_PROOF_INVALID", "叶序号超出树范围")
    # 证明深度必须与树规模匹配，防止用截断/加长的证明冒充
    # n 个叶子的层数：n=1 时为 0；n>1 时为 ceil(log2(n)) = (n-1).bit_length()
    expected_depth = 0 if tree_size == 1 else (tree_size - 1).bit_length()
    if len(proof["path"]) != expected_depth:
        raise ReceiptError("MERKLE_PROOF_INVALID", "证明深度与树规模不一致")
    try:
        leaf = leaf_hash(receipt["order"])
        rebuilt_root = root_from_proof(leaf, proof)
    except (KeyError, ValueError, TypeError) as exc:
        raise ReceiptError("MERKLE_PROOF_INVALID", str(exc))
    if rebuilt_root != receipt["batch"]["batch_root"]:
        raise ReceiptError("BATCH_ROOT_MISMATCH", "订单数据或 Merkle 证明被改动")
    if proof.get("root") and proof["root"] != rebuilt_root:
        raise ReceiptError("BATCH_ROOT_MISMATCH", "证明内嵌根与重算根不一致")

    # 3) 批根签名必须来自工作台私钥；签名消息把 run_id/来源/版本都绑进去
    batch_for_signing = {
        "run_id": receipt["run_id"],
        "batch_root": receipt["batch"]["batch_root"],
        "tree_size": receipt["batch"]["tree_size"],
        "source_sha256": receipt["source_sha256"],
        "review_revision": receipt["review_revision"],
    }
    try:
        signature = bytes.fromhex(receipt["signature"])
    except ValueError:
        raise ReceiptError("SIGNATURE_MALFORMED")
    if not ed25519.verify(public_key, signing_message(batch_for_signing), signature):
        raise ReceiptError("SIGNATURE_INVALID", "批根签名核验失败")

    # 4) 调用方声明的期望订单/金额必须与凭证一致（争议核对用）
    if expected_order_id is not None and receipt["order"]["order_id"] != expected_order_id:
        raise ReceiptError("ORDER_MISMATCH",
                           f"凭证订单 {receipt['order']['order_id']} != 期望 {expected_order_id}")
    if expected_refund_cents is not None and \
            int(receipt["order"]["refund_cents"]) != int(expected_refund_cents):
        raise ReceiptError("REFUND_MISMATCH",
                           f"凭证退款 {receipt['order']['refund_cents']} 分 != 期望 {expected_refund_cents} 分")

    return {
        "verified": True,
        "run_id": receipt["run_id"],
        "order_id": receipt["order"]["order_id"],
        "refund_cents": receipt["order"]["refund_cents"],
        "payment_cents": receipt["order"]["payment_cents"],
        "verdict": receipt["order"]["verdict"],
        "batch_root": receipt["batch"]["batch_root"],
        "key_id": receipt["key_id"],
        "source_sha256": receipt["source_sha256"],
        "review_revision": receipt["review_revision"],
    }
