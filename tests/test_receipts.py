import copy
import json

import pytest

from app.receipts.batch import (
    build_receipt,
    build_tree,
    leaf_hash,
    merkle_proof,
    root_from_proof,
    signing_message,
)
from app.receipts.verify import ReceiptError, verify_receipt
from app.security.keys import SigningKey
from app.security.ed25519 import generate_keypair


def make_order(order_id, refund, payment=10000, freight=0, verdict="PASS", lines=None):
    return {
        "order_id": order_id,
        "refund_cents": refund,
        "payment_cents": payment,
        "freight_refund_cents": freight,
        "verdict": verdict,
        "reason": "BALANCED",
        "lines": lines or [{"line_id": order_id + "L1", "refund_cents": refund,
                            "alloc_discount_cents": 0}],
    }


def make_run(orders, run_id="runA", status="APPROVED", revision=1, source="s" * 64):
    return {"run_id": run_id, "status": status, "revision": revision,
            "source": {"sha256": source}, "orders": orders}


def make_batch(run, key):
    tree = build_tree(run["orders"])
    batch = {"run_id": run["run_id"], "batch_root": tree["root"], "tree_size": tree["size"],
             "source_sha256": run["source"]["sha256"], "review_revision": run["revision"]}
    return tree, batch, key.sign(signing_message(batch))


def issue(run, order_id, key):
    tree, batch, signature = make_batch(run, key)
    proof = merkle_proof(tree, order_id)
    return build_receipt(run["run_id"], batch, next(o for o in run["orders"] if o["order_id"] == order_id),
                         proof, key.key_id, signature)


@pytest.fixture
def key():
    return SigningKey(generate_keypair()[0])


@pytest.fixture
def run(key):
    orders = [make_order("O1", 4500), make_order("O2", 8000, payment=10000, freight=800),
              make_order("O3", 900), make_order("O4", 1), make_order("O5", 687)]
    return make_run(orders)


def anchor(key):
    return {"key_id": key.key_id, "public_key": key.public.hex()}


# ---------- Merkle 树基本性质 ----------

def test_tree_root_changes_when_any_amount_changes(run):
    root1 = build_tree(run["orders"])["root"]
    changed = copy.deepcopy(run["orders"])
    changed[0]["refund_cents"] += 1
    assert build_tree(changed)["root"] != root1


def test_tree_root_changes_when_order_id_changes(run):
    root1 = build_tree(run["orders"])["root"]
    changed = copy.deepcopy(run["orders"])
    changed[1]["order_id"] = "O2X"
    assert build_tree(changed)["root"] != root1


def test_proof_rebuilds_root_for_every_order(run):
    tree = build_tree(run["orders"])
    for order in run["orders"]:
        proof = merkle_proof(tree, order["order_id"])
        assert root_from_proof(leaf_hash(order), proof) == tree["root"]


def test_proof_contains_no_other_order_data(run):
    tree = build_tree(run["orders"])
    proof = merkle_proof(tree, "O1")
    blob = json.dumps(proof)
    for other in ("O2", "O3", "O4", "O5"):
        assert other not in blob
    assert all(len(step["hash"]) == 64 for step in proof["path"])


def test_tree_is_order_independent(run):
    tree1 = build_tree(run["orders"])
    tree2 = build_tree(list(reversed(run["orders"])))
    assert tree1["root"] == tree2["root"]
    assert tree1["order_ids"] == tree2["order_ids"]


def test_single_order_tree(run, key):
    solo = make_run([make_order("SOLO", 1234)])
    receipt = issue(solo, "SOLO", key)
    assert verify_receipt(json.dumps(receipt), anchor(key))["verified"] is True
    assert receipt["merkle_proof"]["path"] == []


def test_empty_batch_is_rejected():
    with pytest.raises(ValueError):
        build_tree([])


# ---------- 完整核验通过路径 ----------

def test_valid_receipt_verifies(run, key):
    receipt = issue(run, "O2", key)
    result = verify_receipt(json.dumps(receipt), anchor(key),
                            expected_order_id="O2", expected_refund_cents=8000)
    assert result["order_id"] == "O2"
    assert result["refund_cents"] == 8000
    assert result["key_id"] == key.key_id


def test_receipt_is_deterministic(run, key):
    first = issue(run, "O1", key)
    second = issue(run, "O1", key)
    # 同一批次同一订单，重复签发得到逐字节一致的凭证——重试不新增凭证
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------- 各类篡改必须验不过 ----------

def test_change_refund_amount_fails(run, key):
    receipt = issue(run, "O1", key)
    receipt["order"]["refund_cents"] = 4501
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "BATCH_ROOT_MISMATCH"


def test_change_order_id_fails(run, key):
    receipt = issue(run, "O1", key)
    receipt["order"]["order_id"] = "O9"
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "BATCH_ROOT_MISMATCH"


def test_change_line_amount_fails(run, key):
    receipt = issue(run, "O1", key)
    receipt["order"]["lines"][0]["refund_cents"] += 100
    with pytest.raises(ReceiptError):
        verify_receipt(json.dumps(receipt), anchor(key))


def test_tamper_merkle_proof_fails(run, key):
    receipt = issue(run, "O1", key)
    receipt["merkle_proof"]["path"][0]["hash"] = "0" * 64
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "BATCH_ROOT_MISMATCH"


def test_tamper_batch_root_fails(run, key):
    receipt = issue(run, "O1", key)
    receipt["batch"]["batch_root"] = "f" * 64
    with pytest.raises(ReceiptError):
        verify_receipt(json.dumps(receipt), anchor(key))


def test_tamper_signature_fails(run, key):
    receipt = issue(run, "O1", key)
    raw = bytearray.fromhex(receipt["signature"])
    raw[0] ^= 0x01
    receipt["signature"] = raw.hex()
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "SIGNATURE_INVALID"


def test_replace_entire_verification_material_with_other_key_fails(run, key):
    """连凭证自带的 key_id/批根/签名整套验真材料一起换，也过不了信任锚。"""
    receipt = issue(run, "O1", key)
    attacker = SigningKey(generate_keypair()[0])
    # 攻击者用自己的密钥重签一个改了金额的“凭证”
    forged_run = copy.deepcopy(run)
    forged_run["orders"][0]["refund_cents"] = 99999
    forged = issue(forged_run, "O1", attacker)
    forged["key_id"] = attacker.key_id  # 自带的验真材料也换成攻击者的
    # 复核方手里的信任锚仍是工作台公钥：key_id 首先就对不上
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(forged), anchor(key))
    assert exc.value.code == "KEY_ID_MISMATCH"
    # 即使复核方误存了攻击者公钥，争议订单的真实金额（4500 分）也对不上伪造值
    with pytest.raises(ReceiptError) as exc2:
        verify_receipt(json.dumps(forged), anchor(attacker),
                       expected_order_id="O1", expected_refund_cents=4500)
    assert exc2.value.code == "REFUND_MISMATCH"


def test_foreign_signature_on_original_root_fails(run, key):
    """换签名必须同时换 key_id；在工作台信任锚下 key_id 不匹配即拒绝。"""
    receipt = issue(run, "O1", key)
    attacker = SigningKey(generate_keypair()[0])
    batch = {"run_id": receipt["run_id"], "batch_root": receipt["batch"]["batch_root"],
             "tree_size": receipt["batch"]["tree_size"], "source_sha256": receipt["source_sha256"],
             "review_revision": receipt["review_revision"]}
    receipt["signature"] = attacker.sign(signing_message(batch)).hex()
    # 不换 key_id：签名与 key_id 对应的公钥不符
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "SIGNATURE_INVALID"
    # 连 key_id 一起换成攻击者的：工作台信任锚仍在第一关 key_id 比对处拒绝
    receipt["key_id"] = attacker.key_id
    with pytest.raises(ReceiptError) as exc2:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc2.value.code == "KEY_ID_MISMATCH"


def test_expected_order_and_refund_checks(run, key):
    receipt = issue(run, "O1", key)
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key), expected_order_id="O2")
    assert exc.value.code == "ORDER_MISMATCH"
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key), expected_refund_cents=1)
    assert exc.value.code == "REFUND_MISMATCH"


def test_malformed_receipt_rejected(key):
    with pytest.raises(ReceiptError) as exc:
        verify_receipt("{not json", anchor(key))
    assert exc.value.code == "RECEIPT_NOT_JSON"
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps({"schema": "other"}), anchor(key))
    assert exc.value.code == "RECEIPT_MALFORMED"


def test_run_id_change_breaks_signature(run, key):
    receipt = issue(run, "O1", key)
    receipt["run_id"] = "runB"
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "SIGNATURE_INVALID"


def test_source_digest_change_breaks_signature(run, key):
    receipt = issue(run, "O1", key)
    receipt["source_sha256"] = "a" * 64
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "SIGNATURE_INVALID"


def test_proof_depth_must_match_tree_size(run, key):
    receipt = issue(run, "O1", key)
    truncated = copy.deepcopy(receipt)
    truncated["merkle_proof"]["path"].pop()
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(truncated), anchor(key))
    assert exc.value.code == "MERKLE_PROOF_INVALID"
    extended = copy.deepcopy(receipt)
    extended["merkle_proof"]["path"].append({"side": "right", "hash": "0" * 64})
    with pytest.raises(ReceiptError):
        verify_receipt(json.dumps(extended), anchor(key))


def test_malformed_proof_structure_rejected(run, key):
    receipt = issue(run, "O1", key)
    receipt["merkle_proof"] = {"path": []}
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), anchor(key))
    assert exc.value.code == "MERKLE_PROOF_INVALID"


def test_duplicate_order_ids_rejected():
    dup = [make_order("O1", 100), make_order("O1", 200)]
    with pytest.raises(ValueError):
        build_tree(dup)
