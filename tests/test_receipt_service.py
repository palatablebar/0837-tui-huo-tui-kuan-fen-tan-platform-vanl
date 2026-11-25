import json

import pytest

from app.errors import DomainIssue
from app.receipts.service import build_batch_manifest, issue_order_receipt, list_order_ids
from app.receipts.verify import verify_receipt
from app.security.keys import SigningKey
from app.security.ed25519 import generate_keypair


def order(oid, refund):
    return {"order_id": oid, "refund_cents": refund, "payment_cents": 10000,
            "freight_refund_cents": 0, "verdict": "PASS", "reason": "BALANCED",
            "lines": [{"line_id": oid + "L1", "refund_cents": refund, "alloc_discount_cents": 0}]}


def run(orders, status="APPROVED", revision=1, include_orders=True):
    data = {"run_id": "run1", "status": status, "revision": revision,
            "source": {"sha256": "ab" * 32}, "profile": "clean"}
    if include_orders:
        data["orders"] = orders
    return data


@pytest.fixture
def key():
    return SigningKey(generate_keypair()[0])


def test_receipt_issues_for_approved_run(key):
    data = run([order("O1", 4500), order("O2", 8000)])
    receipt = issue_order_receipt(data, "O1", key)
    result = verify_receipt(json.dumps(receipt), {"key_id": key.key_id, "public_key": key.public.hex()})
    assert result["verified"] is True
    assert result["order_id"] == "O1"
    assert result["refund_cents"] == 4500


def test_unapproved_run_is_blocked(key):
    data = run([order("O1", 4500)], status="DRAFT")
    with pytest.raises(DomainIssue) as exc:
        issue_order_receipt(data, "O1", key)
    assert exc.value.status == 409
    assert exc.value.code == "NOT_APPROVED"


def test_missing_run_returns_404(key):
    with pytest.raises(DomainIssue) as exc:
        issue_order_receipt(None, "O1", key)
    assert exc.value.status == 404


def test_order_not_in_batch_returns_404(key):
    data = run([order("O1", 4500)])
    with pytest.raises(DomainIssue) as exc:
        issue_order_receipt(data, "NOPE", key)
    assert exc.value.status == 404
    assert exc.value.code == "ORDER_NOT_IN_BATCH"


def test_legacy_batch_without_order_records_refuses(key):
    # 旧批次丢失订单级记录：核实不了签发金额，明确拒绝而不是出具无法验证的凭证
    data = run([], include_orders=False)
    with pytest.raises(DomainIssue) as exc:
        issue_order_receipt(data, "O1", key)
    assert exc.value.code == "BATCH_RECORDS_MISSING"
    assert exc.value.status == 409
    with pytest.raises(DomainIssue):
        list_order_ids(data)


def test_retry_does_not_create_new_receipt(key):
    data = run([order("O1", 4500), order("O2", 8000)])
    first = issue_order_receipt(data, "O1", key)
    second = issue_order_receipt(data, "O1", key)
    third = issue_order_receipt(data, "O1", key)
    # 同一订单无论下载多少次，凭证逐字节一致——不存在“新增凭证”
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert json.dumps(second, sort_keys=True) == json.dumps(third, sort_keys=True)


def test_manifest_signature_is_stable_across_calls(key):
    data = run([order("O1", 4500)])
    m1 = build_batch_manifest(data, key)
    m2 = build_batch_manifest(data, key)
    assert m1["batch"] == m2["batch"]
    assert m1["signature"] == m2["signature"]


def test_list_order_ids_only_for_approved(key):
    data = run([order("O1", 4500), order("O2", 8000)])
    assert list_order_ids(data) == ["O1", "O2"]
    data["status"] = "HELD"
    with pytest.raises(DomainIssue) as exc:
        list_order_ids(data)
    assert exc.value.code == "NOT_APPROVED"
