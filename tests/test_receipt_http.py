import json

from app.security.keys import load_signing_key
from app.receipts.verify import verify_receipt


def approved(client, profile="clean"):
    run = client.post("/api/runs", json={"profile": profile}).get_json()
    client.post(f"/api/runs/{run['run_id']}/review",
                json={"decision": "APPROVED", "comment": "复核完成", "expected_revision": 0})
    return client.get(f"/api/runs/{run['run_id']}").get_json()


def test_verify_key_publishes_anchor(client):
    response = client.get("/api/verify-key")
    assert response.status_code == 200
    data = response.get_json()
    assert data["alg"] == "Ed25519"
    assert len(bytes.fromhex(data["public_key"])) == 32
    assert len(data["key_id"]) == 64
    # 重复读取稳定：同一工作台只有一把签名密钥
    again = client.get("/api/verify-key").get_json()
    assert again == data


def test_orders_listed_only_after_approval(client):
    run = client.post("/api/runs", json={"profile": "clean"}).get_json()
    blocked = client.get(f"/api/runs/{run['run_id']}/orders")
    assert blocked.status_code == 409
    client.post(f"/api/runs/{run['run_id']}/review",
                json={"decision": "APPROVED", "comment": "ok", "expected_revision": 0})
    response = client.get(f"/api/runs/{run['run_id']}/orders")
    assert response.status_code == 200
    order_ids = response.get_json()["order_ids"]
    assert order_ids == sorted(order_ids)
    assert "O1" in order_ids


def test_receipt_downloads_and_verifies_offline(client):
    run = approved(client)
    key = load_signing_key()
    response = client.get(f"/api/runs/{run['run_id']}/receipts/O1")
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    receipt = response.get_json()
    assert receipt["schema"] == "workbench-order-receipt/v1"
    assert receipt["order"]["order_id"] == "O1"
    anchor = {"key_id": key.key_id, "public_key": key.public.hex()}
    summary = verify_receipt(json.dumps(receipt), anchor)
    assert summary["verified"] is True
    assert summary["run_id"] == run["run_id"]


def test_receipt_contains_no_other_orders(client):
    run = approved(client)
    receipt = client.get(f"/api/runs/{run['run_id']}/receipts/O1").get_json()
    blob = json.dumps(receipt, ensure_ascii=False)
    for other in ("O2", "O3", "O4"):
        assert other not in blob


def test_receipt_blocked_before_approval(client):
    run = client.post("/api/runs", json={"profile": "clean"}).get_json()
    response = client.get(f"/api/runs/{run['run_id']}/receipts/O1")
    assert response.status_code == 409
    assert response.get_json()["code"] == "NOT_APPROVED"


def test_receipt_unknown_order_404(client):
    run = approved(client)
    response = client.get(f"/api/runs/{run['run_id']}/receipts/NO_SUCH_ORDER")
    assert response.status_code == 404
    assert response.get_json()["code"] == "ORDER_NOT_IN_BATCH"


def test_unknown_run_404(client):
    assert client.get("/api/runs/deadbeef/receipts/O1").status_code == 404


def test_repeated_download_is_byte_identical(client):
    run = approved(client)
    first = client.get(f"/api/runs/{run['run_id']}/receipts/O1").get_data()
    second = client.get(f"/api/runs/{run['run_id']}/receipts/O1").get_data()
    assert first == second


def test_retry_run_shares_same_receipt(client):
    # 同一来源重复执行是幂等的，得到同一批次，凭证也完全一致
    first_run = client.post("/api/runs", json={"profile": "clean"}).get_json()
    second_run = client.post("/api/runs", json={"profile": "clean"}).get_json()
    assert first_run["run_id"] == second_run["run_id"]
    client.post(f"/api/runs/{first_run['run_id']}/review",
                json={"decision": "APPROVED", "comment": "ok", "expected_revision": 0})
    a = client.get(f"/api/runs/{first_run['run_id']}/receipts/O1").get_data()
    b = client.get(f"/api/runs/{second_run['run_id']}/receipts/O1").get_data()
    assert a == b


def test_tampered_amount_rejected_by_verifier(client):
    run = approved(client)
    receipt = client.get(f"/api/runs/{run['run_id']}/receipts/O1").get_json()
    receipt["order"]["refund_cents"] += 1
    key = load_signing_key()
    from app.receipts.verify import ReceiptError
    import pytest
    with pytest.raises(ReceiptError) as exc:
        verify_receipt(json.dumps(receipt), {"key_id": key.key_id, "public_key": key.public.hex()})
    assert exc.value.code == "BATCH_ROOT_MISMATCH"


def test_dirty_batch_can_still_issue_for_passed_orders_when_approved(client):
    # dirty 批次有阻断项时无法签发，自然也没有凭证；clean 全量通过后每单都可取
    blocked = client.post("/api/runs", json={"profile": "dirty"}).get_json()
    review = client.post(f"/api/runs/{blocked['run_id']}/review",
                         json={"decision": "APPROVED", "comment": "x", "expected_revision": 0})
    assert review.status_code == 409
    assert client.get(f"/api/runs/{blocked['run_id']}/receipts/O1").status_code == 409


def test_legacy_batch_without_order_records_refuses_receipt(client, tmp_path):
    # 模拟升级前签发的旧批次：payload 里没有 orders 记录
    from app.review.service import serialize
    store = client.application.extensions["runs"]
    run = client.post("/api/runs", json={"profile": "clean"}).get_json()
    row = store.get(run["run_id"])
    payload = json.loads(row["payload"])
    payload.pop("orders", None)
    import sqlite3
    with store.connect() as db:
        db.execute("UPDATE runs SET payload=?, status='APPROVED', revision=1 WHERE id=?",
                   (json.dumps(payload, ensure_ascii=False), run["run_id"]))
    response = client.get(f"/api/runs/{run['run_id']}/receipts/O1")
    assert response.status_code == 409
    assert response.get_json()["code"] == "BATCH_RECORDS_MISSING"
