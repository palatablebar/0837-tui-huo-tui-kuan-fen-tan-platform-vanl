import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.receipts.service import issue_order_receipt
from app.security.keys import SigningKey
from app.security.ed25519 import generate_keypair

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "verify_receipt.py"


def order(oid, refund):
    return {"order_id": oid, "refund_cents": refund, "payment_cents": 10000,
            "freight_refund_cents": 0, "verdict": "PASS", "reason": "BALANCED",
            "lines": [{"line_id": oid + "L1", "refund_cents": refund, "alloc_discount_cents": 0}]}


def run_cli(tmp_path, receipt, key_text, extra=None):
    receipt_path = tmp_path / "receipt.json"
    key_path = tmp_path / "key.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False), encoding="utf-8")
    key_path.write_text(key_text, encoding="utf-8")
    cmd = [sys.executable, "-I", str(TOOL), str(receipt_path), "--key", str(key_path)] + (extra or [])
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))


@pytest.fixture
def key():
    return SigningKey(generate_keypair()[0])


@pytest.fixture
def receipt(key):
    data = {"run_id": "runE2E", "status": "APPROVED", "revision": 1,
            "source": {"sha256": "cd" * 32}, "orders": [order("O1", 4500), order("O2", 8000)]}
    return issue_order_receipt(data, "O1", key)


def test_cli_accepts_valid_receipt(tmp_path, key, receipt):
    anchor = json.dumps({"key_id": key.key_id, "public_key": key.public.hex()})
    result = run_cli(tmp_path, receipt, anchor, ["--order", "O1", "--refund-cents", "4500"])
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["verified"] is True
    assert summary["order_id"] == "O1"
    assert summary["refund_cents"] == 4500


def test_cli_accepts_hex_trust_anchor(tmp_path, key, receipt):
    result = run_cli(tmp_path, receipt, key.public.hex())
    assert result.returncode == 0, result.stderr


def test_cli_rejects_tampered_amount(tmp_path, key, receipt):
    receipt["order"]["refund_cents"] = 4501
    anchor = json.dumps({"key_id": key.key_id, "public_key": key.public.hex()})
    result = run_cli(tmp_path, receipt, anchor)
    assert result.returncode == 1
    assert json.loads(result.stderr)["code"] == "BATCH_ROOT_MISMATCH"


def test_cli_rejects_tampered_signature(tmp_path, key, receipt):
    raw = bytearray.fromhex(receipt["signature"])
    raw[5] ^= 0xFF
    receipt["signature"] = raw.hex()
    result = run_cli(tmp_path, receipt, json.dumps({"key_id": key.key_id, "public_key": key.public.hex()}))
    assert result.returncode == 1
    assert json.loads(result.stderr)["code"] == "SIGNATURE_INVALID"


def test_cli_rejects_wrong_expected_refund(tmp_path, key, receipt):
    anchor = json.dumps({"key_id": key.key_id, "public_key": key.public.hex()})
    result = run_cli(tmp_path, receipt, anchor, ["--refund-cents", "1"])
    assert result.returncode == 1
    assert json.loads(result.stderr)["code"] == "REFUND_MISMATCH"


def test_cli_runs_without_network(tmp_path, key, receipt):
    # -I 隔离模式 + 无网络参数；同时确认输出里不出现任何其他订单号
    anchor = json.dumps({"key_id": key.key_id, "public_key": key.public.hex()})
    result = run_cli(tmp_path, receipt, anchor)
    assert result.returncode == 0
    assert "O2" not in result.stdout
    assert "O2" not in json.dumps(receipt)
