#!/usr/bin/env python3
"""单订单凭证离线核验工具（外部复核方使用）。

用法
----
    python tools/verify_receipt.py <凭证.json> --key <公钥.json|公钥.hex|公钥.bin>
                                  [--order O1] [--refund-cents 4500]

信任锚（公钥）通过可信渠道从工作台 ``GET /api/verify-key`` 一次性获取并保存，
之后整个核验过程不访问网络、不依赖工作台是否在线，只使用 Python 标准库。

退出码：0 核验通过；1 核验失败（订单/金额/证明/签名/密钥任一不匹配）；2 用法错误。
"""
import argparse
import json
import sys
from pathlib import Path

# 让脚本在被单独拷贝到离线机器、与 app 包同级放置时也能直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.receipts.verify import ReceiptError, load_trust_anchor, verify_receipt  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description="离线核验工作台单订单退款凭证")
    parser.add_argument("receipt", help="单订单凭证 JSON 文件")
    parser.add_argument("--key", required=True,
                        help="信任锚：/api/verify-key 导出的 JSON，或 32 字节公钥（hex/base64/raw）")
    parser.add_argument("--order", help="期望的订单号，提供时一并核对")
    parser.add_argument("--refund-cents", type=int, help="期望的退款金额（整数分），提供时一并核对")
    args = parser.parse_args(argv)

    try:
        receipt_raw = Path(args.receipt).read_text(encoding="utf-8")
        key_path = Path(args.key)
        key_bytes = key_path.read_bytes()
        text = key_bytes.decode("utf-8").strip()
        if text.startswith("{"):
            anchor = json.loads(text)
        elif len(text) == 64:
            anchor = text  # 裸 hex 公钥
        else:
            anchor = key_bytes  # base64 或 raw 32 字节
        result = verify_receipt(receipt_raw, anchor,
                                expected_order_id=args.order,
                                expected_refund_cents=args.refund_cents)
    except ReceiptError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "detail": exc.detail},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"verified": False, "code": "INPUT_UNREADABLE",
                          "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
