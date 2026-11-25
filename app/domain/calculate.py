from datetime import date, timedelta
from app.catalog import SPEC
from app.domain.helpers import *  # noqa: F401,F403


def calculate_rows(items):
    out = []
    rows = items
    orders = {}
    for item in items:
        orders.setdefault(item["order_id"], []).append(item)
    for order_id, lines in orders.items():
        discount = lines[0]["discount_total"]
        gross = sum((line["line_amount"] for line in lines), D("0", "CALC"))
        discount = min(discount, gross)
        shares = largest_remainder(discount, [line["line_amount"] for line in lines])
        refund = 0
        for line, share in zip(lines, shares):
            net_line = line["line_amount"] - share
            line["net_line"] = net_line
            line["alloc_discount"] = share
            line["refund"] = round_div(net_line * line["return_qty"], line["qty"])
            refund += line["refund"]
        freight_refund = lines[0]["freight"] if all(line["return_qty"] == line["qty"] for line in lines) else 0
        refund += freight_refund
        problem = None
        if any(len({line[field] for line in lines}) != 1 for field in ("discount_total", "payment", "freight")):
            problem = "ORDER_FIELDS_CONFLICT"
        out.append({"label": order_id, "refund": refund, "discount": discount,
                    "gross": gross, "payment": lines[0]["payment"], "problem": problem,
                    "freight_refund": freight_refund,
                    "order_id": order_id,
                    "line_details": [
                        {"line_id": line["line_id"], "refund_cents": int(line["refund"]),
                         "alloc_discount_cents": int(line["alloc_discount"])}
                        for line in lines
                    ],
                    "breakdown": [f'{line["line_id"]} · 分摊 {line["alloc_discount"]} 分 · 应退 {line["refund"]} 分'
                                  for line in lines],
                    "metric": refund, "limit": lines[0]["payment"]})
    for item in out:
        item.setdefault("label", str(item.get(SPEC["key"], "")))
    return out
