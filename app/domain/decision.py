from app.domain.helpers import D


def decide_rows(items):
    for item in items:
        if item["problem"]:
            item["verdict"] = "REJECT"
            item["reason"] = item["problem"]
        elif item["refund"] > item["payment"]:
            item["verdict"] = "REJECT"
            item["reason"] = "OVER_REFUND"
        elif item["refund"] == 0 and item["discount"] > 0:
            item["verdict"] = "REVIEW"
            item["reason"] = "DISCOUNT_WITHOUT_REFUND"
        else:
            item["verdict"] = "PASS"
            item["reason"] = "BALANCED"
        item.setdefault("verdict", "PASS")
        item.setdefault("reason", "OK")
    return items
