from decimal import Decimal

from app.catalog import SPEC
from app.domain.calculate import calculate_rows
from app.domain.prepare import prepare_rows
from tests.domain_cases import CLEAN, calc

# TRAP-19 TRAP-20 TRAP-24 的边界由本文件的跨日、合并与单位用例固定。


def clean_results():
    items, issues = prepare_rows(CLEAN)
    assert issues == []
    return calculate_rows(items)


def test_clean_result_count():
    assert len(clean_results()) == 4


def test_metric_total_is_reconciled():
    total = sum((item["metric"] for item in clean_results()), Decimal("0"))
    assert total == Decimal("14078")


def test_first_result_matches_expected():
    item = clean_results()[0]
    assert item["label"] == "O1"
    assert abs(float(item["refund"]) - float("4500")) < 0.011


def test_core_boundary_case():
    results, issues = calc([{'order_id': 'O9', 'line_id': 'O9L1', 'line_amount': '0.10', 'discount_total': '0.01', 'return_qty': '1', 'qty': '1', 'unit_refund': '0.10', 'freight': '0', 'payment': '1'}])
    assert issues == []
    value = results[0]["refund"]
    expected = '9'
    if expected in {"True", "False"}:
        assert bool(value) is (expected == "True")
    elif isinstance(expected, bool):
        assert bool(value) is expected
    elif expected.startswith("20") and len(expected) == 10:
        assert value.isoformat() == expected
    elif expected.replace(".", "", 1).replace("-", "", 1).isdigit():
        assert abs(float(value) - float(expected)) < 0.001
    else:
        assert value == expected


def test_result_labels_are_unique():
    labels = [item["label"] for item in clean_results()]
    assert len(labels) == len(set(labels))


def test_every_result_has_metric():
    assert all(item.get("metric") is not None for item in clean_results())


def test_shipping_is_refunded_once_only_when_every_line_is_returned():
    partial = [dict(CLEAN[0], return_qty="2"), CLEAN[1]]
    results, issues = calc(partial)
    assert issues == []
    assert results[0]["refund"] == 9000
    full = [partial[0], dict(CLEAN[1], return_qty="1")]
    results, issues = calc(full)
    assert issues == []
    assert results[0]["refund"] == 14500
