from app.catalog import SPEC
from app.domain.calculate import calculate_rows
from app.domain.decision import decide_rows
from app.domain.prepare import prepare_rows
from app.intake.service import load

CLEAN = [{'order_id': 'O1',
  'line_id': 'O1L1',
  'line_amount': '100.00',
  'discount_total': '15.00',
  'return_qty': '1',
  'qty': '2',
  'unit_refund': '100.00',
  'freight': '10.00',
  'payment': '200.00'},
 {'order_id': 'O1',
  'line_id': 'O1L2',
  'line_amount': '50.00',
  'discount_total': '15.00',
  'return_qty': '0',
  'qty': '1',
  'unit_refund': '50.00',
  'freight': '10.00',
  'payment': '200.00'},
 {'order_id': 'O2',
  'line_id': 'O2L1',
  'line_amount': '80.00',
  'discount_total': '0.00',
  'return_qty': '1',
  'qty': '1',
  'unit_refund': '80.00',
  'freight': '8.00',
  'payment': '100.00'},
 {'order_id': 'O3',
  'line_id': 'O3L1',
  'line_amount': '33.33',
  'discount_total': '10.00',
  'return_qty': '1',
  'qty': '3',
  'unit_refund': '33.33',
  'freight': '5.00',
  'payment': '60.00'},
 {'order_id': 'O4',
  'line_id': 'O4L1',
  'line_amount': '0.01',
  'discount_total': '0.10',
  'return_qty': '1',
  'qty': '1',
  'unit_refund': '0.01',
  'freight': '0.00',
  'payment': '1.00'}]


def row(**changes):
    item = dict(CLEAN[0])
    item.update(changes)
    return item


def calc(rows):
    items, issues = prepare_rows(rows)
    return calculate_rows(items), issues


def run(rows):
    items, issues = prepare_rows(rows)
    return decide_rows(calculate_rows(items)), issues


def run_profile(profile):
    return run(load(profile)["rows"])
