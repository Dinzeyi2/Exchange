from datetime import date

import pytest

from node.adapters.models import (
    aba_valid,
    business_day,
    lei_valid,
    next_business_day,
    purchase_price,
)


@pytest.mark.parametrize(
    "value,valid",
    [
        ("021000021", True),
        ("021000022", False),
        ("000000000", False),
        ("123", False),
        ("１２３４５６７８９", False),
    ],
)
def test_aba(value, valid):
    assert aba_valid(value) == valid


@pytest.mark.parametrize(
    "value,valid",
    [("5493001KJTIIGC8Y1R12", True), ("5493001KJTIIGC8Y1R13", False), ("wrong", False)],
)
def test_lei(value, valid):
    assert lei_valid(value) == valid


def test_half_up():
    assert purchase_price(1, "50") == 1
    assert purchase_price(50_000_000_000, "99.75") == 49_875_000_000


@pytest.mark.parametrize("price", ["NaN", "Infinity", "-1", "0"])
def test_bad_price(price):
    with pytest.raises(ValueError):
        purchase_price(100, price)


@pytest.mark.parametrize(
    "day", ["2026-11-11", "2026-11-26", "2027-06-18", "2027-12-31", "2026-05-25"]
)
def test_holidays(day):
    assert not business_day(date.fromisoformat(day))


def test_next_business_day():
    assert next_business_day(date(2026, 11, 6)) == date(2026, 11, 9)
