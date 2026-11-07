from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Role(StrEnum):
    SELLER = "seller"
    BUYER = "buyer"
    AGENT = "agent"
    BORROWER = "borrower"


def aba_valid(value: str) -> bool:
    return (
        len(value) == 9
        and value.isascii()
        and value.isdigit()
        and value != "000000000"
        and sum(int(x) * w for x, w in zip(value, [3, 7, 1] * 3)) % 10 == 0
    )


def lei_valid(value: str) -> bool:
    if (
        len(value) != 20
        or not value.isascii()
        or not value.isalnum()
        or value != value.upper()
        or not value[-2:].isdigit()
    ):
        return False
    expanded = "".join(str(ord(c) - 55) if c.isalpha() else c for c in value)
    return int(expanded) % 97 == 1


def purchase_price(amount: int, price: str) -> int:
    p = Decimal(price)
    if not p.is_finite() or p <= 0 or amount <= 0:
        raise ValueError("invalid amount or price")
    result = int(
        (Decimal(amount) * p / 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )
    if result > 2**53 - 1:
        raise ValueError("amount exceeds canonical JSON safe integer limit")
    return result


def _observed(day):
    return (
        day - timedelta(days=1)
        if day.weekday() == 5
        else day + timedelta(days=1)
        if day.weekday() == 6
        else day
    )


def federal_holidays(year):
    days = {
        _observed(date(y, m, d))
        for y in [year - 1, year, year + 1]
        for m, d in [(1, 1), (6, 19), (7, 4), (11, 11), (12, 25)]
    }
    for month, weekday, nth in [
        (1, 0, 3),
        (2, 0, 3),
        (9, 0, 1),
        (10, 0, 2),
        (11, 3, 4),
    ]:
        first = date(year, month, 1)
        days.add(
            first + timedelta(days=(weekday - first.weekday()) % 7 + 7 * (nth - 1))
        )
    last = date(year, 6, 1) - timedelta(days=1)
    days.add(last - timedelta(days=last.weekday()))
    return days


def business_day(day):
    return day.weekday() < 5 and day not in federal_holidays(day.year)


def next_business_day(day):
    day += timedelta(days=1)
    while not business_day(day):
        day += timedelta(days=1)
    return day


class Facility(Model):
    facility_id: str
    borrower_name: str
    type: str = "term_loan"
    currency: str = "USD"
    total_outstanding: int = Field(gt=0, le=2**63 - 1)
    rate_desc: str = "SOFR + 275 bps"
    maturity: str
    min_assignment: int = Field(gt=0)
    assignment_multiple: int = Field(gt=0)
    borrower_consent_required: bool = True
    consent_exempt_assignee_types: list[str] = Field(
        default_factory=lambda: ["affiliate", "approved_fund"]
    )
    agent_consent_required: bool = True
    assignment_fee: int = 350000


class Ssi(Model):
    owner_legal_name: str
    bank_name: str
    aba: str
    account: str = Field(min_length=1, max_length=34)
    currency: str = "USD"
    effective_at: str

    @field_validator("currency")
    @classmethod
    def usd_only(cls, value):
        if value != "USD":
            raise ValueError("only USD settlement instructions are supported")
        return value

    @field_validator("aba")
    @classmethod
    def valid_aba(cls, value):
        if not aba_valid(value):
            raise ValueError("invalid ABA checksum")
        return value


class TradeInput(Model):
    trade_id: str = Field(pattern=r"^LT-[A-Za-z0-9-]{6,64}$")
    facility_id: str
    amount: int = Field(gt=0, le=2**53 - 1)
    price: str = Field(pattern=r"^\d{1,3}(\.\d{1,6})?$")
    seller: str
    buyer: str
    trade_date: str
    settlement_date: str

    @field_validator("trade_date", "settlement_date")
    @classmethod
    def valid_date(cls, value):
        date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def valid_valuation(self):
        purchase_price(self.amount, self.price)
        return self
