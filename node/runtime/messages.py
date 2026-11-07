"""Closed, typed action schemas. No free-form peer operations."""

from typing import Literal

from pydantic import Field, model_validator

from node.adapters.models import Model, Ssi, TradeInput


class Ticket(Model):
    terms: TradeInput
    participants: dict[str, str]

    @model_validator(mode="after")
    def roles(self):
        if (
            set(self.participants) != {"seller", "buyer", "agent", "borrower"}
            or len(set(self.participants.values())) != 4
        ):
            raise ValueError("four independent participants required")
        return self


class Action(Model):
    execution_id: str = Field(pattern=r"^[a-zA-Z0-9-]{8,100}$")


class Propose(Action):
    ticket: Ticket
    approval: dict


class TradeBreak(Action):
    reason: Literal["booked_trade_mismatch"]


class Affirm(Action):
    terms_hash: str


class RequestPackage(Action):
    types: list[str]


class ReleasePackage(Action):
    documents: dict[str, str]
    hashes: dict[str, str]
    approval: dict


class Status(Action):
    status: Literal["cleared", "updated", "CONSENTED", "DECLINED"]
    approvals: list[dict]


class SsiUpdate(Action):
    ssi: Ssi
    approval: dict


class ConsentRequest(Action):
    terms: dict
    due_at: str


class DocumentRequest(Action):
    ticket: Ticket
    text: str
    document_hash: str


class DocumentSignature(Action):
    document_hash: str
    approval: dict


class Ready(Action):
    terms_hash: str
    document_hash: str
    approvals_hash: str


class FundingRequest(Action):
    terms_hash: str


class FundingNotice(Action):
    payment_id: str
    approval: dict


class SettleRequest(Action):
    terms_hash: str


class Receipt(Action):
    receipt_id: str
    facility_id: str
    amount: int = Field(gt=0)
    seller: str
    buyer: str
    effective_date: str
    document_hash: str
    register_total: int = Field(gt=0)


class Ack(Action):
    receipt_id: str


class ExecutionStatus(Model):
    execution_id: str
    body_hash: str


class Readiness(Model):
    question: str
    params: dict


SCHEMAS = {
    "trade.propose": Propose,
    "trade.affirm": Affirm,
    "trade.break": TradeBreak,
    "consent.status": Status,
    "kyc.request_package": RequestPackage,
    "kyc.release": ReleasePackage,
    "kyc.clear": Status,
    "ssi.update": SsiUpdate,
    "ssi.confirm": Status,
    "consent.request": ConsentRequest,
    "consent.borrower": Status,
    "consent.agent": Status,
    "doc.request": DocumentRequest,
    "doc.sign": DocumentSignature,
    "trade.ready": Ready,
    "funding.request": FundingRequest,
    "funding.release": FundingNotice,
    "settle.execute": SettleRequest,
    "settle.receipt": Receipt,
    "receipt.ack": Ack,
    "execution.status": ExecutionStatus,
    "ask": Readiness,
}
# Exactly which origin role may deliver a message to which role.
ROUTES = {
    "trade.propose": ({"seller"}, {"buyer", "agent"}),
    "trade.affirm": ({"buyer"}, {"seller", "agent"}),
    "trade.break": ({"buyer"}, {"seller", "agent"}),
    "consent.status": ({"agent"}, {"seller", "buyer"}),
    "kyc.request_package": ({"agent"}, {"buyer"}),
    "kyc.release": ({"buyer"}, {"agent"}),
    "kyc.clear": ({"agent"}, {"seller", "buyer"}),
    "ssi.update": ({"seller", "buyer"}, {"agent"}),
    "ssi.confirm": ({"agent"}, {"seller", "buyer"}),
    "consent.request": ({"agent"}, {"borrower"}),
    "consent.borrower": ({"borrower"}, {"agent"}),
    "consent.agent": ({"agent"}, {"seller", "buyer"}),
    "doc.request": ({"agent"}, {"seller", "buyer"}),
    "doc.sign": ({"seller", "buyer"}, {"agent"}),
    "trade.ready": ({"agent"}, {"seller", "buyer"}),
    "funding.request": ({"seller"}, {"buyer"}),
    "funding.release": ({"buyer"}, {"agent"}),
    "settle.execute": ({"seller"}, {"agent"}),
    "settle.receipt": ({"agent"}, {"seller", "buyer", "borrower"}),
    "receipt.ack": ({"seller", "buyer", "borrower"}, {"agent"}),
}

TASK_ROLES = {
    "trade.propose": ["trader"],
    "kyc.release": ["loan_ops"],
    "kyc.clear": ["kyc"],
    "ssi.release": ["treasurer"],
    "ssi.accept": ["officer", "officer"],
    "consent.agent": ["officer"],
    "consent.borrower": ["treasurer"],
    "doc.sign": ["signatory"],
    "funding.release": ["treasurer"],
    "settle.execute": ["officer"],
}
