import pytest
from conftest import advance, load
from cryptography.exceptions import InvalidSignature

from node.identity.crypto import verify
from node.transport.protocol import ProtocolError


def test_full_assignment(workflow, trade_id):
    w = workflow
    t = advance(w, trade_id)
    assert len(t["checks"]) >= 9
    w.receive_credit(
        trade_id,
        {
            "execution_id": t["execution_id"],
            "amount": t["purchase_price"],
            "account": "DEMO-AGENT-SETTLEMENT",
        },
    )
    settled = advance(w, trade_id, "SETTLED")
    with w.store.transaction() as s:
        r = w.store.get(s, "register:FAC-ATLAS-01")
    assert r == {"Meridian Capital": 150_000_000_000, "Northstar Bank": 150_000_000_000}
    assert w.store.verify_audit_chain()
    receipt = settled["receipt"]
    verify(
        w.signer.public_key,
        {k: v for k, v in receipt.items() if k != "signature"},
        receipt["signature"],
    )
    receipt["status"] = "CANCELLED"
    with pytest.raises(InvalidSignature):
        verify(
            w.signer.public_key,
            {k: v for k, v in receipt.items() if k != "signature"},
            receipt["signature"],
        )
    with w.store.transaction() as s:
        with pytest.raises(ProtocolError, match="already_settled"):
            w.settle(s, settled, settled["terms"]["seller"])


def test_no_approvals_no_settlement(workflow, trade_id):
    with workflow.store.transaction() as s:
        with pytest.raises(ProtocolError, match="settlement_preconditions"):
            workflow.settle(s, workflow.load(s, trade_id), "Meridian Capital")


def test_non_seller_cannot_request(workflow, trade_id):
    with workflow.store.transaction() as s:
        with pytest.raises(ProtocolError, match="seller_request"):
            workflow.settle(s, workflow.load(s, trade_id), "Northstar Bank")


def test_wrong_officer(workflow, trade_id):
    t = load(workflow, trade_id)
    with pytest.raises(ProtocolError, match="officer_not_permitted"):
        workflow.decide(trade_id, t["tasks"][0]["task_id"], "buyer-ops", "approve")


def test_reject_reason_required(workflow, trade_id):
    t = load(workflow, trade_id)
    with pytest.raises(ProtocolError, match="reason_required"):
        workflow.decide(trade_id, t["tasks"][0]["task_id"], "seller-trader", "reject")


def test_dual_officer_distinct(workflow, trade_id):
    w = workflow
    t = load(w, trade_id)
    w.decide(trade_id, t["tasks"][0]["task_id"], "seller-trader", "approve")
    t = load(w, trade_id)
    task = next(x for x in t["tasks"] if x["action"] == "ssi.update")
    w.decide(trade_id, task["task_id"], "buyer-treasurer", "approve")
    w.decide(trade_id, task["task_id"], "agent-officer", "approve")
    with pytest.raises(ProtocolError, match="officer_not_permitted"):
        w.decide(trade_id, task["task_id"], "agent-officer", "approve")
    w.decide(trade_id, task["task_id"], "agent-second", "approve")
    assert load(w, trade_id)["facts"]["ssi_current"]


def test_wrong_credit_amount(workflow, trade_id):
    t = advance(workflow, trade_id)
    with pytest.raises(ProtocolError, match="credit_mismatch"):
        workflow.receive_credit(
            trade_id,
            {
                "execution_id": t["execution_id"],
                "amount": 1,
                "account": "DEMO-AGENT-SETTLEMENT",
            },
        )
    assert load(workflow, trade_id)["state"] == "FUNDING_SENT"


def test_kyc_missing_document(workflow, trade_id):
    w = workflow
    with w.store.transaction() as s:
        w.store.put(s, "sandbox:kyc", "sandbox", {"identity": "only"})
    t = load(w, trade_id)
    w.decide(trade_id, t["tasks"][0]["task_id"], "seller-trader", "approve")
    t = load(w, trade_id)
    task = next(x for x in t["tasks"] if x["action"] == "kyc.release")
    w.decide(trade_id, task["task_id"], "buyer-ops", "approve")
    task = next(x for x in load(w, trade_id)["tasks"] if x["action"] == "kyc.clear")
    with pytest.raises(ProtocolError, match="kyc_documents_missing"):
        w.decide(trade_id, task["task_id"], "agent-kyc", "approve")
    assert not load(w, trade_id)["facts"]["kyc_cleared"]


def test_atomic_recheck_position(workflow, trade_id):
    w = workflow
    t = advance(w, trade_id)
    w.receive_credit(
        trade_id,
        {
            "execution_id": t["execution_id"],
            "amount": t["purchase_price"],
            "account": "DEMO-AGENT-SETTLEMENT",
        },
    )
    with w.store.transaction() as s:
        w.store.put(
            s,
            "register:FAC-ATLAS-01",
            "register",
            {"Meridian Capital": 0, "Northstar Bank": 300_000_000_000},
        )
    t = load(w, trade_id)
    task = next(x for x in t["tasks"] if x["action"] == "settle.execute")
    with pytest.raises(ProtocolError, match="settlement_preconditions"):
        w.decide(trade_id, task["task_id"], "agent-officer", "approve")
    assert load(w, trade_id)["state"] == "FUNDS_RECEIVED"
