import pytest
from conftest import load
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import x25519
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from node.identity.crypto import fingerprint, public_bytes
from node.transport.protocol import ProtocolError


def test_audit_update_delete_refused(workflow):
    for statement in [
        "UPDATE audit_entries SET hash = :value WHERE seq = 1",
        "DELETE FROM audit_entries WHERE seq = 1",
    ]:
        with pytest.raises(DatabaseError):
            with workflow.store.engine.begin() as connection:
                connection.execute(text(statement), {"value": "tampered"})
    assert workflow.store.verify_audit_chain()


def test_tampered_approval_signature(workflow, trade_id):
    w = workflow
    t = load(w, trade_id)
    task = t["tasks"][0]
    w.decide(trade_id, task["task_id"], "seller-trader", "approve")
    task = load(w, trade_id)["tasks"][0]
    task["approvals"][0]["summary"] = "tampered"
    with pytest.raises(InvalidSignature):
        w.verify_task(task)


def test_ssi_change_invalidates_pending_approval(workflow, trade_id):
    w = workflow
    t = load(w, trade_id)
    w.decide(trade_id, t["tasks"][0]["task_id"], "seller-trader", "approve")
    t = load(w, trade_id)
    task = next(x for x in t["tasks"] if x["action"] == "ssi.update")
    w.decide(trade_id, task["task_id"], "buyer-treasurer", "approve")
    with w.store.transaction() as s:
        ssi = w.store.get(s, "sandbox:ssi")
        ssi["account"] = "different-account"
        w.store.put(s, "sandbox:ssi", "sandbox", ssi)
    with pytest.raises(ProtocolError, match="stale_ssi"):
        w.decide(trade_id, task["task_id"], "agent-officer", "approve")


def test_per_trade_fingerprint():
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    value = {"aba": "021000021", "account": "SYNTHETIC"}
    one = fingerprint(a, public_bytes(b.public_key()), "LT-ONE", value)
    assert one == fingerprint(b, public_bytes(a.public_key()), "LT-ONE", value)
    assert one != fingerprint(a, public_bytes(b.public_key()), "LT-TWO", value)
    assert one != fingerprint(
        a,
        public_bytes(b.public_key()),
        "LT-ONE",
        {"aba": "021000021", "account": "OTHER"},
    )
