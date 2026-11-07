import base64
from datetime import datetime, timedelta, timezone

import pytest

from node.audit.store import Store
from node.identity.crypto import verify
from node.signer.backends import SoftwareSigner
from node.transport.protocol import Peer, ProtocolError, Transport, envelope


@pytest.fixture
def transport(tmp_path):
    sender = SoftwareSigner()
    receiver = SoftwareSigner()
    peer = Peer(
        node_id="seller",
        legal_name="Seller",
        lei="5493001KJTIIGC8Y1R12",
        role="seller",
        signing_key=base64.b64encode(sender.public_key).decode(),
        agreement_key=base64.b64encode(b"a" * 32).decode(),
        certificate_sha256="a" * 64,
        certificate_path="unused",
        endpoint="https://seller",
    )
    t = Transport(
        "agent",
        receiver,
        Store("sqlite:///" + str(tmp_path / "p.db")),
        {"seller": peer},
        lambda peer, msg: {"ok": True},
    )
    return t, sender, receiver


def message(sender):
    return envelope(
        sender, "seller", "agent", "ask", "LT-TEST-001", {"question": "test"}
    )


def test_signed_round_trip(transport):
    t, s, r = transport
    answer = t.receive(message(s), "a" * 64)
    verify(r.public_key, {k: v for k, v in answer.items() if k != "sig"}, answer["sig"])
    assert answer["body"]["answer"] == {"ok": True}
    assert t.store.verify_audit_chain()


def test_replay_refused(transport):
    t, s, _ = transport
    m = message(s)
    t.receive(m, "a" * 64)
    with pytest.raises(ProtocolError, match="replayed"):
        t.receive(m, "a" * 64)


def test_stale_refused(transport):
    t, s, _ = transport
    m = message(s)
    m["ts"] = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
    m["sig"] = s.sign({k: v for k, v in m.items() if k != "sig"})
    with pytest.raises(ProtocolError, match="stale"):
        t.receive(m, "a" * 64)


def test_certificate_sender_mismatch(transport):
    t, s, _ = transport
    with pytest.raises(ProtocolError, match="certificate_sender_mismatch"):
        t.receive(message(s), "b" * 64)


def test_tamper_refused(transport):
    t, s, _ = transport
    m = message(s)
    m["body"] = {"ok": "tampered"}
    with pytest.raises(ProtocolError, match="bad_signature"):
        t.receive(m, "a" * 64)


def test_wrong_recipient(transport):
    t, s, _ = transport
    m = message(s)
    m["to"] = "other"
    with pytest.raises(ProtocolError, match="wrong_recipient"):
        t.receive(m, "a" * 64)


def test_unknown_sender(transport):
    t, s, _ = transport
    m = message(s)
    m["from"] = "unknown"
    with pytest.raises(ProtocolError, match="unknown_sender"):
        t.receive(m, "a" * 64)
