"""Negative protocol/action tests against running nodes, not in-process mocks."""

import base64
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from node.identity.crypto import digest, verify
from node.signer.backends import SoftwareSigner
from node.transport.client import send
from node.transport.protocol import Peer, envelope, tls_context


def peer_message(acceptance, sender, target, kind, body, claimed_sender=None):
    manifest = acceptance.manifest
    node = manifest["nodes"][sender]
    root = Path(node["root"]) / "private"
    signer = SoftwareSigner(
        serialization.load_pem_private_key(
            (root / "signing.pem").read_bytes(), password=None
        )
    )
    peer = Peer.model_validate(manifest["nodes"][target]["bundle"])
    # Container peers are deliberately not host-published. This helper is for OS-process tests.
    peer.endpoint = "https://localhost:" + str(
        manifest["nodes"][target].get(
            "host_peer_port", manifest["nodes"][target]["peer_port"]
        )
    )
    context = tls_context(
        root / (sender + ".crt"),
        root / (sender + ".key"),
        [peer.certificate_path],
        server=False,
    )
    msg = envelope(
        signer, claimed_sender or sender, target, kind, acceptance.trade_id, body
    )
    return peer, context, signer, msg


def reject(response, code):
    assert response["type"] == "error", response
    assert response["body"]["error"] == code, response


def run(acceptance):
    results = {}

    def call(sender, target, kind, body):
        peer, ctx, signer, msg = peer_message(acceptance, sender, target, kind, body)
        return send(peer, msg, ctx)

    reject(
        call("seller", "agent", "ask", {"question": "dump_accounts", "params": {}}),
        "question_not_permitted",
    )
    results["unauthorized_question_refused"] = True
    reject(
        call(
            "borrower",
            "agent",
            "ask",
            {"question": "lender_kyc_cleared", "params": {"lender": "Northstar Bank"}},
        ),
        "question_not_permitted",
    )
    results["wrong_peer_question_refused"] = True
    body = {"question": "consent_status", "params": {"trade_id": acceptance.trade_id}}
    peer, ctx, signer, msg = peer_message(acceptance, "seller", "agent", "ask", body)
    assert send(peer, msg, ctx)["type"] == "answer"
    reject(send(peer, msg, ctx), "replayed_envelope")
    results["replay_refused"] = True
    stale = copy.deepcopy(msg)
    stale["nonce"] = uuid4().hex
    stale["ts"] = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
    stale["sig"] = signer.sign({k: v for k, v in stale.items() if k != "sig"})
    reject(send(peer, stale, ctx), "stale_envelope")
    results["stale_refused"] = True
    tampered = copy.deepcopy(msg)
    tampered["nonce"] = uuid4().hex
    reject(send(peer, tampered, ctx), "bad_signature")
    results["tampered_envelope_refused"] = True
    # Valid buyer signature with the seller TLS identity is forbidden even when both are pinned.
    buyer_key = SoftwareSigner(
        serialization.load_pem_private_key(
            (
                Path(acceptance.manifest["nodes"]["buyer"]["root"])
                / "private"
                / "signing.pem"
            ).read_bytes(),
            password=None,
        )
    )
    mismatch = envelope(buyer_key, "buyer", "agent", "ask", acceptance.trade_id, body)
    reject(send(peer, mismatch, ctx), "certificate_sender_mismatch")
    results["tls_sender_binding"] = True
    settle = {"execution_id": uuid4().hex, "terms_hash": digest(acceptance.ticket)}
    reject(call("buyer", "agent", "settle.execute", settle), "action_not_permitted")
    results["non_seller_settlement_refused"] = True
    reject(
        call("seller", "agent", "settle.execute", settle),
        "settlement_preconditions_failed",
    )
    results["settlement_without_approvals_refused"] = True
    ssi = copy.deepcopy(acceptance.books["buyer"]["own_ssi"])
    ssi["aba"] = "021000022"
    reject(
        call(
            "buyer",
            "agent",
            "ssi.update",
            {"execution_id": uuid4().hex, "ssi": ssi, "approval": {}},
        ),
        "invalid_action_body",
    )
    results["bad_aba_refused"] = True
    reject(
        call(
            "buyer",
            "agent",
            "kyc.release",
            {
                "execution_id": uuid4().hex,
                "documents": {"identity": "aGVsbG8="},
                "hashes": {},
                "approval": {},
            },
        ),
        "kyc_documents_missing",
    )
    results["missing_kyc_document_refused"] = True
    return results


def verify_received_signatures(acceptance):
    manifest = acceptance.manifest
    count = 0
    approval_count = 0
    from certify.provision import ROLES

    for role in ROLES:
        audit = acceptance.admin(role).call("local.audit")
        for entry in audit["entries"]:
            msg = entry.get("envelope")
            if not msg:
                continue
            sender = msg.get("from")
            if sender not in ROLES:
                continue
            key = base64.b64decode(manifest["nodes"][sender]["bundle"]["signing_key"])
            # Negative security-test envelopes were intentionally invalid; only dispatched
            # inbound audit entries and successful outbound envelopes need validate.
            if entry["type"] == "envelope.rejected":
                continue
            try:
                verify(key, {k: v for k, v in msg.items() if k != "sig"}, msg["sig"])
            except InvalidSignature:
                # Transport records rejected input by hash only; no accepted message may fail.
                raise AssertionError("accepted envelope signature invalid")
            count += 1
            answer = msg.get("body", {}).get("answer", {})
            if (
                msg["type"] == "answer"
                and isinstance(answer, dict)
                and "question" in answer
            ):
                verify(
                    key, {k: v for k, v in answer.items() if k != "sig"}, answer["sig"]
                )
                modified = copy.deepcopy(answer)
                modified["result"] = {"tampered": True}
                try:
                    verify(
                        key,
                        {k: v for k, v in modified.items() if k != "sig"},
                        modified["sig"],
                    )
                except InvalidSignature:
                    pass
                else:
                    raise AssertionError("tampered answer verified")
            if msg["type"] == "settle.receipt":
                altered = copy.deepcopy(msg)
                altered["body"]["amount"] += 1
                try:
                    verify(
                        key,
                        {k: v for k, v in altered.items() if k != "sig"},
                        altered["sig"],
                    )
                except InvalidSignature:
                    pass
                else:
                    raise AssertionError("tampered receipt verified")
            # Approval records are also verified independently with the officer pins.
            body = msg.get("body", {})
            records = []
            if isinstance(body.get("approval"), dict):
                records.append(body["approval"])
            if isinstance(body.get("approvals"), list):
                records.extend(body["approvals"])
            for record in records:
                officer_id = record.get("signed", {}).get("officer_id")
                if not officer_id:
                    continue
                officer = manifest["officers"][officer_id]
                signer = SoftwareSigner(
                    serialization.load_pem_private_key(
                        Path(officer["signing_key"]).read_bytes(), password=None
                    )
                )
                verify(signer.public_key, record["signed"], record["signature"])
                approval_count += 1
    return {
        "verified_node_envelopes": count,
        "verified_officer_approvals": approval_count,
        "tampered_receipt_refused": True,
        "tampered_answer_refused": True,
    }


def double_settlement(acceptance):
    audit = acceptance.admin("seller").call("local.audit")
    original = next(
        e["envelope"]
        for e in audit["entries"]
        if e.get("envelope", {}).get("type") == "settle.execute"
        and e["direction"] == "out"
    )
    peer, ctx, signer, msg = peer_message(
        acceptance, "seller", "agent", "settle.execute", original["body"]
    )
    assert (
        send(peer, msg, ctx)["type"] == "answer"
    )  # Original execution result, no second effect.
    changed = copy.deepcopy(original["body"])
    changed["terms_hash"] = "0" * 64
    peer, ctx, signer, msg = peer_message(
        acceptance, "seller", "agent", "settle.execute", changed
    )
    reject(send(peer, msg, ctx), "execution_id_conflict")
    changed = copy.deepcopy(original["body"])
    changed["execution_id"] = uuid4().hex
    peer, ctx, signer, msg = peer_message(
        acceptance, "seller", "agent", "settle.execute", changed
    )
    response = send(peer, msg, ctx)
    assert response["type"] == "error" and response["body"]["error"] in [
        "trade_stopped",
        "already_settled",
    ]
    books = acceptance.admin("agent").call("local.books")
    assert books["register"]["FAC-ATLAS-01"] == {
        "Meridian Capital": 150_000_000_000,
        "Northstar Bank": 150_000_000_000,
    }
    return {
        "same_execution_returns_original_result": True,
        "execution_payload_conflict_refused": True,
        "second_settlement_refused": True,
    }
