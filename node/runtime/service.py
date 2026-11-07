"""Role-isolated settlement state machine.

No method opens another institution's store. Cross-node effects are durable signed
messages; inbound business effects and the execution ledger commit atomically.
"""

import base64
import copy
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from node.adapters.models import Ssi, TradeInput, business_day, purchase_price
from node.audit.store import Store, now
from node.identity.crypto import digest, fingerprint, verify
from node.payments.iso20022 import execution_ref
from node.runtime.messages import ROUTES, SCHEMAS, TASK_ROLES, Ticket
from node.runtime.vault import Vault
from node.transport.client import send
from node.transport.protocol import (
    Peer,
    ProtocolError,
    Transport,
    envelope,
    tls_context,
)


class Node:
    def __init__(self, settings):
        self.cfg = settings
        self.id = settings.node_id
        self.role = settings.role
        self.store = Store(
            settings.database_url(), initialize=settings.mode == "certification"
        )
        with self.store.transaction() as tx:
            identity = {
                "node_id": settings.node_id,
                "role": settings.role,
                "public_key": settings.public_signing_key,
            }
            existing = self.store.get(tx, "node:identity")
            if not existing:
                from sqlalchemy import func, select

                from node.audit.store import AuditEntry, Record

                if tx.scalar(select(func.count()).select_from(Record)) or tx.scalar(
                    select(func.count()).select_from(AuditEntry)
                ):
                    raise ValueError(
                        "unbound database is not empty; approved migration required"
                    )
            if existing and existing != identity:
                raise ValueError("database belongs to another node identity")
            self.store.put(tx, "node:identity", "metadata", identity)
        self.signer = settings.signer()
        self.vault = Vault(
            base64.b64decode(os.environ[settings.field_key_env], validate=True)
        )
        self.agreement = serialization.load_pem_private_key(
            Path(settings.agreement_key).read_bytes(), password=None
        )
        from node.identity.crypto import public_bytes

        if public_bytes(self.agreement.public_key()) != base64.b64decode(
            settings.public_agreement_key
        ):
            raise ValueError("agreement key mismatch")
        challenge = {
            "purpose": "startup-possession-proof",
            "node_id": self.id,
            "nonce": uuid4().hex,
        }
        verify(self.signer.public_key, challenge, self.signer.sign(challenge))
        self.peers = {p.node_id: p for p in settings.peers}
        self.officers = {o.officer_id: o for o in settings.officers}
        self.roles = {p.role: p.node_id for p in settings.peers} | {self.role: self.id}
        self.catalog_policy = None
        if settings.catalog_file:
            import yaml

            with Path(settings.catalog_file).open() as policy_stream:
                self.catalog_policy = yaml.safe_load(policy_stream)
            known = {
                "lender_holds_at_least",
                "my_register_position_matches",
                "assignment_eligible",
                "consent_requirements",
                "lender_kyc_cleared",
                "my_ssi_matches",
                "consent_status",
                "funds_available",
                "relationship_to_borrower",
                "position_free_to_sell",
            }
            if (
                not isinstance(self.catalog_policy, dict)
                or set(self.catalog_policy.get("questions", {})) - known
            ):
                raise ValueError("free-form catalog questions forbidden")
            for question, rule in self.catalog_policy["questions"].items():
                answerer = (
                    "buyer"
                    if question in ["funds_available", "relationship_to_borrower"]
                    else "seller"
                    if question == "position_free_to_sell"
                    else "agent"
                )
                allowed = (
                    {"seller"}
                    if question == "funds_available"
                    else {"seller", "agent"}
                    if question == "relationship_to_borrower"
                    else set()
                    if question == "position_free_to_sell"
                    else {"seller", "buyer"}
                )
                if rule.get("answerer") != answerer or not set(
                    rule.get("allowed", [])
                ).issubset(allowed):
                    raise ValueError("catalog policy cannot widen permissions")
        self.bank_auth = None
        if settings.oidc:
            from node.approvals.oidc import BankOidc

            auth = settings.oidc
            self.bank_auth = BankOidc(
                auth.issuer, auth.audience, auth.jwks_file, auth.subjects
            )
        self.template = Path(settings.document_template).read_text()
        if settings.mode == "production" and (
            "REFERENCE TEMPLATE" in self.template or not self.template.strip()
        ):
            raise ValueError("bank-approved legal template required")
        self.context = tls_context(
            settings.certificate,
            settings.tls_key,
            [p.certificate_path for p in settings.peers],
            server=False,
        )
        self.transport = Transport(
            self.id, self.signer, self.store, self.peers, self.receive
        )
        self.transport.audit_encoder = self.encode_audit
        officer_peers = {
            o.officer_id: Peer(
                node_id=o.officer_id,
                legal_name=o.name,
                lei=settings.lei,
                role="officer",
                signing_key=o.signing_key,
                agreement_key=base64.b64encode(b"\0" * 32).decode(),
                certificate_sha256=o.certificate_sha256,
                certificate_path=o.certificate_path,
                endpoint="https://localhost",
            )
            for o in settings.officers
        }
        self.local_transport = Transport(
            self.id, self.signer, self.store, officer_peers, self.local
        )
        self.local_transport.audit_encoder = self.encode_audit
        self.pool = ThreadPoolExecutor(
            max_workers=16, thread_name_prefix=self.id + "-outbound"
        )
        self._claim_recovery()

    def encode_audit(self, raw):
        # Audit remains verifiable while raw documents/account details are encrypted at rest.
        if "access_token" in raw.get("body", {}):
            return {
                "type": raw.get("type"),
                "from": raw.get("from"),
                "to": raw.get("to"),
                "payload_hash": digest(raw),
                "credentials_redacted": True,
            }
        answer = raw.get("body", {}).get("answer", {})
        if (
            raw.get("type") == "answer"
            and isinstance(answer, dict)
            and any(k in answer for k in ["entries", "trades", "positions", "register"])
        ):
            # Local read responses are hash-anchored, never recursively embedded into the next export.
            return {
                "type": "local.read_response",
                "from": raw.get("from"),
                "to": raw.get("to"),
                "payload_hash": digest(raw),
            }
        return {
            "type": raw.get("type"),
            "from": raw.get("from"),
            "to": raw.get("to"),
            "trade_id": raw.get("trade_id"),
            "payload_hash": digest(raw),
            "sealed": self.vault.seal("audit", raw),
        }

    def bank(self, s, key, default=None):
        row = self.store.get(s, "bank:" + key)
        return self.vault.open("bank:" + key, row) if row else copy.deepcopy(default)

    def put_bank(self, s, key, value):
        self.store.put(s, "bank:" + key, "bank", self.vault.seal("bank:" + key, value))

    def trade(self, s, trade_id):
        t = self.store.get(s, "trade:" + trade_id)
        if not t:
            raise ProtocolError("trade_not_found", 404)
        return t

    def save(self, s, t):
        self.store.put(s, "trade:" + t["trade_id"], "trade", t)

    def event(self, s, t, kind, details=None):
        event = {
            "trade_id": t["trade_id"],
            "ts": now(),
            "type": kind,
            "actor": self.id,
            "payload_hash": digest(details or {}),
        }
        previous = t.get("timer_ts", event["ts"])
        elapsed = max(
            0,
            int(
                (
                    datetime.fromisoformat(event["ts"])
                    - datetime.fromisoformat(previous)
                ).total_seconds()
                * 1000
            ),
        )
        mode = t.get("timer_mode", "machine")
        t[mode + "_ms"] = t.get(mode + "_ms", 0) + elapsed
        event["machine_ms"] = elapsed if mode == "machine" else 0
        event["human_ms"] = elapsed if mode == "human" else 0
        event["external_ms"] = elapsed if mode == "external" else 0
        t["timer_ts"] = event["ts"]
        t["timer_mode"] = (
            "human"
            if any(task["status"] == "pending" for task in t["tasks"])
            else "external"
            if t["state"] in ["FUNDING_SENT", "PAYMENT_PENDING"]
            else "machine"
        )
        t.setdefault("events", []).append(event)
        self.store.put(s, "event:" + uuid4().hex, "trade_events", event)
        self.store.audit(s, "trade.event", event)

    def fresh_trade(self, trade_id, ticket=None, public_terms=None):
        return {
            "trade_id": trade_id,
            "state": "PROPOSED",
            "ticket": ticket,
            "public_terms": public_terms,
            "tasks": [],
            "events": [],
            "facts": {
                "affirmed": False,
                "kyc": False,
                "ssi": False,
                "agent_consent": False,
                "borrower_consent": False,
                "docs": {},
                "ready": False,
                "funding_sent": False,
                "funds_received": False,
                "settle_requested": False,
            },
            "receipt": None,
            "acks": [],
        }

    def validate_ticket(self, ticket):
        ticket = Ticket.model_validate(ticket).model_dump()
        if ticket["participants"] != self.roles:
            raise ProtocolError("participant_registry_mismatch")
        terms = ticket["terms"]
        seller = self.peers.get(self.roles["seller"])
        buyer = self.peers.get(self.roles["buyer"])
        seller_name = seller.legal_name if seller else self.cfg.legal_name
        buyer_name = buyer.legal_name if buyer else self.cfg.legal_name
        if terms["seller"] != seller_name or terms["buyer"] != buyer_name:
            raise ProtocolError("legal_identity_mismatch")
        if (
            not business_day(date.fromisoformat(terms["settlement_date"]))
            or terms["settlement_date"] < terms["trade_date"]
        ):
            raise ProtocolError("invalid_settlement_date")
        return ticket

    def terms(self, t):
        return t["ticket"]["terms"]

    def value(self, t):
        return purchase_price(self.terms(t)["amount"], self.terms(t)["price"])

    def enqueue(self, s, t, target, kind, body, execution_id=None):
        if (
            kind not in ROUTES
            or self.role not in ROUTES[kind][0]
            or self.peers[target].role not in ROUTES[kind][1]
        ):
            raise ProtocolError("outbound_action_not_permitted")
        body = {"execution_id": execution_id or uuid4().hex, **body}
        SCHEMAS[kind].model_validate(body)
        key = "outbox:" + target + ":" + body["execution_id"]
        existing = self.store.get(s, key)
        if existing:
            if existing["body_hash"] != digest(body):
                raise ProtocolError("execution_id_conflict", 409)
            return
        row = {
            "key": key,
            "to": target,
            "type": kind,
            "trade_id": t["trade_id"],
            "body_hash": digest(body),
            "payload": self.vault.seal(key, body),
            "state": "PENDING",
            "created_at": now(),
        }
        self.store.put(s, key, "outbox", row)
        self.event(
            s,
            t,
            "message.queued",
            {"to": target, "type": kind, "execution_id": body["execution_id"]},
        )

    def task(self, s, t, action, payload):
        binding = {
            "trade_id": t["trade_id"],
            "action": action,
            "payload_hash": digest(payload),
            "terms_hash": digest(t.get("ticket") or t["public_terms"]),
        }
        key = digest(binding)
        if any(x["what_hash"] == key for x in t["tasks"]):
            return
        task = {
            "task_id": uuid4().hex,
            "action": action,
            "what_hash": key,
            "binding": binding,
            "payload": self.vault.seal("task:" + key, payload),
            "status": "pending",
            "approvals": [],
            "required_roles": TASK_ROLES[action],
            "created_at": now(),
        }
        t["tasks"].append(task)
        self.event(s, t, "task.created", binding)

    def payload(self, task):
        return self.vault.open("task:" + task["what_hash"], task["payload"])

    def approval(self, record, action, trade_id, payload, expected_role):
        # A remote node trusts only the signing key pins in the named institution's bundle.
        signed = record.get("signed", {})
        officer_id = signed.get("officer_id")
        if (
            signed.get("trade_id") != trade_id
            or signed.get("action") != action
            or signed.get("payload_hash") != digest(payload)
            or signed.get("decision") != "approve"
        ):
            raise ProtocolError("approval_binding_invalid")
        if expected_role == self.role:
            officer = self.officers.get(officer_id)
            key = officer.signing_key if officer else None
            roles = officer.roles if officer else []
        else:
            # Public officer registrations are provisioned into bank-approved peer registries.
            registry = self.cfg.peer_officers
            officer = registry.get(self.roles[expected_role], {}).get(officer_id, {})
            key = officer.get("signing_key")
            roles = officer.get("roles", [])
        if not key or not any(r in roles for r in TASK_ROLES[action]):
            raise ProtocolError("officer_not_authorized")
        try:
            verify(base64.b64decode(key, validate=True), signed, record["signature"])
        except Exception:
            raise ProtocolError("approval_signature_invalid")
        return officer_id

    def check_approvals(self, records, action, t, payload, role):
        if len(records) != len(TASK_ROLES[action]):
            raise ProtocolError("approvals_missing")
        ids = [self.approval(r, action, t["trade_id"], payload, role) for r in records]
        if len(set(ids)) != len(ids):
            raise ProtocolError("dual_control_requires_distinct_officers")

    def receive(self, peer, message):
        kind = message.type
        if kind not in SCHEMAS:
            raise ProtocolError("action_not_permitted")
        try:
            body = SCHEMAS[kind].model_validate(message.body).model_dump()
        except ValidationError:
            raise ProtocolError("invalid_action_body", 400)
        if kind == "execution.status":
            with self.store.transaction() as s:
                row = self.store.get(
                    s, "inbox:" + peer.node_id + ":" + body["execution_id"]
                )
                if row and row["body_hash"] != body["body_hash"]:
                    raise ProtocolError("execution_id_conflict", 409)
                return {"found": bool(row), "result": row["result"] if row else None}
        if kind == "ask":
            return self.ask(peer, message.trade_id, body)
        allowed = ROUTES[kind]
        if (
            peer.role not in allowed[0]
            or self.role not in allowed[1]
            or self.roles.get(peer.role) != peer.node_id
        ):
            raise ProtocolError("action_not_permitted")
        key = "inbox:" + peer.node_id + ":" + body["execution_id"]
        with self.store.transaction() as s:
            row = self.store.get(s, key)
            if row:
                if (
                    row["body_hash"] != digest(body)
                    or row["type"] != kind
                    or row["trade_id"] != message.trade_id
                ):
                    raise ProtocolError("execution_id_conflict", 409)
                return row["result"]
            result = self.apply(s, peer, message.trade_id, kind, body)
            self.store.put(
                s,
                key,
                "inbox",
                {
                    "body_hash": digest(body),
                    "type": kind,
                    "trade_id": message.trade_id,
                    "result": result,
                },
            )
            return result

    def apply(self, s, peer, trade_id, kind, body):
        if kind == "trade.propose":
            if self.store.get(s, "trade:" + trade_id):
                raise ProtocolError("duplicate_trade", 409)
            ticket = self.validate_ticket(body["ticket"])
            if ticket["terms"]["trade_id"] != trade_id:
                raise ProtocolError("trade_id_mismatch")
            self.approval(
                body["approval"],
                "trade.propose",
                trade_id,
                {"ticket": ticket},
                "seller",
            )
            t = self.fresh_trade(trade_id, ticket)
            self.event(s, t, "trade.received")
            if self.role == "buyer":
                if self.bank(s, "booked_trades", {}).get(trade_id) != ticket["terms"]:
                    t["state"] = "TRADE_BREAK"
                    self.event(s, t, "trade.break")
                    for role in ["seller", "agent"]:
                        self.enqueue(
                            s,
                            t,
                            self.roles[role],
                            "trade.break",
                            {"reason": "booked_trade_mismatch"},
                        )
                else:
                    t["facts"]["affirmed"] = True
                    t["readiness_dirty"] = True
                    t["state"] = "AFFIRMED"
                    for role in ["seller", "agent"]:
                        self.enqueue(
                            s,
                            t,
                            self.roles[role],
                            "trade.affirm",
                            {"terms_hash": digest(ticket)},
                        )
        else:
            if kind == "consent.request" and not self.store.get(s, "trade:" + trade_id):
                terms = body["terms"]
                if (
                    set(terms)
                    != {
                        "trade_id",
                        "facility_id",
                        "amount",
                        "seller",
                        "buyer",
                        "settlement_date",
                    }
                    or terms["trade_id"] != trade_id
                ):
                    raise ProtocolError("invalid_borrower_terms")
                t = self.fresh_trade(trade_id, public_terms=terms)
            else:
                t = self.trade(s, trade_id)
            if t["state"] in [
                "DECLINED",
                "HARD_STOP",
                "TRADE_BREAK",
                "CANCELLED",
                "SETTLED",
                "CLOSED",
            ] and kind not in ["settle.receipt", "receipt.ack"]:
                raise ProtocolError("trade_stopped", 409)
            f = t["facts"]
            if kind == "trade.break":
                t["state"] = "TRADE_BREAK"
                t["break_reason"] = body["reason"]
            elif kind == "consent.status":
                if body["status"] != "DECLINED":
                    raise ProtocolError("invalid_consent_status")
                t["state"] = "DECLINED"
            elif kind == "trade.affirm":
                if body["terms_hash"] != digest(t["ticket"]):
                    raise ProtocolError("affirmation_mismatch")
                f["affirmed"] = True
                if self.role == "seller":
                    t["readiness_dirty"] = True
                t["state"] = "CHECKING"
                if self.role == "agent":
                    self.open_gaps(s, t)
            elif kind == "kyc.request_package":
                if not set(body["types"]).issubset(self.cfg.required_kyc_documents):
                    raise ProtocolError("kyc_document_not_permitted")
                documents = self.bank(s, "kyc_documents", {})
                if not set(body["types"]).issubset(documents):
                    raise ProtocolError("kyc_documents_missing")
                package = {k: documents[k] for k in body["types"]}
                self.task(
                    s,
                    t,
                    "kyc.release",
                    {
                        "types": sorted(body["types"]),
                        "hashes": {
                            k: hashlib.sha256(
                                base64.b64decode(v, validate=True)
                            ).hexdigest()
                            for k, v in package.items()
                        },
                        "to": peer.node_id,
                    },
                )
                t["requested_kyc"] = body["types"]
                t["state"] = "GAPS_OPEN"
            elif kind == "kyc.release":
                if set(body["documents"]) != set(self.cfg.required_kyc_documents):
                    raise ProtocolError("kyc_documents_missing")
                hashes = {
                    k: hashlib.sha256(base64.b64decode(v, validate=True)).hexdigest()
                    for k, v in body["documents"].items()
                }
                if hashes != body["hashes"]:
                    raise ProtocolError("kyc_document_hash_mismatch")
                payload = {
                    "types": sorted(body["documents"]),
                    "hashes": hashes,
                    "to": self.id,
                }
                self.approval(
                    body["approval"], "kyc.release", trade_id, payload, "buyer"
                )
                self.put_bank(s, "kyc_package:" + trade_id, body["documents"])
                t["kyc_release"] = body["approval"]
                self.task(
                    s,
                    t,
                    "kyc.clear",
                    {"hashes": hashes, "lender": self.terms(t)["buyer"]},
                )
            elif kind == "kyc.clear":
                if body["status"] != "cleared":
                    raise ProtocolError("invalid_kyc_status")
                f["kyc"] = True
                t["readiness_dirty"] = True
            elif kind == "ssi.update":
                ssi = Ssi.model_validate(body["ssi"]).model_dump()
                if ssi["owner_legal_name"] != peer.legal_name:
                    raise ProtocolError("ssi_owner_mismatch")
                payload = {"ssi_hash": digest(ssi), "to": self.id}
                self.approval(
                    body["approval"], "ssi.release", trade_id, payload, peer.role
                )
                self.put_bank(s, "ssi_pending:" + trade_id, ssi)
                t["ssi_release"] = body["approval"]
                self.task(
                    s,
                    t,
                    "ssi.accept",
                    {"ssi_hash": digest(ssi), "lender": peer.legal_name},
                )
            elif kind == "ssi.confirm":
                if body["status"] != "updated":
                    raise ProtocolError("invalid_ssi_status")
                f["ssi"] = True
                t["readiness_dirty"] = True
            elif kind == "consent.request":
                terms = body["terms"]
                blocked = self.bank(s, "blocked_list", [])
                t["consent_due_at"] = body["due_at"]
                if terms["buyer"] in blocked:
                    t["state"] = "DECLINED"
                    self.enqueue(
                        s,
                        t,
                        self.roles["agent"],
                        "consent.borrower",
                        {"status": "DECLINED", "approvals": []},
                    )
                else:
                    t["state"] = "CONSENTS_PENDING"
                    self.task(s, t, "consent.borrower", {"terms": terms})
            elif kind == "consent.borrower":
                if body["status"] == "DECLINED":
                    t["state"] = "DECLINED"
                    for role in ["seller", "buyer"]:
                        self.enqueue(
                            s,
                            t,
                            self.roles[role],
                            "consent.status",
                            {"status": "DECLINED", "approvals": body["approvals"]},
                        )
                else:
                    payload = {"terms": self.public_terms(t)}
                    self.check_approvals(
                        body["approvals"], "consent.borrower", t, payload, "borrower"
                    )
                    f["borrower_consent"] = True
                    t["borrower_approvals"] = body["approvals"]
                    self.advance_agent(s, t)
            elif kind == "consent.agent":
                f["agent_consent"] = body["status"] == "CONSENTED"
            elif kind == "doc.request":
                ticket = self.validate_ticket(body["ticket"])
                if (
                    ticket != t["ticket"]
                    or self.bank(s, "booked_trades", {}).get(trade_id)
                    != ticket["terms"]
                ):
                    raise ProtocolError("document_trade_mismatch")
                expected = self.document(t)
                if body["text"] != expected or body["document_hash"] != digest(
                    {"text": expected}
                ):
                    raise ProtocolError("document_terms_mismatch")
                t["document_hash"] = body["document_hash"]
                self.task(
                    s,
                    t,
                    "doc.sign",
                    {"document_hash": body["document_hash"], "text": body["text"]},
                )
                t["state"] = "DOCS_PENDING"
            elif kind == "doc.sign":
                if body["document_hash"] != t.get("document_hash"):
                    raise ProtocolError("document_hash_mismatch")
                payload = {
                    "document_hash": t["document_hash"],
                    "text": self.document(t),
                }
                self.approval(
                    body["approval"], "doc.sign", trade_id, payload, peer.role
                )
                f["docs"][peer.role] = body["approval"]
                self.advance_agent(s, t)
            elif kind == "trade.ready":
                if body["terms_hash"] != digest(t["ticket"]) or body[
                    "document_hash"
                ] != t.get("document_hash"):
                    raise ProtocolError("readiness_mismatch")
                f["ready"] = True
                t["state"] = "READY_TO_SETTLE"
                if self.role == "seller":
                    self.enqueue(
                        s,
                        t,
                        self.roles["buyer"],
                        "funding.request",
                        {"terms_hash": digest(t["ticket"])},
                    )
                elif t.get("funding_requested"):
                    self.task(
                        s,
                        t,
                        "funding.release",
                        {
                            "purchase_price": self.value(t),
                            "agent": self.roles["agent"],
                            "terms_hash": digest(t["ticket"]),
                        },
                    )
            elif kind == "funding.request":
                if body["terms_hash"] != digest(t["ticket"]):
                    raise ProtocolError("funding_terms_mismatch")
                t["funding_requested"] = True
                if f["ready"]:
                    self.task(
                        s,
                        t,
                        "funding.release",
                        {
                            "purchase_price": self.value(t),
                            "agent": self.roles["agent"],
                            "terms_hash": digest(t["ticket"]),
                        },
                    )
            elif kind == "funding.release":
                self.approval(
                    body["approval"],
                    "funding.release",
                    trade_id,
                    {
                        "purchase_price": self.value(t),
                        "agent": self.id,
                        "terms_hash": digest(t["ticket"]),
                    },
                    "buyer",
                )
                if (
                    t.get("funding_payment_id")
                    and t["funding_payment_id"] != body["payment_id"]
                ):
                    raise ProtocolError("funding_execution_conflict")
                t["funding_payment_id"] = body["payment_id"]
                t["funding_approval"] = body["approval"]
                f["funding_sent"] = True
                self.match_pending_credit(s, t)
            elif kind == "settle.execute":
                if body["terms_hash"] != digest(t["ticket"]):
                    raise ProtocolError("settlement_terms_mismatch")
                if t["state"] in ["SETTLED", "CLOSED"]:
                    raise ProtocolError("already_settled", 409)
                if not (
                    f["ready"]
                    and f["kyc"]
                    and f["ssi"]
                    and f["funds_received"]
                    and set(f["docs"]) == {"seller", "buyer", "agent"}
                ):
                    raise ProtocolError("settlement_preconditions_failed")
                f["settle_requested"] = True
                if f["funds_received"]:
                    self.task(
                        s,
                        t,
                        "settle.execute",
                        {
                            "terms_hash": digest(t["ticket"]),
                            "document_hash": t["document_hash"],
                        },
                    )
            elif kind == "settle.receipt":
                self.apply_receipt(s, t, body)
                self.enqueue(
                    s,
                    t,
                    self.roles["agent"],
                    "receipt.ack",
                    {"receipt_id": body["receipt_id"]},
                )
            elif kind == "receipt.ack":
                if not t["receipt"] or body["receipt_id"] != t["receipt"]["receipt_id"]:
                    raise ProtocolError("receipt_mismatch")
                if peer.role not in t["acks"]:
                    t["acks"].append(peer.role)
                if set(t["acks"]) == {"seller", "buyer", "borrower"}:
                    t["state"] = "CLOSED"
            else:
                raise ProtocolError("action_not_implemented")
            self.event(s, t, "action." + kind, {"from": peer.node_id})
        self.save(s, t)
        return {"accepted": True, "trade_id": trade_id, "state": t["state"]}

    def public_terms(self, t):
        terms = self.terms(t)
        return {
            k: terms[k]
            for k in [
                "trade_id",
                "facility_id",
                "amount",
                "seller",
                "buyer",
                "settlement_date",
            ]
        }

    def document(self, t):
        from string import Template

        return Template(self.template).substitute(**self.terms(t))

    def open_gaps(self, s, t):
        self.hard_checks(s, t)
        if t["state"] == "HARD_STOP":
            return
        f = t["facts"]
        terms = self.terms(t)
        f["kyc"] = (
            self.bank(s, "kyc", {}).get(terms["buyer"], {}).get("status") == "cleared"
        )
        if not f["kyc"]:
            self.enqueue(
                s,
                t,
                self.roles["buyer"],
                "kyc.request_package",
                {"types": self.cfg.required_kyc_documents},
            )
        # SSI equality must be established by a signed question; mismatch creates a lender task.
        t["state"] = "GAPS_OPEN"
        self.event(s, t, "checks.started")

    def hard_checks(self, s, t):
        terms = self.terms(t)
        facility = self.bank(s, "facilities", {}).get(terms["facility_id"])
        if not facility:
            raise ProtocolError("unknown_facility")
        positions = self.bank(s, "register", {}).get(terms["facility_id"], {})
        reasons = []
        if facility.get("type") != "term_loan" or facility.get("currency") != "USD":
            reasons.append("unsupported_facility")
        if positions.get(terms["seller"], 0) < terms["amount"]:
            reasons.append("seller_position_insufficient")
        if (
            terms["amount"] < facility["min_assignment"]
            or terms["amount"] % facility["assignment_multiple"]
        ):
            reasons.append("assignment_amount_invalid")
        if terms["buyer"] in self.bank(s, "dq", []):
            reasons.append("disqualified_buyer")
        if reasons:
            t["state"] = "HARD_STOP"
            t["hard_stop_reasons"] = reasons
        return not reasons

    def advance_agent(self, s, t):
        if self.role != "agent" or t["state"] in [
            "SETTLED",
            "CLOSED",
            "DECLINED",
            "HARD_STOP",
        ]:
            return
        if not self.hard_checks(s, t):
            return
        f = t["facts"]
        if f["ready"]:
            return
        if not (f["affirmed"] and f["kyc"] and f["ssi"]):
            return
        facility = self.bank(s, "facilities")[self.terms(t)["facility_id"]]
        if not facility["agent_consent_required"]:
            f["agent_consent"] = True
        if not facility["borrower_consent_required"]:
            f["borrower_consent"] = True
        t["state"] = "CONSENTS_PENDING"
        if not f["agent_consent"]:
            self.task(s, t, "consent.agent", {"terms_hash": digest(t["ticket"])})
        if not f["borrower_consent"] and not t.get("borrower_requested"):
            t["borrower_requested"] = True
            due = (
                datetime.now(timezone.utc)
                + timedelta(days=facility.get("consent_window_days", 5))
            ).isoformat()
            self.enqueue(
                s,
                t,
                self.roles["borrower"],
                "consent.request",
                {"terms": self.public_terms(t), "due_at": due},
            )
        if not (f["agent_consent"] and f["borrower_consent"]):
            return
        if not t.get("document_hash"):
            t["document_hash"] = digest({"text": self.document(t)})
            for role in ["seller", "buyer"]:
                self.enqueue(
                    s,
                    t,
                    self.roles[role],
                    "doc.request",
                    {
                        "ticket": t["ticket"],
                        "text": self.document(t),
                        "document_hash": t["document_hash"],
                    },
                )
            self.task(
                s,
                t,
                "doc.sign",
                {"document_hash": t["document_hash"], "text": self.document(t)},
            )
        t["state"] = "DOCS_PENDING"
        if set(f["docs"]) == {"seller", "buyer", "agent"} and not f["ready"]:
            f["ready"] = True
            t["state"] = "READY_TO_SETTLE"
            for role in ["seller", "buyer"]:
                self.enqueue(
                    s,
                    t,
                    self.roles[role],
                    "trade.ready",
                    {
                        "terms_hash": digest(t["ticket"]),
                        "document_hash": t["document_hash"],
                        "approvals_hash": digest(f["docs"]),
                    },
                )
            self.event(s, t, "trade.ready")

    def apply_receipt(self, s, t, body):
        public = t["public_terms"] if self.role == "borrower" else self.public_terms(t)
        for key in ["facility_id", "amount", "seller", "buyer"]:
            if body[key] != public[key]:
                raise ProtocolError("receipt_trade_mismatch")
        if body["effective_date"] != public["settlement_date"]:
            raise ProtocolError("receipt_date_mismatch")
        if self.role != "borrower" and body["document_hash"] != t.get("document_hash"):
            raise ProtocolError("receipt_document_mismatch")
        if t["receipt"]:
            if t["receipt"] != body:
                raise ProtocolError("receipt_conflict")
            return
        if self.role in ["seller", "buyer"]:
            positions = self.bank(s, "positions", {})
            old = positions.get(body["facility_id"], 0)
            delta = -body["amount"] if self.role == "seller" else body["amount"]
            if old + delta < 0:
                raise ProtocolError("own_position_insufficient")
            positions[body["facility_id"]] = old + delta
            self.put_bank(s, "positions", positions)
        t["receipt"] = body
        t["state"] = "SETTLED"
        if self.role == "seller":
            if not t["facts"].get("seller_payment_received"):
                t["state"] = "PAYMENT_PENDING"
        else:
            t["state"] = "CLOSED"
        self.event(s, t, "books.updated")

    def settle(self, s, t):
        f = t["facts"]
        if t["state"] in ["SETTLED", "CLOSED"] or self.store.get(
            s, "settled:" + t["trade_id"]
        ):
            raise ProtocolError("already_settled", 409)
        if not self.hard_checks(s, t):
            raise ProtocolError("position_or_eligibility_changed")
        facility = self.bank(s, "facilities")[self.terms(t)["facility_id"]]
        if not (
            f["affirmed"]
            and f["kyc"]
            and f["ssi"]
            and f["ready"]
            and f["funds_received"]
            and f["settle_requested"]
        ):
            raise ProtocolError("settlement_preconditions_failed")
        if facility["agent_consent_required"] and not f["agent_consent"]:
            raise ProtocolError("agent_consent_missing")
        if facility["borrower_consent_required"] and not f["borrower_consent"]:
            raise ProtocolError("borrower_consent_missing")
        if set(f["docs"]) != {"seller", "buyer", "agent"}:
            raise ProtocolError("document_signatures_missing")
        if facility["agent_consent_required"]:
            self.check_approvals(
                t.get("agent_consent_approvals", []),
                "consent.agent",
                t,
                {"terms_hash": digest(t["ticket"])},
                "agent",
            )
        if facility["borrower_consent_required"]:
            self.check_approvals(
                t.get("borrower_approvals", []),
                "consent.borrower",
                t,
                {"terms": self.public_terms(t)},
                "borrower",
            )
        self.approval(
            t.get("funding_approval", {}),
            "funding.release",
            t["trade_id"],
            {
                "purchase_price": self.value(t),
                "agent": self.id,
                "terms_hash": digest(t["ticket"]),
            },
            "buyer",
        )
        settled_task = next(
            (
                x
                for x in t["tasks"]
                if x["action"] == "settle.execute" and x["status"] == "approved"
            ),
            None,
        )
        if not settled_task:
            raise ProtocolError("settlement_approval_missing")
        self.check_approvals(
            settled_task["approvals"],
            "settle.execute",
            t,
            self.payload(settled_task),
            "agent",
        )
        for role, record in f["docs"].items():
            self.approval(
                record,
                "doc.sign",
                t["trade_id"],
                {"document_hash": t["document_hash"], "text": self.document(t)},
                role,
            )
        if (
            self.bank(s, "kyc", {}).get(self.terms(t)["buyer"], {}).get("status")
            != "cleared"
        ):
            raise ProtocolError("kyc_not_cleared")
        credit = self.bank(s, "credits", {}).get(t["funding_payment_id"])
        agent_ssi = Ssi.model_validate(self.bank(s, "own_ssi"))
        if (
            not credit
            or credit["amount"] != self.value(t)
            or credit["account"] != agent_ssi.account
        ):
            raise ProtocolError("exact_booked_funds_required")
        consumed = self.bank(s, "consumed_credits", {})
        if credit["execution_id"] in consumed:
            raise ProtocolError("credit_already_used")
        consumed[credit["execution_id"]] = t["trade_id"]
        self.put_bank(s, "consumed_credits", consumed)
        terms = self.terms(t)
        register = self.bank(s, "register")
        r = register[terms["facility_id"]]
        total = sum(r.values())
        r[terms["seller"]] -= terms["amount"]
        r[terms["buyer"]] = r.get(terms["buyer"], 0) + terms["amount"]
        if sum(r.values()) != total:
            raise ProtocolError("register_total_changed")
        self.put_bank(s, "register", register)
        receipt = {
            "execution_id": uuid4().hex,
            "receipt_id": uuid4().hex,
            "facility_id": terms["facility_id"],
            "amount": terms["amount"],
            "seller": terms["seller"],
            "buyer": terms["buyer"],
            "effective_date": terms["settlement_date"],
            "document_hash": t["document_hash"],
            "register_total": total,
        }
        t["receipt"] = receipt
        t["state"] = "SETTLED"
        self.store.put(
            s,
            "settled:" + t["trade_id"],
            "settlement",
            {"receipt_id": receipt["receipt_id"], "ts": now()},
        )
        self.payment(
            s,
            t,
            "seller",
            self.bank(s, "ssi_on_file")[terms["seller"]],
            self.value(t),
            execution_ref("disbursement", t["trade_id"]),
        )
        for role in ["seller", "buyer", "borrower"]:
            self.enqueue(s, t, self.roles[role], "settle.receipt", receipt)
        self.event(s, t, "register.updated")
        self.event(s, t, "receipts.queued")

    def payment(self, s, t, creditor, ssi, amount, payment_id):
        Ssi.model_validate(ssi)
        key = "payment:" + payment_id
        if self.store.get(s, key):
            raise ProtocolError("payment_already_exists")
        self.store.put(
            s,
            key,
            "payment",
            {
                "payment_id": payment_id,
                "trade_id": t["trade_id"],
                "creditor": creditor,
                "payload": self.vault.seal(key, {"ssi": ssi, "amount": amount}),
                "state": "PENDING",
                "created_at": now(),
            },
        )

    def match_pending_credit(self, s, t):
        credit = self.bank(s, "credits", {}).get(t.get("funding_payment_id"))
        if not credit:
            return
        if (
            credit["amount"] != self.value(t)
            or credit["account"] != self.bank(s, "own_ssi")["account"]
        ):
            raise ProtocolError("credit_mismatch")
        t["facts"]["funds_received"] = True
        t["state"] = "FUNDS_RECEIVED"
        self.event(s, t, "funds.received")
        if t["facts"]["settle_requested"]:
            self.task(
                s,
                t,
                "settle.execute",
                {
                    "terms_hash": digest(t["ticket"]),
                    "document_hash": t["document_hash"],
                },
            )

    def ingest_credits(self, entries, source_hash):
        # Invoked exclusively from the node's bank-owned file inbox, never by peers.
        with self.store.transaction() as s:
            credits = self.bank(s, "credits", {})
            for credit in entries:
                if credit["account"] != self.bank(s, "own_ssi")["account"]:
                    raise ProtocolError("wrong_credit_account")
                previous = credits.get(credit["execution_id"])
                if previous and previous != credit:
                    raise ProtocolError("credit_id_conflict")
                credits[credit["execution_id"]] = credit
            self.put_bank(s, "credits", credits)
            for t in self.store.list(s, "trade"):
                if (
                    self.role == "agent"
                    and t.get("funding_payment_id")
                    and not t["facts"]["funds_received"]
                ):
                    self.match_pending_credit(s, t)
                    self.save(s, t)
                if self.role == "seller":
                    payment_id = execution_ref("disbursement", t["trade_id"])
                    credit = credits.get(payment_id)
                    if credit:
                        if credit["amount"] != self.value(t):
                            raise ProtocolError("seller_credit_amount_mismatch")
                        t["facts"]["seller_payment_received"] = True
                        self.event(s, t, "seller.payment_reconciled")
                        if t["receipt"]:
                            t["state"] = "CLOSED"
                        self.save(s, t)
            self.store.audit(
                s,
                "payment.credit_ingested",
                {"source_hash": source_hash, "entry_count": len(entries)},
            )

    def ask(self, peer, trade_id, body):
        question = body["question"]
        params = body["params"]
        rules = {
            "lender_holds_at_least": (
                "agent",
                {"seller", "buyer"},
                {"lender", "facility_id", "amount"},
            ),
            "my_register_position_matches": (
                "agent",
                {"seller", "buyer"},
                {"facility_id", "claimed_position"},
            ),
            "assignment_eligible": (
                "agent",
                {"seller", "buyer"},
                {"assignee", "facility_id", "amount"},
            ),
            "consent_requirements": (
                "agent",
                {"seller", "buyer"},
                {"facility_id", "assignee_relationship"},
            ),
            "lender_kyc_cleared": ("agent", {"seller", "buyer"}, {"lender"}),
            "my_ssi_matches": (
                "agent",
                {"seller", "buyer"},
                {"trade_id", "fingerprint"},
            ),
            "consent_status": ("agent", {"seller", "buyer"}, {"trade_id"}),
            "funds_available": ("buyer", {"seller"}, {"purchase_price"}),
            "relationship_to_borrower": ("buyer", {"seller", "agent"}, {"facility_id"}),
        }
        if (
            question not in rules
            or rules[question][0] != self.role
            or peer.role not in rules[question][1]
        ):
            raise ProtocolError("question_not_permitted")
        if self.catalog_policy:
            configured = self.catalog_policy["questions"].get(question)
            if (
                not configured
                or configured.get("disabled")
                or peer.role not in configured.get("allowed", [])
            ):
                raise ProtocolError("question_not_permitted")
            for name, value in params.items():
                if (
                    name in ["amount", "claimed_position", "purchase_price"]
                    and type(value) is int
                    and value > configured.get("max_amount", 2**53 - 1)
                ):
                    raise ProtocolError("parameter_limit_exceeded")
        if set(params) != rules[question][2]:
            raise ProtocolError("invalid_parameters", 400)
        for name, value in params.items():
            if name in ["amount", "claimed_position", "purchase_price"] and (
                type(value) is not int or value < 0 or value > 2**53 - 1
            ):
                raise ProtocolError("invalid_parameters", 400)
            if name not in ["amount", "claimed_position", "purchase_price"] and (
                not isinstance(value, str) or len(value) > 256
            ):
                raise ProtocolError("invalid_parameters", 400)
        with self.store.transaction() as s:
            t = self.trade(s, trade_id)
            if self.role == "agent":
                terms = self.terms(t)
                facility = self.bank(s, "facilities")[terms["facility_id"]]
                if (
                    "facility_id" in params
                    and params["facility_id"] != terms["facility_id"]
                ):
                    raise ProtocolError("facility_scope_mismatch")
                reg = self.bank(s, "register")[terms["facility_id"]]
                if question == "lender_holds_at_least":
                    result = reg.get(params["lender"], 0) >= params["amount"]
                elif question == "my_register_position_matches":
                    result = reg.get(peer.legal_name, 0) == params["claimed_position"]
                elif question == "assignment_eligible":
                    reasons = []
                    if params["assignee"] in self.bank(s, "dq", []):
                        reasons.append("disqualified")
                    if params["amount"] < facility["min_assignment"]:
                        reasons.append("below_minimum")
                    if params["amount"] % facility["assignment_multiple"]:
                        reasons.append("invalid_multiple")
                    result = {"eligible": not reasons, "reasons": reasons}
                elif question == "consent_requirements":
                    result = {
                        "borrower_consent_required": facility[
                            "borrower_consent_required"
                        ]
                        and params["assignee_relationship"]
                        not in facility.get("consent_exempt_assignee_types", []),
                        "agent_consent_required": facility["agent_consent_required"],
                        "assignment_fee": facility.get("assignment_fee", 0),
                    }
                elif question == "lender_kyc_cleared":
                    result = (
                        self.bank(s, "kyc", {}).get(params["lender"], {}).get("status")
                        == "cleared"
                    )
                elif question == "my_ssi_matches":
                    if params["trade_id"] != trade_id:
                        raise ProtocolError("trade_scope_mismatch")
                    ssi = self.bank(s, "ssi_on_file", {}).get(peer.legal_name)
                    match = False
                    if ssi:
                        expected = fingerprint(
                            self.agreement,
                            base64.b64decode(peer.agreement_key),
                            trade_id,
                            ssi,
                        )
                        import hmac

                        match = hmac.compare_digest(expected, params["fingerprint"])
                    result = {"match": match}
                    t.setdefault("ssi_matches", {})[peer.role] = match
                    t["facts"]["ssi"] = all(
                        t["ssi_matches"].get(r, False) for r in ["seller", "buyer"]
                    )
                    self.advance_agent(s, t)
                    self.save(s, t)
                else:
                    if params["trade_id"] != trade_id:
                        raise ProtocolError("trade_scope_mismatch")
                    result = {
                        "agent": "CONSENTED"
                        if t["facts"]["agent_consent"]
                        else "PENDING",
                        "borrower": "CONSENTED"
                        if t["facts"]["borrower_consent"]
                        else "PENDING",
                    }
            elif question == "funds_available":
                result = (
                    self.bank(s, "cash", {"available": 0})["available"]
                    >= params["purchase_price"]
                    or t["facts"]["funding_sent"]
                    and self.value(t) == params["purchase_price"]
                )
            else:
                result = self.bank(s, "relationships", {}).get(
                    params["facility_id"], "none"
                )
        answer = {
            "question": question,
            "params": params,
            "result": result,
            "answered_by": self.id,
            "ts": now(),
            "policy_hash": digest(
                self.catalog_policy
                or {k: [v[0], sorted(v[1]), sorted(v[2])] for k, v in rules.items()}
            ),
        }
        return {**answer, "sig": self.signer.sign(answer)}

    def rpc(self, target, kind, trade_id, body):
        peer = self.peers[target]
        outgoing = envelope(self.signer, self.id, target, kind, trade_id, body)
        with self.store.transaction() as s:
            self.store.audit(
                s, "envelope.send_intent", self.encode_audit(outgoing), "out", target
            )
        response = send(peer, outgoing, self.context)
        with self.store.transaction() as s:
            self.store.audit(
                s, "envelope.response", self.encode_audit(response), "in", target
            )
        if response["type"] == "error":
            raise ProtocolError(response["body"]["error"])
        result = response["body"]["answer"]
        if kind == "ask":
            try:
                verify(
                    base64.b64decode(peer.signing_key),
                    {k: v for k, v in result.items() if k != "sig"},
                    result["sig"],
                )
            except Exception:
                raise ProtocolError("answer_signature_invalid")
            if (
                result["question"] != body["question"]
                or result["params"] != body["params"]
                or result["answered_by"] != target
            ):
                raise ProtocolError("answer_binding_invalid")
        return result

    def readiness(self, trade_id):
        # Nine independently signed remote answers plus a local free-position check.
        if self.role not in ["seller", "buyer"]:
            raise ProtocolError("readiness_lender_required")
        with self.store.transaction() as s:
            t = self.trade(s, trade_id)
            terms = self.terms(t)
            own = self.bank(s, "positions", {}).get(terms["facility_id"], 0)
            own_ssi = self.bank(s, "own_ssi")
            fp = fingerprint(
                self.agreement,
                base64.b64decode(self.peers[self.roles["agent"]].agreement_key),
                trade_id,
                own_ssi,
            )
            free = (
                own - self.bank(s, "pledged", {}).get(terms["facility_id"], 0)
                >= terms["amount"]
                if self.role == "seller"
                else True
            )
        agent = self.roles["agent"]
        questions = [
            (
                agent,
                "lender_holds_at_least",
                {
                    "lender": terms["seller"],
                    "facility_id": terms["facility_id"],
                    "amount": terms["amount"],
                },
            ),
            (
                agent,
                "my_register_position_matches",
                {"facility_id": terms["facility_id"], "claimed_position": own},
            ),
            (
                agent,
                "assignment_eligible",
                {
                    "assignee": terms["buyer"],
                    "facility_id": terms["facility_id"],
                    "amount": terms["amount"],
                },
            ),
            (
                agent,
                "consent_requirements",
                {"facility_id": terms["facility_id"], "assignee_relationship": "none"},
            ),
            (agent, "lender_kyc_cleared", {"lender": terms["buyer"]}),
            (agent, "my_ssi_matches", {"trade_id": trade_id, "fingerprint": fp}),
            (agent, "consent_status", {"trade_id": trade_id}),
        ]
        if self.role == "seller":
            questions += [
                (
                    self.roles["buyer"],
                    "funds_available",
                    {"purchase_price": self.value(t)},
                ),
                (
                    self.roles["buyer"],
                    "relationship_to_borrower",
                    {"facility_id": terms["facility_id"]},
                ),
            ]
        futures = [
            self.pool.submit(
                self.rpc, target, "ask", trade_id, {"question": q, "params": params}
            )
            for target, q, params in questions
        ]
        answers = [f.result() for f in futures]
        with self.store.transaction() as s:
            t = self.trade(s, trade_id)
            t["checks"] = answers
            t["position_free_to_sell"] = free
            if not free or any(
                a["question"]
                in [
                    "lender_holds_at_least",
                    "my_register_position_matches",
                    "funds_available",
                ]
                and a["result"] is False
                or a["question"] == "assignment_eligible"
                and not a["result"]["eligible"]
                for a in answers
            ):
                t["state"] = "HARD_STOP"
                self.event(s, t, "checks.hard_stop")
            elif not next(
                a["result"]["match"]
                for a in answers
                if a["question"] == "my_ssi_matches"
            ):
                self.task(
                    s, t, "ssi.release", {"ssi_hash": digest(own_ssi), "to": agent}
                )
            self.event(s, t, "checks.completed", {"count": len(answers) + 1})
            self.save(s, t)
        return {"checks": answers, "position_free_to_sell": free}

    def local(self, peer, message):
        officer = self.officers[peer.node_id]
        body = dict(message.body)
        kind = message.type
        if self.cfg.mode == "production" and not getattr(
            peer, "bank_authenticated", False
        ):
            if not self.bank_auth:
                raise ProtocolError("bank_authentication_required", 401)
            authenticated = self.bank_auth.authenticate(
                body.pop("access_token", ""),
                step_up=kind
                in [
                    "local.approve",
                    "local.import",
                    "local.trade.create",
                    "local.settle.request",
                    "local.execution.retry",
                ],
            )
            if authenticated != officer.officer_id:
                raise ProtocolError("bank_identity_officer_mismatch")
        if kind == "local.import":
            if "administrator" not in officer.roles:
                raise ProtocolError("administrator_required")
            initialization_approval = body.pop("initialization_approval", None)
            if self.cfg.mode == "production":
                signed = (initialization_approval or {}).get("signed", {})
                if (
                    signed.get("node_id") != self.id
                    or signed.get("officer_id") != officer.officer_id
                    or signed.get("action") != "bank.initialize"
                    or signed.get("body_hash") != digest(body)
                ):
                    raise ProtocolError("initialization_approval_invalid")
                try:
                    verify(
                        base64.b64decode(officer.signing_key),
                        signed,
                        initialization_approval["signature"],
                    )
                except Exception:
                    raise ProtocolError("initialization_signature_invalid")
            allowed = {
                "seller": {"positions", "pledged", "booked_trades", "own_ssi"},
                "buyer": {
                    "positions",
                    "booked_trades",
                    "own_ssi",
                    "kyc_documents",
                    "cash",
                    "relationships",
                    "agent_ssi",
                },
                "agent": {
                    "register",
                    "facilities",
                    "kyc",
                    "ssi_on_file",
                    "own_ssi",
                    "dq",
                },
                "borrower": {"blocked_list"},
            }[self.role]
            if set(body) - allowed:
                raise ProtocolError("foreign_institution_data_forbidden")
            with self.store.transaction() as s:
                if self.store.get(s, "bank:imported"):
                    raise ProtocolError("initial_import_already_completed", 409)
                self.validate_import(body)
                for key, value in body.items():
                    self.put_bank(s, key, value)
                self.store.put(
                    s,
                    "bank:imported",
                    "metadata",
                    {"ts": now(), "officer": officer.officer_id},
                )
                self.store.audit(
                    s,
                    "bank.imported",
                    {
                        "fields": sorted(body),
                        "officer": officer.officer_id,
                        "payload_hash": digest(body),
                        "approval": initialization_approval,
                    },
                )
            return {"imported": True}
        if kind == "local.trade.create":
            if self.role != "seller" or "trader" not in officer.roles:
                raise ProtocolError("seller_trader_required")
            ticket = self.validate_ticket(body["ticket"])
            trade_id = message.trade_id
            if ticket["terms"]["trade_id"] != trade_id:
                raise ProtocolError("trade_id_mismatch")
            with self.store.transaction() as s:
                if self.store.get(s, "trade:" + trade_id):
                    raise ProtocolError("duplicate_trade", 409)
                if self.bank(s, "booked_trades", {}).get(trade_id) != ticket["terms"]:
                    raise ProtocolError("seller_booked_trade_missing")
                if (
                    self.bank(s, "positions", {}).get(ticket["terms"]["facility_id"], 0)
                    - self.bank(s, "pledged", {}).get(ticket["terms"]["facility_id"], 0)
                    < ticket["terms"]["amount"]
                ):
                    raise ProtocolError("position_not_free")
                t = self.fresh_trade(trade_id, ticket)
                t["state"] = "DRAFT"
                self.task(s, t, "trade.propose", {"ticket": ticket})
                self.event(s, t, "trade.created")
                self.save(s, t)
            return {"trade_id": trade_id}
        if kind == "local.approve":
            return self.decide(message.trade_id, body, officer)
        if kind == "local.readiness":
            return self.readiness(message.trade_id)
        if kind == "local.settle.request":
            if self.role != "seller" or "trader" not in officer.roles:
                raise ProtocolError("seller_trader_required")
            self.readiness(message.trade_id)
            with self.store.transaction() as s:
                t = self.trade(s, message.trade_id)
                if not t["facts"]["ready"] or t["state"] == "HARD_STOP":
                    raise ProtocolError("not_ready")
                if t.get("settlement_requested"):
                    raise ProtocolError("settlement_already_requested", 409)
                t["settlement_requested"] = True
                self.enqueue(
                    s,
                    t,
                    self.roles["agent"],
                    "settle.execute",
                    {"terms_hash": digest(t["ticket"])},
                )
                self.save(s, t)
            return {"requested": True}
        if kind == "local.execution.retry":
            if not set(officer.roles) & {"officer", "treasurer", "administrator"}:
                raise ProtocolError("reconciliation_officer_required")
            with self.store.transaction() as s:
                row = self.store.get(s, body["outbox_key"])
                if not row or row["state"] != "NEEDS_RECONCILIATION":
                    raise ProtocolError("reconciliation_not_pending")
                if not str(body.get("reason", "")).strip():
                    raise ProtocolError("retry_reason_required")
                # Keep the exact execution id, target and payload. Receiver ledger prevents
                # a late original request and this retry from creating two effects.
                row["state"] = "PENDING"
                self.store.put(s, row["key"], "outbox", row)
                self.store.audit(
                    s,
                    "execution.manual_retry",
                    {
                        "officer_id": officer.officer_id,
                        "outbox_key": row["key"],
                        "body_hash": row["body_hash"],
                        "reason_hash": digest(body["reason"]),
                    },
                )
            return {"queued": True, "execution_id_preserved": True}
        if kind == "local.reconcile":
            if not set(officer.roles) & {"officer", "administrator", "treasurer"}:
                raise ProtocolError("reconciliation_officer_required")
            return self.reconcile(body["outbox_key"])
        if kind == "local.status":
            with self.store.transaction() as s:
                trades = self.store.list(s, "trade")
                outbox = self.store.list(s, "outbox")
                payments = self.store.list(s, "payment")
                views = []
                for t in trades:
                    view = copy.deepcopy(t)
                    for task in view["tasks"]:
                        task["payload_preview"] = self.payload(task)
                        task.pop("payload")
                    views.append(view)
                return {
                    "node_id": self.id,
                    "role": self.role,
                    "trades": views,
                    "audit_valid": self.store.verify_audit_chain_readonly(s),
                    "outbox": [
                        {
                            "key": r["key"],
                            "state": r["state"],
                            "type": r["type"],
                            "to": r["to"],
                        }
                        for r in outbox
                    ],
                    "payments": [
                        {"payment_id": r["payment_id"], "state": r["state"]}
                        for r in payments
                    ],
                }
        if kind == "local.books":
            if not set(officer.roles) & {"administrator", "auditor"}:
                raise ProtocolError("auditor_required")
            with self.store.transaction() as s:
                return {
                    key: self.bank(s, key)
                    for key in ["positions", "register", "credits", "consumed_credits"]
                    if self.store.get(s, "bank:" + key)
                }
        if kind == "local.audit":
            if not set(officer.roles) & {"administrator", "auditor"}:
                raise ProtocolError("auditor_required")
            with self.store.transaction() as s:
                rows = self.store.audit_rows(s)
                # Local authorized audit view exposes envelope bodies only to this institution's auditor.
                decoded = []
                for row in rows:
                    item = copy.deepcopy(row)
                    if isinstance(row["body"], dict) and "sealed" in row["body"]:
                        item["envelope"] = self.vault.open(
                            "audit", row["body"]["sealed"]
                        )
                    decoded.append(item)
                return {
                    "entries": decoded,
                    "chain_valid": self.store.verify_audit_chain_readonly(s),
                }
        raise ProtocolError("local_command_not_permitted")

    def validate_import(self, body):
        for key in ["own_ssi", "agent_ssi"]:
            if key in body:
                Ssi.model_validate(body[key])
        if (
            "own_ssi" in body
            and body["own_ssi"]["owner_legal_name"] != self.cfg.legal_name
        ):
            raise ProtocolError("own_ssi_identity_mismatch")
        for value in body.get("ssi_on_file", {}).values():
            Ssi.model_validate(value)
        if "cash" in body:
            if (
                set(body["cash"]) != {"available"}
                or type(body["cash"]["available"]) is not int
                or not 0 <= body["cash"]["available"] <= 2**53 - 1
            ):
                raise ProtocolError("invalid_treasury_balance")
        if (
            "agent_ssi" in body
            and body["agent_ssi"]["owner_legal_name"]
            != self.peers[self.roles["agent"]].legal_name
        ):
            raise ProtocolError("agent_ssi_identity_mismatch")
        for owner, ssi in body.get("ssi_on_file", {}).items():
            if ssi["owner_legal_name"] != owner:
                raise ProtocolError("ssi_ledger_owner_mismatch")
        for relationship in body.get("relationships", {}).values():
            if relationship not in [
                "none",
                "existing_lender",
                "affiliate",
                "approved_fund",
            ]:
                raise ProtocolError("invalid_relationship")
        for facility in body.get("facilities", {}).values():
            if facility.get("type") != "term_loan" or facility.get("currency") != "USD":
                raise ProtocolError("unsupported_facility")
            for field in ["assignment_fee", "total_outstanding"]:
                if field in facility and (
                    type(facility[field]) is not int
                    or not 0 <= facility[field] <= 2**53 - 1
                ):
                    raise ProtocolError("invalid_facility_money")
            for amount in [
                facility.get("min_assignment"),
                facility.get("assignment_multiple"),
            ]:
                if type(amount) is not int or not 0 < amount <= 2**53 - 1:
                    raise ProtocolError("invalid_assignment_limits")
            if any(
                type(facility.get(field)) is not bool
                for field in ["agent_consent_required", "borrower_consent_required"]
            ):
                raise ProtocolError("invalid_consent_rules")
        for terms in body.get("booked_trades", {}).values():
            TradeInput.model_validate(terms)
        for amount in body.get("pledged", {}).values():
            if type(amount) is not int or not 0 <= amount <= 2**53 - 1:
                raise ProtocolError("invalid_pledged_position")
        for amount in body.get("positions", {}).values():
            if type(amount) is not int or amount < 0 or amount > 2**53 - 1:
                raise ProtocolError("invalid_position")
        for register in body.get("register", {}).values():
            if any(
                type(amount) is not int or amount < 0 or amount > 2**53 - 1
                for amount in register.values()
            ):
                raise ProtocolError("invalid_register")
        for content in body.get("kyc_documents", {}).values():
            if not base64.b64decode(content, validate=True):
                raise ProtocolError("empty_kyc_document")

    def decide(self, trade_id, body, officer):
        with self.store.transaction() as s:
            t = self.trade(s, trade_id)
            if t["state"] in [
                "SETTLED",
                "CLOSED",
                "DECLINED",
                "HARD_STOP",
                "TRADE_BREAK",
                "CANCELLED",
            ]:
                raise ProtocolError("trade_not_approvable")
            task = next(
                (x for x in t["tasks"] if x["task_id"] == body.get("task_id")), None
            )
            if not task or task["status"] != "pending":
                raise ProtocolError("task_not_pending", 409)
            if any(
                a["signed"]["officer_id"] == officer.officer_id
                for a in task["approvals"]
            ):
                raise ProtocolError("officer_already_approved")
            pending = list(task["required_roles"])
            for record in task["approvals"]:
                roles = self.officers[record["signed"]["officer_id"]].roles
                role = next((r for r in pending if r in roles), None)
                if role:
                    pending.remove(role)
            if not any(r in officer.roles for r in pending):
                raise ProtocolError("officer_role_not_permitted")
            record = body.get("approval", {})
            signed = record.get("signed", {})
            payload = self.payload(task)
            expected = {
                "officer_id": officer.officer_id,
                "trade_id": trade_id,
                "task_id": task["task_id"],
                "action": task["action"],
                "what_hash": task["what_hash"],
                "payload_hash": digest(payload),
            }
            if any(signed.get(k) != v for k, v in expected.items()):
                raise ProtocolError("approval_binding_invalid")
            if (
                signed.get("decision") not in ["approve", "reject"]
                or signed.get("decision") == "reject"
                and not str(signed.get("reason", "")).strip()
            ):
                raise ProtocolError("rejection_reason_required")
            try:
                verify(
                    base64.b64decode(officer.signing_key), signed, record["signature"]
                )
                stamp = datetime.fromisoformat(signed["ts"])
                if abs((datetime.now(timezone.utc) - stamp).total_seconds()) > 120:
                    raise ValueError()
            except Exception:
                raise ProtocolError("officer_signature_or_timestamp_invalid")
            if (
                task["action"] == "ssi.accept"
                and task["approvals"]
                and signed["decision"] == "approve"
                and not str(signed.get("reason", "")).strip()
            ):
                raise ProtocolError("ssi_callback_reference_required")
            task["approvals"].append(record)
            self.store.audit(
                s,
                "officer.approval",
                {
                    "officer_id": officer.officer_id,
                    "trade_id": trade_id,
                    "action": task["action"],
                    "record": record,
                },
            )
            if signed["decision"] == "reject":
                task["status"] = "rejected"
                t["state"] = (
                    "DECLINED" if task["action"] == "consent.borrower" else "CANCELLED"
                )
                if task["action"] == "consent.borrower":
                    self.enqueue(
                        s,
                        t,
                        self.roles["agent"],
                        "consent.borrower",
                        {"status": "DECLINED", "approvals": []},
                    )
            elif len(task["approvals"]) == len(task["required_roles"]):
                task["status"] = "approved"
                self.execute(s, t, task, payload)
            self.event(
                s,
                t,
                "approval." + signed["decision"],
                {"officer_id": officer.officer_id, "action": task["action"]},
            )
            self.save(s, t)
            return {"state": t["state"], "task_status": task["status"]}

    def execute(self, s, t, task, payload):
        action = task["action"]
        records = task["approvals"]
        f = t["facts"]
        self.check_approvals(records, action, t, payload, self.role)
        if action == "trade.propose":
            for role in ["agent", "buyer"]:
                self.enqueue(
                    s,
                    t,
                    self.roles[role],
                    "trade.propose",
                    {"ticket": t["ticket"], "approval": records[0]},
                )
            t["state"] = "PROPOSED"
        elif action == "kyc.release":
            documents = self.bank(s, "kyc_documents")
            package = {k: documents[k] for k in payload["types"]}
            hashes = {
                k: hashlib.sha256(base64.b64decode(v, validate=True)).hexdigest()
                for k, v in package.items()
            }
            if hashes != payload["hashes"]:
                raise ProtocolError("stale_kyc_package")
            self.enqueue(
                s,
                t,
                self.roles["agent"],
                "kyc.release",
                {"documents": package, "hashes": hashes, "approval": records[0]},
            )
        elif action == "kyc.clear":
            package = self.bank(s, "kyc_package:" + t["trade_id"])
            if not package or set(package) != set(self.cfg.required_kyc_documents):
                raise ProtocolError("kyc_documents_missing")
            if {
                k: hashlib.sha256(base64.b64decode(v)).hexdigest()
                for k, v in package.items()
            } != payload["hashes"]:
                raise ProtocolError("kyc_hash_mismatch")
            kyc = self.bank(s, "kyc", {})
            kyc[payload["lender"]] = {
                "status": "cleared",
                "cleared_at": now(),
                "doc_hashes": payload["hashes"],
            }
            self.put_bank(s, "kyc", kyc)
            f["kyc"] = True
            t["kyc_clear_approvals"] = records
            for role in ["seller", "buyer"]:
                self.enqueue(
                    s,
                    t,
                    self.roles[role],
                    "kyc.clear",
                    {"status": "cleared", "approvals": records},
                )
            self.advance_agent(s, t)
        elif action == "ssi.release":
            ssi = self.bank(s, "own_ssi")
            Ssi.model_validate(ssi)
            if digest(ssi) != payload["ssi_hash"]:
                raise ProtocolError("stale_ssi")
            self.enqueue(
                s,
                t,
                self.roles["agent"],
                "ssi.update",
                {"ssi": ssi, "approval": records[0]},
            )
        elif action == "ssi.accept":
            ssi = self.bank(s, "ssi_pending:" + t["trade_id"])
            Ssi.model_validate(ssi)
            if digest(ssi) != payload["ssi_hash"]:
                raise ProtocolError("stale_ssi")
            ssis = self.bank(s, "ssi_on_file", {})
            ssis[payload["lender"]] = ssi
            self.put_bank(s, "ssi_on_file", ssis)
            lender_role = (
                "buyer" if payload["lender"] == self.terms(t)["buyer"] else "seller"
            )
            t.setdefault("ssi_matches", {})[lender_role] = True
            f["ssi"] = all(t["ssi_matches"].get(r, False) for r in ["seller", "buyer"])
            t["ssi_accept_approvals"] = records
            target = (
                self.roles["buyer"]
                if payload["lender"] == self.terms(t)["buyer"]
                else self.roles["seller"]
            )
            self.enqueue(
                s, t, target, "ssi.confirm", {"status": "updated", "approvals": records}
            )
            self.advance_agent(s, t)
        elif action == "consent.agent":
            f["agent_consent"] = True
            t["agent_consent_approvals"] = records
            for role in ["seller", "buyer"]:
                self.enqueue(
                    s,
                    t,
                    self.roles[role],
                    "consent.agent",
                    {"status": "CONSENTED", "approvals": records},
                )
            self.advance_agent(s, t)
        elif action == "consent.borrower":
            f["borrower_consent"] = True
            self.enqueue(
                s,
                t,
                self.roles["agent"],
                "consent.borrower",
                {"status": "CONSENTED", "approvals": records},
            )
        elif action == "doc.sign":
            if digest({"text": self.document(t)}) != payload["document_hash"]:
                raise ProtocolError("document_changed")
            if self.role in ["seller", "buyer"] and self.bank(
                s, "booked_trades", {}
            ).get(t["trade_id"]) != self.terms(t):
                raise ProtocolError("booked_trade_changed")
            f["docs"][self.role] = records[0]
            if self.role == "agent":
                self.advance_agent(s, t)
            else:
                self.enqueue(
                    s,
                    t,
                    self.roles["agent"],
                    "doc.sign",
                    {"document_hash": payload["document_hash"], "approval": records[0]},
                )
        elif action == "funding.release":
            if not f["ready"]:
                raise ProtocolError("not_ready")
            cash = self.bank(s, "cash", {"available": 0})
            if cash["available"] < self.value(t):
                raise ProtocolError("funds_unavailable")
            cash["available"] -= self.value(t)
            self.put_bank(s, "cash", cash)
            payment_id = execution_ref("funding", t["trade_id"])
            self.payment(
                s, t, "agent", self.bank(s, "agent_ssi"), self.value(t), payment_id
            )
            f["funding_sent"] = True
            t["state"] = "FUNDING_SENT"
            self.enqueue(
                s,
                t,
                self.roles["agent"],
                "funding.release",
                {"payment_id": payment_id, "approval": records[0]},
            )
        elif action == "settle.execute":
            self.settle(s, t)
        else:
            raise ProtocolError("local_action_not_implemented")

    def _claim_recovery(self):
        # A crash after the remote commit cannot authorize a new financial execution.
        with self.store.transaction() as s:
            for row in self.store.list(s, "outbox"):
                if row["state"] == "SENDING":
                    row["state"] = "NEEDS_RECONCILIATION"
                    self.store.put(s, row["key"], "outbox", row)
            for payment in self.store.list(s, "payment"):
                if payment["state"] == "EXPORTING":
                    payment["state"] = "NEEDS_RECONCILIATION"
                    self.store.put(
                        s, "payment:" + payment["payment_id"], "payment", payment
                    )

    def dispatch_one(self):
        with self.store.transaction() as s:
            pending = sorted(
                (r for r in self.store.list(s, "outbox") if r["state"] == "PENDING"),
                key=lambda r: (
                    r["created_at"],
                    r["type"] != "trade.propose",
                    r["to"] != self.roles.get("agent"),
                    r["key"],
                ),
            )
            if not pending:
                return False
            row = pending[0]
            row["state"] = "SENDING"
            self.store.put(s, row["key"], "outbox", row)
            body = self.vault.open(row["key"], row["payload"])
        try:
            route = ROUTES.get(row["type"])
            if (
                not route
                or self.role not in route[0]
                or self.peers[row["to"]].role not in route[1]
            ):
                raise ProtocolError("outbound_action_not_permitted")
            if (
                digest(body) != row["body_hash"]
                or row["key"] != "outbox:" + row["to"] + ":" + body["execution_id"]
            ):
                raise ProtocolError("outbox_integrity_failed")
            SCHEMAS[row["type"]].model_validate(body)
            result = self.rpc(row["to"], row["type"], row["trade_id"], body)
            state = "DELIVERED"
        except ProtocolError as error:
            result = {"error": error.code}
            state = "REJECTED"
        except Exception:
            result = {"error": "outcome_unknown"}
            state = "NEEDS_RECONCILIATION"
        with self.store.transaction() as s:
            latest = self.store.get(s, row["key"])
            latest["state"] = state
            latest["result"] = result
            self.store.put(s, row["key"], "outbox", latest)
            if state in ["NEEDS_RECONCILIATION", "REJECTED"]:
                t = self.trade(s, row["trade_id"])
                t["previous_state"] = t["state"]
                t["state"] = "NEEDS_RECONCILIATION"
                self.event(s, t, "message." + state.lower(), {"outbox_key": row["key"]})
                self.save(s, t)
        return True

    def reconcile(self, key):
        with self.store.transaction() as s:
            row = self.store.get(s, key)
            if not row or row["state"] != "NEEDS_RECONCILIATION":
                raise ProtocolError("reconciliation_not_pending")
            body = self.vault.open(key, row["payload"])
        result = self.rpc(
            row["to"],
            "execution.status",
            row["trade_id"],
            {"execution_id": body["execution_id"], "body_hash": row["body_hash"]},
        )
        if result["found"]:
            with self.store.transaction() as s:
                row = self.store.get(s, key)
                row["state"] = "DELIVERED"
                row["result"] = result["result"]
                self.store.put(s, key, "outbox", row)
                t = self.trade(s, row["trade_id"])
                if t["state"] == "NEEDS_RECONCILIATION":
                    t["state"] = t.pop("previous_state", "CHECKING")
                self.event(s, t, "execution.reconciled")
                self.save(s, t)
        return result

    def check_one(self):
        if self.role not in ["seller", "buyer"]:
            return False
        with self.store.transaction() as s:
            dirty = next(
                (
                    t
                    for t in self.store.list(s, "trade")
                    if t.get("readiness_dirty")
                    and t["state"]
                    not in [
                        "CLOSED",
                        "SETTLED",
                        "HARD_STOP",
                        "TRADE_BREAK",
                        "DECLINED",
                        "CANCELLED",
                    ]
                ),
                None,
            )
            if not dirty:
                return False
            dirty["readiness_dirty"] = False
            self.save(s, dirty)
        try:
            self.readiness(dirty["trade_id"])
        except Exception:
            with self.store.transaction() as s:
                t = self.trade(s, dirty["trade_id"])
                t["state"] = "NEEDS_RECONCILIATION"
                self.event(s, t, "readiness.failed")
                self.save(s, t)
            raise
        return True
