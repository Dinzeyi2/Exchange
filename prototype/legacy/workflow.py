"""Deterministic reference workflow. Synthetic four-role sandbox; not a production coordinator."""

from datetime import date, datetime
from uuid import uuid4

from node.adapters.models import Ssi, TradeInput, business_day, purchase_price
from node.audit.store import now
from node.documents.agreement import document_hash
from node.identity.crypto import digest, verify
from node.transport.protocol import ProtocolError

TERMINAL = {
    "CLOSED",
    "HARD_STOP",
    "DECLINED",
    "CANCELLED",
    "TRADE_BREAK",
    "NEEDS_RECONCILIATION",
}
OFFICERS = {
    "seller-trader": ("Jordan Ellis", "seller", ["trader"]),
    "seller-signatory": ("Morgan Chen", "seller", ["signatory"]),
    "buyer-ops": ("Amara Okafor", "buyer", ["loan_ops"]),
    "buyer-treasurer": ("Daniel Brooks", "buyer", ["treasurer"]),
    "buyer-signatory": ("Priya Shah", "buyer", ["signatory"]),
    "agent-kyc": ("Sofia Martinez", "agent", ["kyc"]),
    "agent-officer": ("Alex Morgan", "agent", ["officer", "signatory"]),
    "agent-second": ("Casey Williams", "agent", ["officer"]),
    "borrower-treasurer": ("Taylor Reed", "borrower", ["treasurer"]),
}
ACTIONS = {
    "trade.propose": [("seller", "trader")],
    "kyc.release": [("buyer", "loan_ops")],
    "kyc.clear": [("agent", "kyc")],
    "ssi.update": [("buyer", "treasurer"), ("agent", "officer"), ("agent", "officer")],
    "consent.agent": [("agent", "officer")],
    "consent.borrower": [("borrower", "treasurer")],
    "doc.seller": [("seller", "signatory")],
    "doc.buyer": [("buyer", "signatory")],
    "doc.agent": [("agent", "signatory")],
    "funding.release": [("buyer", "treasurer")],
    "settle.execute": [("agent", "officer")],
}
SUMMARIES = {
    "trade.propose": "Send the signed trade ticket to the buyer and administrative agent.",
    "kyc.release": "Release only the required synthetic identity and tax documents to the agent.",
    "kyc.clear": "Accept the released document package and clear the buyer for this facility.",
    "ssi.update": "Replace buyer settlement instructions on the agent record. Requires treasury and two different agent officers.",
    "consent.agent": "Record agent consent to the proposed assignment.",
    "consent.borrower": "Record borrower consent to the proposed assignment.",
    "doc.seller": "Sign the assignment agreement as seller.",
    "doc.buyer": "Sign the assignment agreement as buyer.",
    "doc.agent": "Sign the assignment agreement as administrative agent.",
    "funding.release": "Create a payment instruction in the reference outbox. No money is moved.",
    "settle.execute": "Atomically transfer the lender register position and issue a signed settlement receipt.",
}


class Workflow:
    def __init__(self, store, signer, officer_signers):
        self.store, self.signer, self.officer_signers = store, signer, officer_signers

    def event(self, s, t, type, actor="system", payload=None):
        stamp = now()
        last = t["events"][-1]["ts"] if t["events"] else stamp
        elapsed = max(
            0,
            int(
                (
                    datetime.fromisoformat(stamp) - datetime.fromisoformat(last)
                ).total_seconds()
                * 1000
            ),
        )
        waiting = t["state"] in {
            "DRAFT",
            "GAPS_OPEN",
            "CONSENTS_PENDING",
            "DOCS_PENDING",
            "READY_TO_SETTLE",
            "FUNDING_SENT",
            "FUNDS_RECEIVED",
        }
        e = {
            "trade_id": t["trade_id"],
            "ts": stamp,
            "type": type,
            "actor": actor,
            "machine_ms": 0 if waiting else elapsed,
            "human_ms": elapsed if waiting else 0,
            "payload_hash": digest(payload or {}),
        }
        t["events"].append(e)
        self.store.audit(s, "trade.event", e)

    def save(self, s, t):
        self.store.put(s, "trade:" + t["trade_id"], "trade", t)

    def load(self, s, id):
        t = self.store.get(s, "trade:" + id)
        if not t:
            raise ProtocolError("trade_not_found", 404)
        return t

    def task(self, s, t, action):
        if any(x["action"] == action for x in t["tasks"]):
            return
        binding = {
            "trade_id": t["trade_id"],
            "action": action,
            "terms_hash": digest(t["terms"]),
            "document_hash": document_hash(t["terms"]),
        }
        if action.startswith("kyc."):
            binding["release_hash"] = digest(self.store.get(s, "sandbox:kyc"))
        if action == "ssi.update":
            binding["ssi_hash"] = digest(self.store.get(s, "sandbox:ssi"))
        task = {
            "task_id": uuid4().hex,
            "action": action,
            "summary": SUMMARIES[action],
            "binding": binding,
            "what_hash": digest(binding),
            "status": "pending",
            "approvals": [],
            "created_at": now(),
        }
        t["tasks"].append(task)
        self.event(s, t, "task.created", payload={"action": action})

    def create(self, raw, actor):
        terms = TradeInput.model_validate(raw).model_dump()
        if terms["seller"] == terms["buyer"]:
            raise ProtocolError("same_counterparty", 400)
        if (
            not business_day(date.fromisoformat(terms["settlement_date"]))
            or terms["settlement_date"] < terms["trade_date"]
        ):
            raise ProtocolError("invalid_settlement_date", 400)
        price = purchase_price(terms["amount"], terms["price"])
        with self.store.transaction() as s:
            if self.store.get(s, "trade:" + terms["trade_id"]):
                raise ProtocolError("duplicate_trade", 409)
            facility = self.store.get(s, "facility:" + terms["facility_id"])
            if not facility:
                raise ProtocolError("unknown_facility", 400)
            if facility["type"] != "term_loan" or facility["currency"] != "USD":
                raise ProtocolError("unsupported_facility", 400)
            t = {
                "trade_id": terms["trade_id"],
                "terms": terms,
                "purchase_price": price,
                "state": "DRAFT",
                "created_at": now(),
                "events": [],
                "tasks": [],
                "checks": [],
                "facts": {
                    "kyc_released": False,
                    "kyc_cleared": False,
                    "ssi_current": False,
                    "agent_consent": False,
                    "borrower_consent": False,
                    "docs": {},
                    "funding_sent": False,
                    "funds_received": False,
                },
                "receipt": None,
                "execution_id": uuid4().hex,
            }
            self.event(s, t, "trade.created", actor)
            self.task(s, t, "trade.propose")
            self.save(s, t)
            return t

    def checks(self, s, t):
        terms = t["terms"]
        f = self.store.get(s, "facility:" + terms["facility_id"])
        r = self.store.get(s, "register:" + terms["facility_id"])
        available = self.store.get(s, "sandbox:treasury")["available"]
        facts = t["facts"]
        tests = [
            (
                "position",
                "Seller holds the assignment",
                r.get(terms["seller"], 0) >= terms["amount"],
                "Agent",
                "hard",
            ),
            (
                "eligible",
                "Assignment minimum and multiple",
                terms["amount"] >= f["min_assignment"]
                and terms["amount"] % f["assignment_multiple"] == 0,
                "Agent",
                "hard",
            ),
            ("dq", "Buyer is eligible", terms["buyer"] not in f["dq"], "Agent", "hard"),
            (
                "free",
                "Position is free to sell",
                r.get(terms["seller"], 0) - f.get("pledged", 0) >= terms["amount"],
                "Seller",
                "hard",
            ),
            (
                "funds",
                "Purchase funds available",
                available >= t["purchase_price"],
                "Buyer",
                "hard",
            ),
            (
                "affirm",
                "Buyer trade affirmed",
                facts.get("affirmed", False),
                "Buyer",
                "hard",
            ),
            ("kyc", "Buyer KYC cleared", facts["kyc_cleared"], "Agent", "gap"),
            (
                "ssi",
                "Settlement instructions match",
                facts["ssi_current"],
                "Agent",
                "gap",
            ),
            (
                "agent_consent",
                "Agent consent",
                facts["agent_consent"] or not f["agent_consent_required"],
                "Agent",
                "consent",
            ),
            (
                "borrower_consent",
                "Borrower consent",
                facts["borrower_consent"] or not f["borrower_consent_required"],
                "Borrower",
                "consent",
            ),
        ]
        t["checks"] = [
            {
                "id": id,
                "label": label,
                "passed": bool(passed),
                "signed_by": by,
                "kind": kind,
            }
            for id, label, passed, by, kind in tests
        ]
        return t["checks"]

    def progress(self, s, t):
        f = t["facts"]
        checks = self.checks(s, t)
        if any(not c["passed"] and c["kind"] == "hard" for c in checks):
            t["state"] = "HARD_STOP"
            self.event(s, t, "trade.hard_stop")
            return
        if not f["kyc_cleared"] or not f["ssi_current"]:
            t["state"] = "GAPS_OPEN"
            if not f["kyc_released"]:
                self.task(s, t, "kyc.release")
            elif not f["kyc_cleared"]:
                self.task(s, t, "kyc.clear")
            if not f["ssi_current"]:
                self.task(s, t, "ssi.update")
            return
        if not any(e["type"] == "checks.passed" for e in t["events"]):
            t["state"] = "CHECKS_PASSED"
            self.event(s, t, "checks.passed")
        if any(not c["passed"] and c["kind"] == "consent" for c in checks):
            t["state"] = "CONSENTS_PENDING"
            if not f["agent_consent"]:
                self.task(s, t, "consent.agent")
            if not f["borrower_consent"]:
                self.task(s, t, "consent.borrower")
            return
        if len(f["docs"]) < 3:
            t["state"] = "DOCS_PENDING"
            for role in ["seller", "buyer", "agent"]:
                if role not in f["docs"]:
                    self.task(s, t, "doc." + role)
            return
        if not f["funding_sent"]:
            t["state"] = "READY_TO_SETTLE"
            self.task(s, t, "funding.release")
        elif not f["funds_received"]:
            t["state"] = "FUNDING_SENT"
        else:
            t["state"] = "FUNDS_RECEIVED"
            self.task(s, t, "settle.execute")

    def can_approve(self, task, officer):
        if officer not in OFFICERS:
            return False
        _, institution, roles = OFFICERS[officer]
        remaining = list(ACTIONS[task["action"]])
        for a in task["approvals"]:
            _, inst, rs = OFFICERS[a["officer_id"]]
            for need in remaining:
                if need[0] == inst and need[1] in rs:
                    remaining.remove(need)
                    break
        return officer not in {a["officer_id"] for a in task["approvals"]} and any(
            i == institution and r in roles for i, r in remaining
        )

    def decide(self, id, task_id, officer, decision, reason=""):
        if decision not in ["approve", "reject"] or (
            decision == "reject" and not reason.strip()
        ):
            raise ProtocolError("reason_required", 400)
        with self.store.transaction() as s:
            t = self.load(s, id)
            task = next((x for x in t["tasks"] if x["task_id"] == task_id), None)
            if not task or task["status"] != "pending" or t["state"] in TERMINAL:
                raise ProtocolError("task_not_pending", 409)
            if not self.can_approve(task, officer):
                raise ProtocolError("officer_not_permitted")
            if task["binding"]["terms_hash"] != digest(t["terms"]):
                raise ProtocolError("stale_approval", 409)
            if task["binding"].get("release_hash") and task["binding"][
                "release_hash"
            ] != digest(self.store.get(s, "sandbox:kyc")):
                raise ProtocolError("stale_kyc_package", 409)
            if task["binding"].get("ssi_hash") and task["binding"][
                "ssi_hash"
            ] != digest(self.store.get(s, "sandbox:ssi")):
                raise ProtocolError("stale_ssi", 409)
            approval = {
                "approval_id": uuid4().hex,
                "trade_id": id,
                "officer_id": officer,
                "what_hash": task["what_hash"],
                "summary": task["summary"],
                "decision": decision,
                "reason": reason,
                "ts": now(),
            }
            approval["signature"] = self.officer_signers[officer].sign(approval)
            task["approvals"].append(approval)
            self.store.audit(s, "approval", approval)
            self.event(
                s, t, "approval." + decision, officer, {"action": task["action"]}
            )
            if decision == "reject":
                task["status"] = "rejected"
                t["state"] = (
                    "DECLINED" if task["action"] == "consent.borrower" else "CANCELLED"
                )
            elif len(task["approvals"]) == len(ACTIONS[task["action"]]):
                self.verify_task(task)
                task["status"] = "approved"
                self.execute(s, t, task["action"], officer)
            self.save(s, t)
            return t

    def verify_task(self, task):
        if len(task["approvals"]) != len(ACTIONS[task["action"]]):
            raise ProtocolError("approvals_missing")
        seen = set()
        remaining = list(ACTIONS[task["action"]])
        for a in task["approvals"]:
            officer = a["officer_id"]
            if (
                officer in seen
                or a["decision"] != "approve"
                or a["what_hash"] != task["what_hash"]
            ):
                raise ProtocolError("invalid_approval")
            seen.add(officer)
            _, inst, roles = OFFICERS[officer]
            need = next((x for x in remaining if x[0] == inst and x[1] in roles), None)
            if not need:
                raise ProtocolError("invalid_approval_role")
            remaining.remove(need)
            verify(
                self.officer_signers[officer].public_key,
                {k: v for k, v in a.items() if k != "signature"},
                a["signature"],
            )

    def execute(self, s, t, action, officer):
        f = t["facts"]
        if action == "trade.propose":
            t["state"] = "PROPOSED"
            self.event(s, t, "trade.proposed", officer)
            booked = self.store.get(s, "booked:" + t["trade_id"])
            if booked != t["terms"]:
                t["state"] = "TRADE_BREAK"
                self.event(s, t, "trade.break")
                return
            f["affirmed"] = True
            t["state"] = "AFFIRMED"
            self.event(s, t, "trade.affirmed")
            t["state"] = "CHECKING"
        elif action == "kyc.release":
            f["kyc_released"] = True
        elif action == "kyc.clear":
            if not f["kyc_released"]:
                raise ProtocolError("kyc_not_released")
            package = self.store.get(s, "sandbox:kyc")
            if not package or not {"identity", "tax"}.issubset(package):
                raise ProtocolError("kyc_documents_missing")
            f["kyc_cleared"] = True
        elif action == "ssi.update":
            Ssi.model_validate(self.store.get(s, "sandbox:ssi"))
            f["ssi_current"] = True
        elif action == "consent.agent":
            f["agent_consent"] = True
        elif action == "consent.borrower":
            f["borrower_consent"] = True
        elif action.startswith("doc."):
            if self.store.get(s, "booked:" + t["trade_id"]) != t["terms"]:
                raise ProtocolError("document_trade_mismatch")
            role = action.split(".")[1]
            what = {
                "trade_id": t["trade_id"],
                "document_hash": document_hash(t["terms"]),
                "role": role,
            }
            f["docs"][role] = {
                **what,
                "officer_id": officer,
                "signature": self.officer_signers[officer].sign(what),
            }
        elif action == "funding.release":
            if t["state"] != "READY_TO_SETTLE" or not all(
                c["passed"] for c in self.checks(s, t)
            ):
                raise ProtocolError("not_ready")
            f["funding_sent"] = True
            # Durable payment intent; export is explicitly separate from transaction commit.
            self.store.put(
                s,
                "payment:" + t["execution_id"],
                "payment",
                {
                    "execution_id": t["execution_id"],
                    "trade_id": t["trade_id"],
                    "amount": t["purchase_price"],
                    "status": "pending_export",
                    "created_at": now(),
                },
            )
        elif action == "settle.execute":
            self.settle(s, t, t["terms"]["seller"])
            return
        self.event(s, t, "action." + action, officer)
        self.progress(s, t)

    def settle(self, s, t, requester):
        if requester != t["terms"]["seller"]:
            raise ProtocolError("seller_request_required")
        if t["state"] in ["SETTLED", "CLOSED"] or self.store.get(
            s, "execution:" + t["trade_id"]
        ):
            raise ProtocolError("already_settled", 409)
        if (
            not all(c["passed"] for c in self.checks(s, t))
            or not t["facts"]["funds_received"]
        ):
            raise ProtocolError("settlement_preconditions_failed")
        credit = self.store.get(s, "credit:" + t["execution_id"])
        if (
            not credit
            or credit["amount"] != t["purchase_price"]
            or credit["account"] != "DEMO-AGENT-SETTLEMENT"
        ):
            raise ProtocolError("funds_not_booked")
        required = set(ACTIONS)
        tasks = {x["action"]: x for x in t["tasks"] if x["status"] == "approved"}
        if required - set(tasks):
            raise ProtocolError("approvals_missing")
        for task in tasks.values():
            self.verify_task(task)
        if set(t["facts"]["docs"]) != {"seller", "buyer", "agent"}:
            raise ProtocolError("document_signatures_missing")
        for role, doc in t["facts"]["docs"].items():
            if doc["document_hash"] != document_hash(t["terms"]):
                raise ProtocolError("document_hash_mismatch")
            verify(
                self.officer_signers[doc["officer_id"]].public_key,
                {k: v for k, v in doc.items() if k not in ["officer_id", "signature"]},
                doc["signature"],
            )
        terms = t["terms"]
        reg = self.store.get(s, "register:" + terms["facility_id"])
        before = sum(reg.values())
        reg[terms["seller"]] -= terms["amount"]
        reg[terms["buyer"]] = reg.get(terms["buyer"], 0) + terms["amount"]
        if sum(reg.values()) != before:
            raise ProtocolError("register_invariant")
        self.store.put(s, "register:" + terms["facility_id"], "register", reg)
        self.store.put(
            s,
            "execution:" + t["trade_id"],
            "execution",
            {"execution_id": t["execution_id"]},
        )
        receipt = {
            "trade_id": t["trade_id"],
            "status": "SETTLED",
            "effective_date": terms["settlement_date"],
            "document_hash": document_hash(terms),
            "ts": now(),
        }
        t["receipt"] = {**receipt, "signature": self.signer.sign(receipt)}
        t["state"] = "SETTLED"
        self.event(s, t, "register.updated")
        self.event(s, t, "receipt.issued")
        # Local sandbox receipts only. Bank-specific delivery/book updates remain integration work.

    def receive_credit(self, id, credit):
        with self.store.transaction() as s:
            t = self.load(s, id)
            if (
                t["state"] != "FUNDING_SENT"
                or credit["execution_id"] != t["execution_id"]
                or credit["amount"] != t["purchase_price"]
                or credit["account"] != "DEMO-AGENT-SETTLEMENT"
            ):
                raise ProtocolError("credit_mismatch", 409)
            if self.store.get(s, "credit:" + credit["execution_id"]):
                raise ProtocolError("duplicate_credit", 409)
            self.store.put(s, "credit:" + credit["execution_id"], "credit", credit)
            t["facts"]["funds_received"] = True
            self.event(s, t, "funds.received")
            self.progress(s, t)
            self.save(s, t)
            return t
