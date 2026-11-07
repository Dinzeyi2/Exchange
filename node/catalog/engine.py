import yaml

from node.audit.store import now
from node.identity.crypto import digest
from node.transport.protocol import ProtocolError


class Catalog:
    IDS = {
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

    def __init__(self, path, role, signer, node_id, adapter):
        self.policy = yaml.safe_load(open(path))
        if set(self.policy["questions"]) - self.IDS:
            raise ValueError("free form questions forbidden")
        # Configuration may only narrow the fixed v1 authorization matrix.
        matrix = {q: ("agent", {"seller", "buyer"}) for q in self.IDS}
        matrix.update(
            funds_available=("buyer", {"seller"}),
            relationship_to_borrower=("buyer", {"seller", "agent"}),
            position_free_to_sell=("seller", set()),
        )
        for question, rule in self.policy["questions"].items():
            answerer, allowed = matrix[question]
            if rule["answerer"] != answerer or not set(rule["allowed"]).issubset(
                allowed
            ):
                raise ValueError("catalog cannot widen permissions")
        self.hash = digest(self.policy)
        self.role, self.signer, self.node_id, self.adapter = (
            role,
            signer,
            node_id,
            adapter,
        )

    def ask(self, peer, question, params):
        rule = self.policy["questions"].get(question)
        if (
            not rule
            or rule.get("disabled")
            or rule["answerer"] != self.role
            or peer.role not in rule["allowed"]
        ):
            raise ProtocolError("question_not_permitted")
        if set(params) != set(rule["params"]):
            raise ProtocolError("invalid_parameters", 400)
        for key, value in params.items():
            if key in ("amount", "claimed_position", "purchase_price") and (
                type(value) is not int
                or value < 0
                or value > rule.get("max_amount", 2**63 - 1)
            ):
                raise ProtocolError("invalid_parameters", 400)
            if key not in ("amount", "claimed_position", "purchase_price") and (
                not isinstance(value, str) or len(value) > 200
            ):
                raise ProtocolError("invalid_parameters", 400)
        a = self.adapter
        if question == "lender_holds_at_least":
            result = (
                a.position(params["facility_id"], params["lender"]) >= params["amount"]
            )
        elif question == "my_register_position_matches":
            result = (
                a.position(params["facility_id"], peer.legal_name)
                == params["claimed_position"]
            )
        elif question == "assignment_eligible":
            f = a.get_facility(params["facility_id"])
            reasons = []
            if params["assignee"] in a.data.get("dq", []):
                reasons.append("disqualified")
            if params["amount"] < f.min_assignment:
                reasons.append("below_minimum")
            if params["amount"] % f.assignment_multiple:
                reasons.append("invalid_multiple")
            result = {"eligible": not reasons, "reasons": reasons}
        elif question == "consent_requirements":
            f = a.get_facility(params["facility_id"])
            result = {
                "borrower_consent_required": f.borrower_consent_required
                and params["assignee_relationship"]
                not in f.consent_exempt_assignee_types,
                "agent_consent_required": f.agent_consent_required,
                "assignment_fee": f.assignment_fee,
            }
        elif question == "lender_kyc_cleared":
            result = a.get_kyc_record(params["lender"]).get("status") == "cleared"
        elif question == "my_ssi_matches":
            result = {
                "match": a.ssi_matches(peer, params["trade_id"], params["fingerprint"])
            }
        elif question == "consent_status":
            result = a.data.get("consents", {}).get(
                params["trade_id"], {"agent": "pending", "borrower": "pending"}
            )
        elif question == "funds_available":
            result = a.data.get("available_funds", 0) >= params["purchase_price"]
        elif question == "relationship_to_borrower":
            result = a.data.get("relationships", {}).get(params["facility_id"], "none")
        else:
            raise ProtocolError("question_not_permitted")
        answer = {
            "question": question,
            "params": params,
            "result": result,
            "answered_by": self.node_id,
            "ts": now(),
            "policy_hash": self.hash,
        }
        return {**answer, "sig": self.signer.sign(answer)}
