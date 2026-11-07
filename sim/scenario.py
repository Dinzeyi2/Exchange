import tempfile
import time

from node.audit.store import Store
from node.signer.backends import SoftwareSigner
from node.workflow.engine import OFFICERS, Workflow
from sim.seed import sample_terms, seed


def run():
    start = time.perf_counter()
    with tempfile.TemporaryDirectory() as d:
        store = Store("sqlite:///" + d + "/demo.db")
        w = Workflow(store, SoftwareSigner(), {id: SoftwareSigner() for id in OFFICERS})
        seed(w)
        trade_id = sample_terms()["trade_id"]
        approvals = 0
        ready_ms = None
        credit_at = None
        while True:
            with store.transaction() as s:
                t = w.load(s, trade_id)
            if t["state"] == "SETTLED":
                break
            if t["state"] == "READY_TO_SETTLE" and ready_ms is None:
                ready_ms = (time.perf_counter() - start) * 1000
            if t["state"] == "FUNDING_SENT":
                credit_at = time.perf_counter()
                w.receive_credit(
                    trade_id,
                    {
                        "execution_id": t["execution_id"],
                        "amount": t["purchase_price"],
                        "account": "DEMO-AGENT-SETTLEMENT",
                    },
                )
                continue
            task = next((x for x in t["tasks"] if x["status"] == "pending"), None)
            if not task:
                raise RuntimeError("workflow stalled: " + t["state"])
            officer = next(id for id in OFFICERS if w.can_approve(task, id))
            w.decide(trade_id, task["task_id"], officer, "approve")
            approvals += 1
        with store.transaction() as s:
            register = store.get(s, "register:FAC-ATLAS-01")
        return {
            "mode": "local synthetic reference; not four-node certification",
            "trade_id": trade_id,
            "state": t["state"],
            "approval_count": approvals,
            "ready_machine_ms": round(ready_ms, 2),
            "credit_to_receipt_ms": round((time.perf_counter() - credit_at) * 1000, 2),
            "total_ms": round((time.perf_counter() - start) * 1000, 2),
            "audit_chain_valid": store.verify_audit_chain(),
            "register_total_unchanged": sum(register.values()) == 300_000_000_000,
            "register": register,
            "unmeasured": [
                "WAN p95",
                "20 concurrent peer trades",
                "officer MFA",
                "real camt.054 credit",
                "receipt delivery to four nodes",
                "T+ business outcome",
            ],
        }
