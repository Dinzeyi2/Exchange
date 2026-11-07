"""Four distinct reference nodes, databases, keys and mTLS listeners in one process."""

import asyncio
import json
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from node.adapters.reference import ReferenceAdapter
from node.audit.store import Store
from node.catalog.engine import Catalog
from node.identity.crypto import fingerprint, public_bytes, verify
from node.transport.client import send
from node.transport.dispatch import catalog_handler
from node.transport.protocol import Transport, envelope, tls_context
from node.transport.server import serve
from sim.certificates import identity


async def exercise(directory):
    ids = {
        role: identity(Path(directory) / "identities", role, 0)
        for role in ["seller", "buyer", "agent", "borrower"]
    }
    servers = {}
    transports = {}
    clients = ThreadPoolExecutor(max_workers=24, thread_name_prefix="reference-client")
    ssi = {
        "owner_legal_name": "Seller",
        "bank_name": "Synthetic Bank",
        "aba": "021000021",
        "account": "DEMO-ONLY",
        "currency": "USD",
        "effective_at": "2026-11-07T00:00:00Z",
    }
    data = {
        "positions": {"FAC-DEMO": {"Seller": 100000000}},
        "available_funds": 100000000,
        "relationships": {"FAC-DEMO": "existing_lender"},
        "kyc": {"Buyer": {"status": "cleared"}},
        "ssi": {"Seller": ssi},
        "facilities": {
            "FAC-DEMO": {
                "facility_id": "FAC-DEMO",
                "borrower_name": "Synthetic Borrower",
                "total_outstanding": 100000000,
                "maturity": "2031-06-30",
                "min_assignment": 10000,
                "assignment_multiple": 10000,
            }
        },
    }
    try:
        for role, (peer, signer, key, cert, private) in ids.items():
            adapter = ReferenceAdapter(data.copy(), key)
            catalog = Catalog("catalog/questions.yaml", role, signer, role, adapter)
            peers = {k: v[0] for k, v in ids.items() if k != role}
            store = Store("sqlite:///" + str(Path(directory) / (role + ".db")))
            transport = Transport(role, signer, store, peers, catalog_handler(catalog))
            transports[role] = transport
            context = tls_context(
                cert, private, [v.certificate_path for v in peers.values()]
            )
            servers[role] = await serve(transport, context, host="127.0.0.1", port=0)
            peer.endpoint = "https://localhost:" + str(
                servers[role].sockets[0].getsockname()[1]
            )
        seller = ids["seller"]
        agent = ids["agent"]
        context = tls_context(seller[3], seller[4], [agent[3]], server=False)
        timings = []
        for _ in range(20):
            msg = envelope(
                seller[1],
                "seller",
                "agent",
                "ask",
                "LT-NETWORK-01",
                {
                    "question": "lender_holds_at_least",
                    "params": {
                        "lender": "Seller",
                        "facility_id": "FAC-DEMO",
                        "amount": 10000,
                    },
                },
            )
            start = time.perf_counter()
            response = await asyncio.get_running_loop().run_in_executor(
                clients, send, agent[0], msg, context
            )
            timings.append((time.perf_counter() - start) * 1000)
            verify(
                agent[1].public_key,
                {k: v for k, v in response.items() if k != "sig"},
                response["sig"],
            )
            answer = response["body"]["answer"]
            verify(
                agent[1].public_key,
                {k: v for k, v in answer.items() if k != "sig"},
                answer["sig"],
            )
            assert answer["result"] is True
        ssi_fingerprint = fingerprint(
            seller[2], public_bytes(agent[2].public_key()), "LT-PARALLEL-01", ssi
        )
        questions = [
            (
                "agent",
                "lender_holds_at_least",
                {"lender": "Seller", "facility_id": "FAC-DEMO", "amount": 10000},
            ),
            (
                "agent",
                "my_register_position_matches",
                {"facility_id": "FAC-DEMO", "claimed_position": 100000000},
            ),
            (
                "agent",
                "assignment_eligible",
                {"assignee": "Buyer", "facility_id": "FAC-DEMO", "amount": 10000},
            ),
            (
                "agent",
                "consent_requirements",
                {"facility_id": "FAC-DEMO", "assignee_relationship": "none"},
            ),
            ("agent", "lender_kyc_cleared", {"lender": "Buyer"}),
            (
                "agent",
                "my_ssi_matches",
                {"trade_id": "LT-PARALLEL-01", "fingerprint": ssi_fingerprint},
            ),
            ("agent", "consent_status", {"trade_id": "LT-PARALLEL-01"}),
            ("buyer", "funds_available", {"purchase_price": 10000}),
            ("buyer", "relationship_to_borrower", {"facility_id": "FAC-DEMO"}),
        ]

        async def ask(target, question, params):
            ctx = tls_context(seller[3], seller[4], [ids[target][3]], server=False)
            msg = envelope(
                seller[1],
                "seller",
                target,
                "ask",
                "LT-PARALLEL-01",
                {"question": question, "params": params},
            )
            response = await asyncio.get_running_loop().run_in_executor(
                clients, send, ids[target][0], msg, ctx
            )
            if response["type"] == "error":
                raise RuntimeError(response["body"])
            return response["body"]["answer"]

        began = time.perf_counter()
        answers = await asyncio.gather(*(ask(*q) for q in questions))
        parallel_ms = (time.perf_counter() - began) * 1000
        assert len(answers) == 9 and answers[5]["result"] == {"match": True}
        return {
            "parallel_readiness_checks": 9,
            "parallel_readiness_ms": round(parallel_ms, 2),
            "scope": "four isolated mTLS listeners on loopback; signed catalog round trips seller → agent",
            "samples": len(timings),
            "signed_round_trip_p95_ms": round(sorted(timings)[18], 2),
            "audit_chains_valid": all(
                t.store.verify_audit_chain() for t in transports.values()
            ),
            "full_distributed_lifecycle": False,
        }
    finally:
        for server in servers.values():
            server.close()
            await server.wait_closed()
        clients.shutdown(wait=True, cancel_futures=True)


def run():
    with tempfile.TemporaryDirectory() as directory:
        return asyncio.run(exercise(directory))


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
