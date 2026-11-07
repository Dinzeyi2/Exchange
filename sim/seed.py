from datetime import date

from node.adapters.models import next_business_day


def sample_terms(index=1):
    return {
        "trade_id": f"LT-20261107-{index:06d}",
        "facility_id": "FAC-ATLAS-01",
        "amount": 50_000_000_000,
        "price": "99.75",
        "seller": "Meridian Capital",
        "buyer": "Northstar Bank",
        "trade_date": date.today().isoformat(),
        "settlement_date": next_business_day(date.today()).isoformat(),
    }


def seed(workflow):
    with workflow.store.transaction() as s:
        if workflow.store.get(s, "facility:FAC-ATLAS-01"):
            return
        workflow.store.put(
            s,
            "facility:FAC-ATLAS-01",
            "facility",
            {
                "facility_id": "FAC-ATLAS-01",
                "borrower_name": "Atlas Infrastructure Holdings",
                "type": "term_loan",
                "currency": "USD",
                "total_outstanding": 300_000_000_000,
                "rate_desc": "SOFR + 275 bps",
                "maturity": "2031-06-30",
                "min_assignment": 100_000_000,
                "assignment_multiple": 100_000_000,
                "borrower_consent_required": True,
                "agent_consent_required": True,
                "dq": [],
            },
        )
        workflow.store.put(
            s,
            "register:FAC-ATLAS-01",
            "register",
            {"Meridian Capital": 200_000_000_000, "Northstar Bank": 100_000_000_000},
        )
        workflow.store.put(
            s, "sandbox:treasury", "sandbox", {"available": 500_000_000_000}
        )
        workflow.store.put(
            s,
            "sandbox:kyc",
            "sandbox",
            {
                "identity": "synthetic-identity-document",
                "tax": "synthetic-tax-document",
            },
        )
        workflow.store.put(
            s,
            "sandbox:ssi",
            "sandbox",
            {
                "owner_legal_name": "Northstar Bank",
                "bank_name": "Northstar",
                "aba": "021000021",
                "account": "SYNTHETIC-0001",
                "currency": "USD",
                "effective_at": "2026-11-07T00:00:00Z",
            },
        )
        for i in range(1, 4):
            terms = sample_terms(i)
            workflow.store.put(s, "booked:" + terms["trade_id"], "booked", terms)
    for i in range(1, 4):
        workflow.create(sample_terms(i), "demo-seed")
