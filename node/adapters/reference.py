import base64
import csv
import hmac
from pathlib import Path
from typing import Protocol

from node.adapters.models import Facility, Ssi
from node.identity.crypto import fingerprint


class LoanSystemAdapter(Protocol):
    def get_facility(self, facility_id): ...
    def get_lender_positions(self, facility_id): ...
    def get_own_position(self, facility_id): ...
    def get_booked_trade(self, trade_ref): ...
    def get_kyc_record(self, lender): ...
    def get_kyc_documents(self, types): ...
    def get_own_ssi(self): ...
    def get_ssi_on_file(self, lender): ...
    def apply_register_transfer(
        self, facility_id, from_lender, to_lender, amount, effective_date, execution_id
    ): ...


class ReferenceAdapter:
    """Synthetic data only; reference SQL/CSV readers below never write bank tables."""

    def __init__(self, data, agreement_key=None):
        self.data, self.agreement_key = data, agreement_key

    def get_facility(self, id):
        return Facility.model_validate(self.data["facilities"][id])

    def get_lender_positions(self, id):
        return self.data["positions"][id].copy()

    def get_own_position(self, id):
        return self.data["own_positions"][id].copy()

    def get_booked_trade(self, ref):
        return self.data["booked_trades"][ref].copy()

    def get_kyc_record(self, lender):
        return self.data.get("kyc", {}).get(lender, {"status": "none"}).copy()

    def get_own_ssi(self):
        return Ssi.model_validate(self.data["own_ssi"])

    def get_ssi_on_file(self, lender):
        return Ssi.model_validate(self.data["ssi"][lender])

    def get_kyc_documents(self, types):
        return {t: self.data["kyc_documents"][t] for t in types}

    def position(self, facility, lender):
        return self.data.get("positions", {}).get(facility, {}).get(lender, 0)

    def ssi_matches(self, peer, trade_id, claimed):
        if self.agreement_key is None:
            raise ValueError("agreement key missing")
        actual = fingerprint(
            self.agreement_key,
            base64.b64decode(peer.agreement_key),
            trade_id,
            self.get_ssi_on_file(peer.legal_name).model_dump(),
        )
        return hmac.compare_digest(actual, claimed)

    def apply_register_transfer(self, *args, **kwargs):
        raise NotImplementedError(
            "Use transactional agent register service; bank writes need a bank-specific adapter"
        )


class CsvAdapter(ReferenceAdapter):
    @classmethod
    def from_directory(cls, path):
        # Pilot files use one canonical JSON object per `data` column.
        import json

        data = {}
        for name in [
            "facilities",
            "positions",
            "own_positions",
            "booked_trades",
            "kyc",
            "ssi",
        ]:
            with (Path(path) / (name + ".csv")).open(newline="") as stream:
                data[name] = {
                    r["id"]: json.loads(r["data"]) for r in csv.DictReader(stream)
                }
        return cls(data)


class SqlAdapter(ReferenceAdapter):
    @classmethod
    def from_views(cls, engine, views):
        import json
        import re

        from sqlalchemy import text

        data = {}
        with engine.connect() as c:
            for name, view in views.items():
                if name not in [
                    "facilities",
                    "positions",
                    "own_positions",
                    "booked_trades",
                    "kyc",
                    "ssi",
                ] or not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", view):
                    raise ValueError("invalid configured view")
                rows = c.execute(text(f"SELECT id, data FROM {view}")).mappings()
                data[name] = {
                    r["id"]: json.loads(r["data"])
                    if isinstance(r["data"], str)
                    else r["data"]
                    for r in rows
                }
        return cls(data)
