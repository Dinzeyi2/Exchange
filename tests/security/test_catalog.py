from types import SimpleNamespace

import pytest

from node.adapters.reference import ReferenceAdapter
from node.catalog.engine import Catalog
from node.identity.crypto import verify
from node.signer.backends import SoftwareSigner
from node.transport.protocol import ProtocolError


@pytest.fixture
def catalog():
    return Catalog(
        "catalog/questions.yaml",
        "agent",
        SoftwareSigner(),
        "agent",
        ReferenceAdapter(
            {"positions": {"f": {"Seller": 100, "Other": 200}}, "kyc": {}}
        ),
    )


def test_unlisted_question(catalog):
    with pytest.raises(ProtocolError, match="question_not_permitted"):
        catalog.ask(SimpleNamespace(role="seller"), "SELECT *", {})


def test_wrong_peer(catalog):
    with pytest.raises(ProtocolError, match="question_not_permitted"):
        catalog.ask(
            SimpleNamespace(role="borrower"), "lender_kyc_cleared", {"lender": "x"}
        )


def test_only_own_position(catalog):
    peer = SimpleNamespace(role="seller", legal_name="Seller")
    answer = catalog.ask(
        peer,
        "my_register_position_matches",
        {"facility_id": "f", "claimed_position": 200},
    )
    assert answer["result"] is False
    assert "positions" not in answer
    verify(
        catalog.signer.public_key,
        {k: v for k, v in answer.items() if k != "sig"},
        answer["sig"],
    )


def test_extra_params(catalog):
    with pytest.raises(ProtocolError, match="invalid_parameters"):
        catalog.ask(
            SimpleNamespace(role="seller"),
            "lender_kyc_cleared",
            {"lender": "x", "sql": "anything"},
        )
