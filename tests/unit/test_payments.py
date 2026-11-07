import pytest
from lxml import etree as E

from node.adapters.models import Ssi
from node.payments.iso20022 import (
    CAMT,
    pacs008,
    read_camt054,
    validate_xsd,
    write_outbox,
)


def notification(amount="100.01", account="SETTLEMENT", currency="USD", status="BOOK"):
    return f'''<Document xmlns="{CAMT}"><BkToCstmrDbtCdtNtfctn><Ntfctn><Acct><Id><Othr><Id>{account}</Id></Othr></Id></Acct><Ntry><Amt Ccy="{currency}">{amount}</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>{status}</Cd></Sts><NtryDtls><TxDtls><Refs><EndToEndId>execution-123</EndToEndId></Refs></TxDtls></NtryDtls></Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn></Document>'''.encode()


def test_credit_exact_cents():
    assert read_camt054(notification()) == [
        {"execution_id": "execution-123", "amount": 10001, "account": "SETTLEMENT"}
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"amount": "0.001"},
        {"amount": "NaN"},
        {"amount": "-1"},
        {"currency": "EUR"},
        {"status": "PDNG"},
        {"account": ""},
    ],
)
def test_invalid_credit_refused(kwargs):
    with pytest.raises(ValueError):
        read_camt054(notification(**kwargs))


def test_xxe_refused():
    with pytest.raises(ValueError):
        read_camt054(
            f'<!DOCTYPE Document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Document xmlns="{CAMT}">&xxe;</Document>'.encode()
        )


def test_idempotent_outbox(tmp_path):
    file = write_outbox(tmp_path, "execution-123", b"test")
    assert write_outbox(tmp_path, "execution-123", b"test") == file
    with pytest.raises(ValueError, match="collision"):
        write_outbox(tmp_path, "execution-123", b"other")
    with pytest.raises(ValueError):
        write_outbox(tmp_path, "../../escape", b"test")


def test_xsd_validation_not_silently_skipped(tmp_path):
    schema = tmp_path / "test.xsd"
    schema.write_text(
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="expected" type="xs:string"/></xs:schema>'
    )
    validate_xsd(b"<expected>ok</expected>", schema)
    with pytest.raises(E.DocumentInvalid):
        validate_xsd(b"<unexpected/>", schema)


def test_reference_payment_integer_amount():
    ssi = Ssi(
        owner_legal_name="Synthetic",
        bank_name="Synthetic Bank",
        aba="021000021",
        account="DEMO",
        effective_at="2026-11-07",
    )
    xml = pacs008("execution-123", 10001, "Buyer", "Agent", ssi, "2026-11-07T00:00:00Z")
    assert b">100.01<" in xml and b">DEMO<" in xml
