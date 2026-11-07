import hashlib
import os
from decimal import Decimal
from pathlib import Path

from lxml import etree as E

PACS = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"
CAMT = "urn:iso:std:iso:20022:tech:xsd:camt.054.001.08"


def execution_ref(kind, trade_id):
    return ("F" if kind == "funding" else "D") + hashlib.sha256(
        trade_id.encode()
    ).hexdigest()[:32]


def pacs008(execution_id, amount, debtor, creditor, ssi, ts, debtor_ssi=None):
    """ISO 20022 pacs.008.001.08, validated against the bank's pinned scheme XSD before export."""
    if not execution_id or len(execution_id) > 35:
        raise ValueError("payment execution reference must fit Max35Text")
    if type(amount) is not int or amount <= 0:
        raise ValueError("invalid amount")
    root = E.Element("{" + PACS + "}Document", nsmap={None: PACS})

    def child(parent, name, value=None, **attrs):
        e = E.SubElement(parent, "{" + PACS + "}" + name, **attrs)
        if value is not None:
            e.text = str(value)
        return e

    msg = child(root, "FIToFICstmrCdtTrf")
    group = child(msg, "GrpHdr")
    child(group, "MsgId", execution_id)
    child(group, "CreDtTm", ts)
    child(group, "NbOfTxs", "1")
    info = child(group, "SttlmInf")
    child(info, "SttlmMtd", "CLRG")
    tx = child(msg, "CdtTrfTxInf")
    pid = child(tx, "PmtId")
    child(pid, "EndToEndId", execution_id)
    child(tx, "IntrBkSttlmAmt", format(Decimal(amount) / 100, ".2f"), Ccy="USD")
    child(tx, "ChrgBr", "SHAR")
    child(child(tx, "Dbtr"), "Nm", debtor)
    if debtor_ssi:
        child(
            child(child(child(tx, "DbtrAcct"), "Id"), "Othr"), "Id", debtor_ssi.account
        )
    dbtr_agent = child(child(tx, "DbtrAgt"), "FinInstnId")
    if debtor_ssi:
        member = child(dbtr_agent, "ClrSysMmbId")
        child(child(member, "ClrSysId"), "Cd", "USABA")
        child(member, "MmbId", debtor_ssi.aba)
    else:
        child(dbtr_agent, "Nm", debtor)
    agent = child(child(tx, "CdtrAgt"), "FinInstnId")
    member = child(agent, "ClrSysMmbId")
    child(child(member, "ClrSysId"), "Cd", "USABA")
    child(member, "MmbId", ssi.aba)
    child(child(tx, "Cdtr"), "Nm", creditor)
    child(child(child(child(tx, "CdtrAcct"), "Id"), "Othr"), "Id", ssi.account)
    return E.tostring(root, xml_declaration=True, encoding="UTF-8")


def validate_xsd(payload, path):
    parser = E.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    schema = E.XMLSchema(E.parse(str(path), parser))
    schema.assertValid(E.fromstring(payload, parser))


def read_camt054(payload):
    if len(payload) > 1024 * 1024:
        raise ValueError("credit notification too large")
    parser = E.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = E.fromstring(payload, parser)
    if root.tag != "{" + CAMT + "}Document" or root.getroottree().docinfo.doctype:
        raise ValueError("invalid camt.054")
    ns = {"c": CAMT}
    entries = []
    for entry in root.findall(".//c:Ntry", ns):
        if entry.findtext("c:CdtDbtInd", namespaces=ns) != "CRDT":
            continue
        status = entry.findtext("c:Sts/c:Cd", namespaces=ns) or entry.findtext(
            "c:Sts", namespaces=ns
        )
        if status != "BOOK":
            continue
        # Only a single booked credit per entry is supported; aggregated entries are refused.
        ids = entry.findall(".//c:EndToEndId", ns)
        amount = entry.find("c:Amt", ns)
        if len(ids) != 1 or amount is None or amount.get("Ccy") != "USD":
            raise ValueError("ambiguous credit")
        cents = Decimal(amount.text) * 100
        if not cents.is_finite() or cents != cents.to_integral_value() or cents <= 0:
            raise ValueError("invalid credit amount")
        notification = entry.getparent()
        if notification.tag != "{" + CAMT + "}Ntfctn":
            raise ValueError("credit entry outside notification")
        account = notification.findtext("c:Acct/c:Id/c:Othr/c:Id", namespaces=ns)
        if not account:
            raise ValueError("missing settlement account")
        entries.append(
            {"execution_id": ids[0].text, "amount": int(cents), "account": account}
        )
    if not entries:
        raise ValueError("no booked credits")
    return entries


def write_outbox(directory, execution_id, payload):
    if not execution_id.replace("-", "").isalnum():
        raise ValueError("invalid execution id")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = path / (execution_id + ".xml")
    if target.exists():
        if target.read_bytes() != payload:
            raise ValueError("execution collision")
        return target
    temp = path / (execution_id + ".tmp")
    with temp.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, target)
    return target
