"""Durable bank-hub file boundary. Exchange never connects to a payment rail."""

import hashlib
import os
from pathlib import Path
from uuid import uuid4

from node.adapters.models import Ssi
from node.payments.iso20022 import pacs008, read_camt054, validate_xsd


def export_one(node):
    with node.store.transaction() as s:
        rows = [r for r in node.store.list(s, "payment") if r["state"] == "PENDING"]
        if not rows:
            return False
        row = rows[0]
        key = "payment:" + row["payment_id"]
        payload = node.vault.open(key, row["payload"])
        xml = pacs008(
            row["payment_id"],
            payload["amount"],
            node.cfg.legal_name,
            payload["ssi"]["owner_legal_name"],
            Ssi.model_validate(payload["ssi"]),
            row["created_at"],
            debtor_ssi=Ssi.model_validate(node.bank(s, "own_ssi")),
        )
        if node.cfg.pacs_xsd:
            validate_xsd(xml, node.cfg.pacs_xsd)
        elif node.cfg.mode == "production":
            raise ValueError("payment XSD required")
        row["state"] = "EXPORTING"
        row["xml_hash"] = hashlib.sha256(xml).hexdigest()
        node.store.put(s, key, "payment", row)
    directory = Path(node.cfg.payment_outbox)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / (row["payment_id"] + ".xml")
    # No overwrite and no retry following ambiguous hand-off. Banks must preserve the hub ack ledger.
    temporary = directory / ("." + uuid4().hex + ".tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(xml)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(
            temporary, target
        )  # Atomic publication without replacing an existing execution.
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        with node.store.transaction() as s:
            row["state"] = "NEEDS_RECONCILIATION"
            node.store.put(s, key, "payment", row)
        raise
    finally:
        temporary.unlink(missing_ok=True)
    with node.store.transaction() as s:
        row["state"] = "EXPORTED"
        node.store.put(s, key, "payment", row)
        node.store.audit(
            s,
            "payment.exported",
            {"payment_id": row["payment_id"], "xml_hash": row["xml_hash"]},
        )
    return True


def ingest_one(node):
    directory = Path(node.cfg.payment_inbox)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    files = sorted(directory.glob("*.xml"))
    if not files:
        return False
    source = files[0]
    if source.is_symlink():
        raise ValueError("payment inbox symlinks forbidden")
    data = source.read_bytes()
    source_hash = hashlib.sha256(data).hexdigest()
    with node.store.transaction() as s:
        seen = node.store.get(s, "hub-inbox:" + source_hash)
    if not seen:
        if node.cfg.camt_xsd:
            validate_xsd(data, node.cfg.camt_xsd)
        elif node.cfg.mode == "production":
            raise ValueError("credit notification XSD required")
        entries = read_camt054(data)
        node.ingest_credits(entries, source_hash)
        with node.store.transaction() as s:
            node.store.put(
                s, "hub-inbox:" + source_hash, "hub-inbox", {"sha256": source_hash}
            )
    processed = directory / "processed"
    processed.mkdir(exist_ok=True, mode=0o700)
    os.replace(source, processed / (source_hash + ".xml"))
    return True
