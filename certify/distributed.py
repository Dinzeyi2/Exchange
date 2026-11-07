"""Exercise independent nodes through authenticated network interfaces only.

Test fixtures represent bank books and payment-hub evidence. The controller is
not installed in a bank node, cannot directly mutate a node database and never
uses an in-process Node instance.
"""

import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from lxml import etree as E

from certify.network_client import OfficerClient
from certify.provision import OFFICERS, ROLES, fixtures, provision
from node.identity.crypto import digest
from node.payments.iso20022 import execution_ref
from node.transport.protocol import ProtocolError


def wait_for(function, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, ProtocolError) as error:
            last = type(error).__name__
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for node progress; last error=" + str(last))


def camt(payment_id, amount, account):
    return f"""<?xml version="1.0" encoding="UTF-8"?><Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.054.001.08"><BkToCstmrDbtCdtNtfctn><Ntfctn><Acct><Id><Othr><Id>{account}</Id></Othr></Id></Acct><Ntry><Amt Ccy="USD">{amount // 100}.{amount % 100:02d}</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts><NtryDtls><TxDtls><Refs><EndToEndId>{payment_id}</EndToEndId></Refs></TxDtls></NtryDtls></Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn></Document>""".encode()


class Acceptance:
    def __init__(self, manifest, hub=None):
        self.manifest = manifest
        self.clients = {
            o: OfficerClient(manifest, o) for role in ROLES for o in OFFICERS[role]
        }
        self.hub = hub or self.file_hub
        self.ticket, self.books = fixtures()
        self.trade_id = self.ticket["terms"]["trade_id"]
        self.timings = {}
        self.approvals = []

    def admin(self, role):
        return self.clients[role + "-admin"]

    def status(self, role):
        return self.admin(role).call("local.status")

    def trade(self, role):
        return next(
            (t for t in self.status(role)["trades"] if t["trade_id"] == self.trade_id),
            None,
        )

    def pending(self, role, action):
        t = self.trade(role)
        return (
            next(
                (
                    task
                    for task in t["tasks"]
                    if task["action"] == action and task["status"] == "pending"
                ),
                None,
            )
            if t
            else None
        )

    def approve(self, role, action, officer):
        task = wait_for(lambda: self.pending(role, action))
        start = time.perf_counter()
        result = self.clients[officer].approve(
            self.trade_id,
            task,
            reason="ACCEPTANCE-CALLBACK-REFERENCE"
            if action == "ssi.accept" and task["approvals"]
            else "",
        )
        self.approvals.append(
            {
                "role": role,
                "action": action,
                "officer": officer,
                "elapsed_ms": (time.perf_counter() - start) * 1000,
            }
        )
        return result

    def file_hub(self, source, destination, payment_id, account):
        root = Path(self.manifest["nodes"][source]["root"]) / "data" / "hub" / "outbox"
        path = root / (payment_id + ".xml")
        wait_for(path.exists)
        payload = path.read_bytes()
        xml = E.fromstring(payload)
        ns = {"p": "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"}
        raw = xml.findtext(".//p:IntrBkSttlmAmt", namespaces=ns)
        from decimal import Decimal

        amount = int(Decimal(raw) * 100)
        target = (
            Path(self.manifest["nodes"][destination]["root"]) / "data" / "hub" / "inbox"
        )
        target.mkdir(parents=True, exist_ok=True)
        notification = camt(payment_id, amount, account)
        temp = target / (uuid4().hex + ".tmp")
        temp.write_bytes(notification)
        os.replace(temp, target / (payment_id + ".xml"))
        return amount

    def run(self):
        start = time.perf_counter()
        for role in ROLES:
            self.admin(role).call("local.import", self.books[role])
        self.clients["seller-trader"].call(
            "local.trade.create", {"ticket": self.ticket}, self.trade_id
        )
        self.approve("seller", "trade.propose", "seller-trader")
        wait_for(
            lambda: (
                self.trade("buyer")
                and self.trade("agent")
                and self.trade("seller")["facts"]["affirmed"]
            )
        )
        security_results = {}
        if all(
            self.manifest["nodes"][r].get(
                "host_peer_port", self.manifest["nodes"][r]["peer_port"]
            )
            != 8443
            for r in ROLES
        ):
            from certify.security import run as security_run

            security_results = security_run(self)
        # Initial checks expose KYC and buyer SSI gaps without sending account operands.
        for role in ["seller", "buyer"]:
            self.clients[role + "-admin"].call(
                "local.readiness", trade_id=self.trade_id
            )
        self.approve("buyer", "kyc.release", "buyer-ops")
        self.approve("agent", "kyc.clear", "agent-kyc")
        self.approve("buyer", "ssi.release", "buyer-treasurer")
        self.approve("agent", "ssi.accept", "agent-officer")
        # Same officer may not satisfy the second callback/control approval.
        duplicate = self.pending("agent", "ssi.accept")
        try:
            self.clients["agent-officer"].approve(self.trade_id, duplicate)
        except ProtocolError as error:
            assert error.code == "officer_already_approved"
        else:
            raise AssertionError("dual control bypass")
        self.approve("agent", "ssi.accept", "agent-second")
        self.approve("agent", "consent.agent", "agent-officer")
        self.approve("borrower", "consent.borrower", "borrower-treasurer")
        self.approve("seller", "doc.sign", "seller-signatory")
        self.approve("buyer", "doc.sign", "buyer-signatory")
        self.approve("agent", "doc.sign", "agent-officer")
        wait_for(
            lambda: (
                self.trade("seller")["facts"]["ready"]
                and self.trade("buyer")["facts"]["ready"]
            )
        )
        self.timings["entry_to_ready_wall_ms"] = (time.perf_counter() - start) * 1000
        # Readiness is rerun over the network after gaps and immediately before settlement.
        self.clients["seller-admin"].call("local.readiness", trade_id=self.trade_id)
        self.clients["buyer-admin"].call("local.readiness", trade_id=self.trade_id)
        self.approve("buyer", "funding.release", "buyer-treasurer")
        assert not self.pending("agent", "settle.execute"), (
            "Agent must await booked credit, not a funding notice"
        )
        payment_id = execution_ref("funding", self.trade_id)
        self.hub(
            "buyer", "agent", payment_id, self.books["agent"]["own_ssi"]["account"]
        )
        credit_at = time.perf_counter()
        wait_for(lambda: self.trade("agent")["facts"]["funds_received"])
        self.clients["seller-trader"].call(
            "local.settle.request", trade_id=self.trade_id
        )
        self.approve("agent", "settle.execute", "agent-officer")
        wait_for(lambda: all(self.trade(role).get("receipt") for role in ROLES))
        self.timings["funds_to_receipts_wall_ms"] = (
            time.perf_counter() - credit_at
        ) * 1000
        self.hub(
            "agent",
            "seller",
            execution_ref("disbursement", self.trade_id),
            self.books["seller"]["own_ssi"]["account"],
        )
        wait_for(lambda: all(self.trade(role)["state"] == "CLOSED" for role in ROLES))
        books = {role: self.admin(role).call("local.books") for role in ROLES}
        assert books["agent"]["register"]["FAC-ATLAS-01"] == {
            "Meridian Capital": 150_000_000_000,
            "Northstar Bank": 150_000_000_000,
        }
        assert books["seller"]["positions"]["FAC-ATLAS-01"] == 150_000_000_000
        assert books["buyer"]["positions"]["FAC-ATLAS-01"] == 150_000_000_000
        assert (
            books["seller"]["credits"][execution_ref("disbursement", self.trade_id)][
                "amount"
            ]
            == 49_875_000_000
        )
        assert (
            sum(books["agent"]["register"]["FAC-ATLAS-01"].values()) == 300_000_000_000
        )
        try:
            self.clients["seller-trader"].call(
                "local.trade.create", {"ticket": self.ticket}, self.trade_id
            )
        except ProtocolError as error:
            assert error.code == "duplicate_trade"
        else:
            raise AssertionError("duplicate trade accepted")
        if all(
            self.manifest["nodes"][r].get(
                "host_peer_port", self.manifest["nodes"][r]["peer_port"]
            )
            != 8443
            for r in ROLES
        ):
            from certify.security import double_settlement

            security_results.update(double_settlement(self))
        disclosures = self.privacy_report()
        from certify.security import verify_received_signatures

        signature_results = verify_received_signatures(self)
        assert all(self.status(role)["audit_valid"] for role in ROLES)
        assert self.timings["entry_to_ready_wall_ms"] <= 30000, self.timings
        assert self.timings["funds_to_receipts_wall_ms"] <= 10000, self.timings
        return {
            "trade_id": self.trade_id,
            "states": {role: self.trade(role)["state"] for role in ROLES},
            "register_conserved": True,
            "seller_payment_reconciled": True,
            "duplicate_trade_refused": True,
            "all_audit_chains_valid": True,
            "timings": self.timings,
            "approval_count": len(self.approvals),
            "security_checks": security_results,
            "signature_verification": signature_results,
            "privacy": disclosures,
            "scope": "automated acceptance fixtures; not bank go-live approval",
        }

    def privacy_report(self):
        result = {}
        for role in ROLES:
            audit = self.admin(role).call("local.audit")
            assert audit["chain_valid"]
            incoming = [
                e["envelope"]
                for e in audit["entries"]
                if "envelope" in e
                and e["direction"] == "in"
                and e["envelope"].get("from") in ROLES
            ]
            encoded = json.dumps(incoming)
            if role in ["seller", "borrower"]:
                assert "BUYER-SECRET-ACCOUNT-9876" not in encoded
                assert "BUYER-CONFIDENTIAL" not in encoded
                for value in self.books["buyer"]["kyc_documents"].values():
                    assert value not in encoded
                assert "funding_payment_id" not in encoded
                assert "credit_amount" not in encoded
                assert not any(
                    msg["type"] in ["kyc.release", "ssi.update", "funding.release"]
                    for msg in incoming
                )
            if role == "borrower":
                assert "purchase_price" not in encoded and "99.75" not in encoded
            received = [
                {
                    "from": m["from"],
                    "type": m["type"],
                    "trade_id": m["trade_id"],
                    "body_hash": digest(m["body"]),
                }
                for m in incoming
            ]
            result[role] = {
                "node_id": role,
                "incoming_messages": received,
                "buyer_account_disclosed": role == "agent",
                "buyer_kyc_disclosed": role == "agent",
                "borrower_received_price": False if role == "borrower" else None,
            }
            if role == "agent":
                assert any(
                    m["type"] == "kyc.release"
                    and m["body"].get("approval", {}).get("signed", {}).get("action")
                    == "kyc.release"
                    for m in incoming
                )
                assert any(
                    m["type"] == "ssi.update"
                    and m["body"].get("approval", {}).get("signed", {}).get("action")
                    == "ssi.release"
                    for m in incoming
                )
            # Audit chain is independently checked from the exported original entries.
            previous = "0" * 64
            for i, entry in enumerate(audit["entries"], 1):
                clean = {
                    k: v for k, v in entry.items() if k not in ["hash", "envelope"]
                }
                assert (
                    clean["seq"] == i
                    and clean["prev_hash"] == previous
                    and digest(clean) == entry["hash"]
                )
                previous = entry["hash"]
        return result


def run_processes(root):
    root = Path(root).resolve()
    manifest = provision(root)
    processes = []
    streams = []
    try:
        for role in ROLES:
            node = manifest["nodes"][role]
            stream = (root / (role + ".log")).open("w")
            streams.append(stream)
            proc = subprocess.Popen(
                [
                    __import__("sys").executable,
                    "-m",
                    "node.ops.cli",
                    "serve",
                    "--config",
                    node["config"],
                ],
                env={**os.environ, **node["env"]},
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
            processes.append(proc)
        acceptance = Acceptance(manifest)
        for role in ROLES:
            wait_for(lambda role=role: acceptance.status(role))
        report = acceptance.run()
        report["deployment"] = (
            "four independent OS processes, separate databases and keys"
        )
        (root / "report.json").write_text(json.dumps(report, indent=2))
        return report
    finally:
        for proc in processes:
            proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for stream in streams:
            stream.close()


if __name__ == "__main__":
    import sys

    print(json.dumps(run_processes(sys.argv[1]), indent=2))
