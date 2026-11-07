"""Acceptance-test provisioning only; never generates a production bank identity."""

import base64
import json
import os
import shutil
import socket
from datetime import date
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization

from node.adapters.models import next_business_day
from sim.certificates import identity

ROLES = ["seller", "buyer", "agent", "borrower"]
OFFICERS = {
    "seller": {
        "seller-admin": ["administrator", "auditor"],
        "seller-trader": ["trader"],
        "seller-signatory": ["signatory"],
    },
    "buyer": {
        "buyer-admin": ["administrator", "auditor"],
        "buyer-ops": ["loan_ops"],
        "buyer-treasurer": ["treasurer"],
        "buyer-signatory": ["signatory"],
    },
    "agent": {
        "agent-admin": ["administrator", "auditor"],
        "agent-kyc": ["kyc"],
        "agent-officer": ["officer", "signatory"],
        "agent-second": ["officer"],
    },
    "borrower": {
        "borrower-admin": ["administrator", "auditor"],
        "borrower-treasurer": ["treasurer"],
    },
}


def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def provision(root, containers=False):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    controller = root / "controller"
    controller.mkdir(mode=0o700)
    ids = {}
    keys = {}
    officers = {}
    manifest = {"nodes": {}, "officers": {}}
    for i, role in enumerate(ROLES):
        directory = root / role
        directory.mkdir(mode=0o700)
        public = directory / "public"
        public.mkdir(mode=0o700)
        private = directory / "private"
        private.mkdir(mode=0o700)
        peer, signer, agreement, cert, tls_key = identity(private, role, 8443)
        prefix = str(100000000000000000 + i)
        peer.lei = prefix + str(98 - int(prefix + "00") % 97).zfill(2)
        peer.legal_name = {
            "seller": "Meridian Capital",
            "buyer": "Northstar Bank",
            "agent": "Union Agency Bank",
            "borrower": "Atlas Infrastructure Holdings",
        }[role]
        private_write(private / "signing.pem", pem(signer.key))
        private_write(private / "agreement.pem", pem(agreement))
        field_key = os.urandom(32)
        private_write(private / "field-key", base64.b64encode(field_key))
        ids[role] = peer
        keys[role] = (signer, agreement, cert, tls_key)
        officers[role] = {}
        for officer_id, roles in OFFICERS[role].items():
            opath = controller / officer_id
            opath.mkdir(mode=0o700)
            opeer, osigner, _, ocert, okey = identity(opath, officer_id, 0)
            private_write(opath / "signing.pem", pem(osigner.key))
            officers[role][officer_id] = {
                "officer_id": officer_id,
                "name": officer_id,
                "roles": roles,
                "signing_key": opeer.signing_key,
                "certificate_sha256": opeer.certificate_sha256,
                "certificate_path": ocert,
            }
            manifest["officers"][officer_id] = {
                "node": role,
                "certificate": ocert,
                "tls_key": okey,
                "signing_key": str(opath / "signing.pem"),
            }
    for role in ROLES:
        directory = root / role
        cfgroot = Path("/config") if containers else directory
        peerport = 8443 if containers else free_port()
        officerport = 9443 if containers else free_port()
        hostport = 19443 + ROLES.index(role) if containers else officerport
        peers = []
        for target, peer in ids.items():
            if target == role:
                continue
            shutil.copyfile(keys[target][2], directory / "public" / (target + ".crt"))
            bundle = peer.model_dump()
            bundle["certificate_path"] = str(cfgroot / "public" / (target + ".crt"))
            bundle["endpoint"] = (
                "https://" + target + ":8443" if containers else "pending"
            )
            peers.append(bundle)
        ownofficers = []
        for oid, officer in officers[role].items():
            shutil.copyfile(
                officer["certificate_path"], directory / "public" / (oid + ".crt")
            )
            ownofficers.append(
                {
                    **officer,
                    "certificate_path": str(cfgroot / "public" / (oid + ".crt")),
                }
            )
        peer_officers = {
            r: {
                oid: {k: v for k, v in officer.items() if k in ["signing_key", "roles"]}
                for oid, officer in entries.items()
            }
            for r, entries in officers.items()
            if r != role
        }
        template = "ASSIGNMENT AND ASSUMPTION\nTrade: $trade_id\nFacility: $facility_id\nAssignor: $seller\nAssignee: $buyer\nPrincipal cents: $amount\nPrice percent: $price\nTrade date: $trade_date\nEffective: $settlement_date\n"
        (directory / "assignment.txt").write_text(template)
        cfg = {
            "node_id": role,
            "role": role,
            "legal_name": ids[role].legal_name,
            "lei": ids[role].lei,
            "mode": "certification",
            "database_url_env": "EXCHANGE_DATABASE_URL",
            "certificate": str(cfgroot / "private" / (role + ".crt")),
            "tls_key": str(cfgroot / "private" / (role + ".key")),
            "signing_backend": "software",
            "signing_key": str(cfgroot / "private" / "signing.pem"),
            "public_signing_key": ids[role].signing_key,
            "public_agreement_key": ids[role].agreement_key,
            "agreement_key": str(cfgroot / "private" / "agreement.pem"),
            "peer_port": peerport,
            "officer_port": officerport,
            "peer_host": "0.0.0.0" if containers else "127.0.0.1",
            "officer_host": "0.0.0.0" if containers else "127.0.0.1",
            "peers": peers,
            "officers": ownofficers,
            "peer_officers": peer_officers,
            "document_template": str(cfgroot / "assignment.txt"),
            "payment_inbox": "/data/hub/inbox"
            if containers
            else str(directory / "data" / "hub" / "inbox"),
            "payment_outbox": "/data/hub/outbox"
            if containers
            else str(directory / "data" / "hub" / "outbox"),
        }
        (directory / "node.yaml").write_text(yaml.safe_dump(cfg))
        data = directory / "data"
        data.mkdir(mode=0o700)
        db = "sqlite:///" + str(data / "node.db")
        # Each process/container receives only its own DB credential and field-encryption key.
        env = {
            "EXCHANGE_DATABASE_URL": db,
            "EXCHANGE_FIELD_KEY": (directory / "private" / "field-key").read_text(),
        }
        private_write(
            directory / "runtime.env",
            "".join(k + "=" + v + "\n" for k, v in env.items()).encode(),
        )
        nodebundle = ids[role].model_dump()
        nodebundle["endpoint"] = f"https://localhost:{hostport}"
        nodebundle["certificate_path"] = keys[role][2]
        manifest["nodes"][role] = {
            "config": str(directory / "node.yaml"),
            "env": env,
            "bundle": nodebundle,
            "peer_port": peerport,
            "officer_port": officerport,
            "root": str(directory),
        }
    if not containers:
        for role in ROLES:
            path = root / role / "node.yaml"
            cfg = yaml.safe_load(path.read_text())
            for peer in cfg["peers"]:
                peer["endpoint"] = "https://localhost:" + str(
                    manifest["nodes"][peer["node_id"]]["peer_port"]
                )
            path.write_text(yaml.safe_dump(cfg))
    private_write(controller / "manifest.json", json.dumps(manifest, indent=2).encode())
    return manifest


def fixtures():
    trade = {
        "trade_id": "LT-20261107-DISTRIBUTED",
        "facility_id": "FAC-ATLAS-01",
        "amount": 50_000_000_000,
        "price": "99.75",
        "seller": "Meridian Capital",
        "buyer": "Northstar Bank",
        "trade_date": date.today().isoformat(),
        "settlement_date": next_business_day(date.today()).isoformat(),
    }

    def ssi(owner, account):
        return {
            "owner_legal_name": owner,
            "bank_name": owner,
            "aba": "021000021",
            "account": account,
            "currency": "USD",
            "effective_at": "2026-11-07T00:00:00Z",
        }

    seller_ssi = ssi("Meridian Capital", "SELLER-ONLY-ACCOUNT")
    buyer_ssi = ssi("Northstar Bank", "BUYER-SECRET-ACCOUNT-9876")
    agent_ssi = ssi("Union Agency Bank", "AGENT-SETTLEMENT-ACCOUNT")
    docs = {
        "identity": base64.b64encode(b"BUYER-CONFIDENTIAL-IDENTITY").decode(),
        "tax": base64.b64encode(b"BUYER-CONFIDENTIAL-TAX").decode(),
    }
    books = {
        "seller": {
            "positions": {"FAC-ATLAS-01": 200_000_000_000},
            "pledged": {"FAC-ATLAS-01": 0},
            "booked_trades": {trade["trade_id"]: trade},
            "own_ssi": seller_ssi,
        },
        "buyer": {
            "positions": {"FAC-ATLAS-01": 100_000_000_000},
            "booked_trades": {trade["trade_id"]: trade},
            "own_ssi": buyer_ssi,
            "agent_ssi": agent_ssi,
            "kyc_documents": docs,
            "cash": {"available": 49_875_000_000},
            "relationships": {"FAC-ATLAS-01": "none"},
        },
        "agent": {
            "register": {
                "FAC-ATLAS-01": {
                    "Meridian Capital": 200_000_000_000,
                    "Northstar Bank": 100_000_000_000,
                }
            },
            "facilities": {
                "FAC-ATLAS-01": {
                    "type": "term_loan",
                    "currency": "USD",
                    "borrower_name": "Atlas Infrastructure Holdings",
                    "min_assignment": 100_000_000,
                    "assignment_multiple": 100_000_000,
                    "agent_consent_required": True,
                    "borrower_consent_required": True,
                    "assignment_fee": 350000,
                }
            },
            "kyc": {},
            "ssi_on_file": {
                "Meridian Capital": seller_ssi,
                "Northstar Bank": ssi("Northstar Bank", "OUTDATED-ACCOUNT"),
            },
            "own_ssi": agent_ssi,
            "dq": [],
        },
        "borrower": {"blocked_list": []},
    }
    return {"terms": trade, "participants": {r: r for r in ROLES}}, books
