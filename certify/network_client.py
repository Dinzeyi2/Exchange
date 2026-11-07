from pathlib import Path

from cryptography.hazmat.primitives import serialization

from node.audit.store import now
from node.identity.crypto import digest
from node.signer.backends import SoftwareSigner
from node.transport.client import send
from node.transport.protocol import Peer, ProtocolError, envelope, tls_context


class OfficerClient:
    def __init__(self, manifest, officer_id):
        self.manifest = manifest
        self.officer_id = officer_id
        officer = manifest["officers"][officer_id]
        self.role = officer["node"]
        self.peer = Peer.model_validate(manifest["nodes"][self.role]["bundle"])
        self.signer = SoftwareSigner(
            serialization.load_pem_private_key(
                Path(officer["signing_key"]).read_bytes(), password=None
            )
        )
        self.context = tls_context(
            officer["certificate"],
            officer["tls_key"],
            [self.peer.certificate_path],
            server=False,
        )

    def call(self, type, body=None, trade_id=""):
        msg = envelope(
            self.signer, self.officer_id, self.peer.node_id, type, trade_id, body or {}
        )
        response = send(self.peer, msg, self.context)
        if response["type"] == "error":
            raise ProtocolError(response["body"]["error"])
        return response["body"]["answer"]

    def approve(self, trade_id, task, decision="approve", reason=""):
        signed = {
            "officer_id": self.officer_id,
            "trade_id": trade_id,
            "task_id": task["task_id"],
            "action": task["action"],
            "what_hash": task["what_hash"],
            "payload_hash": digest(task["payload_preview"]),
            "decision": decision,
            "reason": reason,
            "ts": now(),
        }
        return self.call(
            "local.approve",
            {
                "task_id": task["task_id"],
                "approval": {"signed": signed, "signature": self.signer.sign(signed)},
            },
            trade_id,
        )
