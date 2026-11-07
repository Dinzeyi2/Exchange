"""Generate self-signed, individually pinned development identities; never use for production."""

import base64
import hashlib
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import NameOID

from node.identity.crypto import public_bytes
from node.signer.backends import SoftwareSigner
from node.transport.protocol import Peer


def identity(path, node_id, port):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    tls_key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    stamp = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(stamp - timedelta(minutes=1))
        .not_valid_after(stamp + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName(node_id),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(tls_key, algorithm=None)
    )
    cert_path = path / (node_id + ".crt")
    key_path = path / (node_id + ".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(
            tls_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    signer = SoftwareSigner()
    agreement = x25519.X25519PrivateKey.generate()
    peer = Peer(
        node_id=node_id,
        legal_name=node_id.title(),
        lei="5493001KJTIIGC8Y1R12",
        role=node_id,
        signing_key=base64.b64encode(signer.public_key).decode(),
        agreement_key=base64.b64encode(public_bytes(agreement.public_key())).decode(),
        certificate_sha256=hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
        certificate_path=str(cert_path),
        endpoint=f"https://localhost:{port}",
    )
    return peer, signer, agreement, str(cert_path), str(key_path)
