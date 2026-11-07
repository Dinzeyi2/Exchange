import base64
import hashlib
import hmac

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canonical(value) -> bytes:
    return rfc8785.dumps(value)


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def verify(public_key: bytes, value, signature: str) -> None:
    ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
        base64.b64decode(signature, validate=True), canonical(value)
    )


def fingerprint(
    private: x25519.X25519PrivateKey, peer_public: bytes, trade_id: str, value
) -> str:
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=("exchange-v1|" + trade_id).encode(),
    ).derive(shared)
    return hmac.new(key, canonical(value), hashlib.sha256).hexdigest()
