import base64
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node.identity.crypto import canonical, public_bytes


class Signer(Protocol):
    @property
    def public_key(self) -> bytes: ...
    def sign(self, value) -> str: ...


class SoftwareSigner:
    """Development only; production configuration refuses this backend."""

    def __init__(self, key=None):
        self.key = key or Ed25519PrivateKey.generate()

    @property
    def public_key(self):
        return public_bytes(self.key.public_key())

    def sign(self, value):
        return base64.b64encode(self.key.sign(canonical(value))).decode()

    @classmethod
    def load_or_create(cls, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists():
            return cls(
                serialization.load_pem_private_key(path.read_bytes(), password=None)
            )
        signer = cls()
        import os

        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(
                signer.key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        return signer


class HsmSigner:
    """PKCS#11 EdDSA signing; token PIN is supplied by the host, never persisted."""

    def __init__(self, module, token_label, key_label, pin, public_key):
        import pkcs11

        self.pkcs11 = pkcs11
        self.token = pkcs11.lib(module).get_token(token_label=token_label)
        self.key_label, self.pin, self._public_key = key_label, pin, public_key

    @property
    def public_key(self):
        return self._public_key

    def sign(self, value):
        p = self.pkcs11
        with self.token.open(user_pin=self.pin) as session:
            key = session.get_key(
                object_class=p.ObjectClass.PRIVATE_KEY, label=self.key_label
            )
            signature = key.sign(canonical(value), mechanism=p.Mechanism.EDDSA)
        return base64.b64encode(signature).decode()
