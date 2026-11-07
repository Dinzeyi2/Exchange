"""AES-GCM field encryption; key injection is local, never transported to peers."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from node.identity.crypto import canonical


class Vault:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("256-bit field key required")
        self.cipher = AESGCM(key)

    def seal(self, key, value):
        nonce = os.urandom(12)
        data = self.cipher.encrypt(nonce, canonical(value), key.encode())
        return {"ciphertext": base64.b64encode(nonce + data).decode()}

    def open(self, key, value):
        import json

        data = base64.b64decode(value["ciphertext"], validate=True)
        return json.loads(self.cipher.decrypt(data[:12], data[12:], key.encode()))
