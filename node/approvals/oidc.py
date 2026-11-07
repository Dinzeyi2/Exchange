"""Offline verification of bank-issued OIDC JWT access tokens against pinned JWKS.

No discovery, untrusted jku/x5u URL fetches, algorithm negotiation, or role claims.
Bank subject→officer mapping and permitted algorithms are local approved policy.
"""

import base64
import json
import math
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from node.transport.protocol import ProtocolError


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JWT member")
        result[key] = value
    return result


class BankOidc:
    def __init__(self, issuer, audience, jwks_file, subjects):
        self.issuer = issuer
        self.audience = audience
        self.subjects = subjects
        keys = json.loads(Path(jwks_file).read_text())["keys"]
        self.keys = {key["kid"]: key for key in keys}
        if len(self.keys) != len(keys):
            raise ValueError("duplicate JWKS kid")

    def authenticate(self, token, step_up=False):
        try:
            if len(token) > 16384:
                raise ValueError()
            header_raw, claims_raw, sig = token.split(".")
            header = json.loads(decode(header_raw), object_pairs_hook=unique_object)
            claims = json.loads(decode(claims_raw), object_pairs_hook=unique_object)
            if header.get("crit") or header.get("jku") or header.get("x5u"):
                raise ValueError()
            key = self.keys[header["kid"]]
            alg = header["alg"]
            if key.get("use", "sig") != "sig" or key.get("alg", alg) != alg:
                raise ValueError()
            data = (header_raw + "." + claims_raw).encode()
            signature = decode(sig)
            if alg == "EdDSA" and key["kty"] == "OKP" and key["crv"] == "Ed25519":
                ed25519.Ed25519PublicKey.from_public_bytes(decode(key["x"])).verify(
                    signature, data
                )
            elif alg == "RS256" and key["kty"] == "RSA":
                pub = rsa.RSAPublicNumbers(
                    int.from_bytes(decode(key["e"]), "big"),
                    int.from_bytes(decode(key["n"]), "big"),
                ).public_key()
                if pub.key_size < 2048:
                    raise ValueError()
                pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise ValueError()
            for member in ["exp", "iat", "nbf"]:
                value = claims.get(member, 0)
                if type(value) not in [int, float] or not math.isfinite(value):
                    raise ValueError()
            now = time.time()
            aud = claims.get("aud")
            aud = [aud] if isinstance(aud, str) else aud
            if (
                claims.get("iss") != self.issuer
                or not isinstance(aud, list)
                or self.audience not in aud
            ):
                raise ValueError()
            if (
                type(claims.get("exp")) not in [int, float]
                or claims["exp"] <= now
                or claims.get("nbf", 0) > now + 30
                or claims.get("iat", now + 100) > now + 30
            ):
                raise ValueError()
            officer = self.subjects[claims["sub"]]
        except Exception:
            raise ProtocolError("invalid_bank_access_token", 401)
        if step_up:
            amr = claims.get("amr", [])
            auth_time = claims.get("auth_time", 0)
            if (
                not isinstance(amr, list)
                or "mfa" not in amr
                or type(auth_time) not in [int, float]
                or not math.isfinite(auth_time)
                or now - auth_time > 300
                or auth_time > now + 30
            ):
                raise ProtocolError("step_up_mfa_required", 403)
        return officer
