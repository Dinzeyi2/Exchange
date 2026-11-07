import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node.approvals.oidc import BankOidc
from node.identity.crypto import public_bytes
from node.transport.protocol import ProtocolError


def enc(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def fixture_auth(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "jwks.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "bank-1",
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "alg": "EdDSA",
                        "use": "sig",
                        "x": enc(public_bytes(key.public_key())),
                    }
                ]
            }
        )
    )
    return BankOidc(
        "https://bank.internal",
        "exchange-bank-api",
        path,
        {"employee-1": "agent-officer"},
    ), key


def token(key, claims, header=None):
    raw = (
        enc(json.dumps(header or {"alg": "EdDSA", "kid": "bank-1"}).encode())
        + "."
        + enc(json.dumps(claims).encode())
    )
    return raw + "." + enc(key.sign(raw.encode()))


def claims():
    return {
        "iss": "https://bank.internal",
        "aud": "exchange-bank-api",
        "sub": "employee-1",
        "exp": time.time() + 60,
        "iat": time.time() - 1,
        "auth_time": time.time() - 1,
        "amr": ["pwd", "mfa"],
    }


def test_pinned_bank_identity_and_mfa(tmp_path):
    auth, key = fixture_auth(tmp_path)
    assert auth.authenticate(token(key, claims()), step_up=True) == "agent-officer"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://attacker"},
        {"aud": "another-bank-api"},
        {"exp": 0},
        {"iat": time.time() + 3600},
        {"sub": "unmapped-user"},
        {"exp": float("nan")},
    ],
)
def test_invalid_token_refused(tmp_path, change):
    auth, key = fixture_auth(tmp_path)
    with pytest.raises(ProtocolError, match="invalid_bank_access_token"):
        auth.authenticate(token(key, {**claims(), **change}))


@pytest.mark.parametrize(
    "change",
    [{"amr": ["pwd"]}, {"auth_time": time.time() - 301}, {"auth_time": float("nan")}],
)
def test_step_up_required(tmp_path, change):
    auth, key = fixture_auth(tmp_path)
    with pytest.raises(ProtocolError, match="step_up_mfa_required"):
        auth.authenticate(token(key, {**claims(), **change}), step_up=True)


def test_signature_and_algorithm_confusion_refused(tmp_path):
    auth, key = fixture_auth(tmp_path)
    for bad in [
        token(Ed25519PrivateKey.generate(), claims()),
        token(key, claims(), {"alg": "HS256", "kid": "bank-1"}),
        token(
            key,
            claims(),
            {"alg": "EdDSA", "kid": "bank-1", "jku": "https://attacker/keys"},
        ),
    ]:
        with pytest.raises(ProtocolError):
            auth.authenticate(bad)
