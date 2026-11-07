import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_oidc import enc, token

from certify.provision import fixtures, provision
from node.api.local import create_app
from node.identity.crypto import public_bytes
from node.runtime.config import Settings
from node.runtime.service import Node
from node.signer.backends import SoftwareSigner


def test_bank_authenticated_hsm_approval_boundary(tmp_path, monkeypatch):
    manifest = provision(tmp_path / "nodes")
    entry = manifest["nodes"]["seller"]
    for k, v in entry["env"].items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("EXCHANGE_HSM_PIN", "test-only-pin")
    bank_key = Ed25519PrivateKey.generate()
    jwks = tmp_path / "jwks.json"
    jwks.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "bank-1",
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": enc(public_bytes(bank_key.public_key())),
                    }
                ]
            }
        )
    )
    settings = Settings.load(entry["config"]).model_dump()
    settings["oidc"] = {
        "issuer": "https://bank.internal",
        "audience": "exchange-api",
        "jwks_file": str(jwks),
        "subjects": {
            "employee-trader": "seller-trader",
            "employee-admin": "seller-admin",
        },
        "authorization_endpoint": "https://bank.internal/authorize",
        "token_endpoint": "https://bank.internal/token",
        "client_id": "exchange-ui",
        "redirect_uri": "https://node.internal/",
    }
    settings["officer_hsm_labels"] = {
        o["officer_id"]: o["officer_id"] for o in settings["officers"]
    }
    node = Node(Settings.model_validate(settings))
    ticket, books = fixtures()

    # This is a software test double at the PKCS#11 boundary; it is not a hardware test.
    def test_hsm(module, token_label, key_label, pin, public_key):
        path = Path(manifest["officers"][key_label]["signing_key"])
        return SoftwareSigner(
            serialization.load_pem_private_key(path.read_bytes(), password=None)
        )

    monkeypatch.setattr("node.api.local.HsmSigner", test_hsm)
    client = TestClient(create_app(node))
    assert (
        client.get("/api/auth/config").json()["counterparties"]["buyer"]
        == "Northstar Bank"
    )
    assert client.get("/api/dashboard").status_code == 401
    claims = {
        "iss": "https://bank.internal",
        "aud": "exchange-api",
        "sub": "employee-trader",
        "exp": time.time() + 60,
        "iat": time.time() - 1,
        "auth_time": time.time() - 1,
        "amr": ["pwd", "mfa"],
    }
    headers = {"Authorization": "Bearer " + token(bank_key, claims)}
    weak = {"Authorization": "Bearer " + token(bank_key, {**claims, "amr": ["pwd"]})}
    admin_headers = {
        "Authorization": "Bearer "
        + token(bank_key, {**claims, "sub": "employee-admin"})
    }
    assert (
        client.post(
            "/api/bank/initialize", json=books["seller"], headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/bank/initialize", json=books["seller"], headers=admin_headers
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/bank/initialize", json=books["seller"], headers=admin_headers
        ).status_code
        == 409
    )
    with node.store.transaction() as tx:
        imported = next(
            e for e in node.store.audit_rows(tx) if e["type"] == "bank.imported"
        )
    assert imported["body"]["approval"]["signed"]["officer_id"] == "seller-admin"

    assert (
        client.post("/api/trades", json=ticket["terms"], headers=weak).status_code
        == 403
    )
    assert (
        client.post("/api/trades", json=ticket["terms"], headers=headers).status_code
        == 201
    )
    dashboard = client.get("/api/dashboard", headers=headers).json()
    assert dashboard["node"] == "Meridian Capital"
    assert len(dashboard["trades"]) == 1
    task = dashboard["trades"][0]["tasks"][0]
    assert task["can_approve"]
    decision = client.post(
        f"/api/trades/{ticket['terms']['trade_id']}/tasks/{task['task_id']}/decision",
        json={"decision": "approve", "what_hash": task["what_hash"]},
        headers=headers,
    )
    assert decision.status_code == 200 and decision.json()["state"] == "PROPOSED"
    assert not any("demo" in route.path for route in client.app.routes)
    node.pool.shutdown()
    node.store.engine.dispose()
