"""Browser integration test with a test IdP key and a software PKCS#11 test double.

This is a test fixture, not a production authentication path or issuer.
"""

import base64
import json
import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import sync_playwright

from certify.provision import fixtures, provision
from node.api.local import create_app
from node.identity.crypto import public_bytes
from node.runtime.config import Settings
from node.runtime.service import Node
from node.signer.backends import SoftwareSigner


def enc(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def main():
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        manifest = provision(root / "nodes")
        entry = manifest["nodes"]["seller"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        issuer = Ed25519PrivateKey.generate()
        jwks = root / "jwks.json"
        jwks.write_text(
            json.dumps(
                {
                    "keys": [
                        {
                            "kid": "test-bank",
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": enc(public_bytes(issuer.public_key())),
                        }
                    ]
                }
            )
        )
        config = Settings.load(entry["config"]).model_dump()
        config["oidc"] = {
            "issuer": "https://test-bank.internal",
            "audience": "exchange-api",
            "jwks_file": str(jwks),
            "subjects": {"employee-1": "seller-trader"},
            "authorization_endpoint": "https://test-bank.internal/authorize",
            "token_endpoint": "https://test-bank.internal/token",
            "client_id": "exchange-ui",
            "redirect_uri": "https://test-node.internal/",
        }
        config["officer_hsm_labels"] = {
            o["officer_id"]: o["officer_id"] for o in config["officers"]
        }

        def test_hsm(module, token_label, key_label, pin, public_key):
            key = Path(manifest["officers"][key_label]["signing_key"]).read_bytes()
            return SoftwareSigner(
                serialization.load_pem_private_key(key, password=None)
            )

        with (
            patch.dict(
                os.environ, {**entry["env"], "EXCHANGE_HSM_PIN": "test-fixture-only"}
            ),
            patch("node.api.local.HsmSigner", test_hsm),
        ):
            node = Node(Settings.model_validate(config))
            ticket, books = fixtures()
            node.local(
                SimpleNamespace(node_id="seller-admin"),
                SimpleNamespace(type="local.import", body=books["seller"], trade_id=""),
            )
            app = create_app(node)
        server = uvicorn.Server(
            uvicorn.Config(
                app, host="127.0.0.1", port=port, access_log=False, log_level="error"
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        while not server.started:
            time.sleep(0.05)
        now = time.time()
        claims = {
            "iss": "https://test-bank.internal",
            "aud": "exchange-api",
            "sub": "employee-1",
            "exp": now + 120,
            "iat": now,
            "auth_time": now,
            "amr": ["pwd", "mfa"],
        }
        raw = (
            enc(json.dumps({"alg": "EdDSA", "kid": "test-bank"}).encode())
            + "."
            + enc(json.dumps(claims).encode())
        )
        token = raw + "." + enc(issuer.sign(raw.encode()))
        errors = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path="/usr/bin/chromium",
                    headless=True,
                    args=["--no-sandbox"],
                )
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://127.0.0.1:{port}")
                page.get_by_role("button", name="Sign in with bank SSO").wait_for()
                assert page.get_by_text("Sandbox password").count() == 0
                page.evaluate(
                    '(value)=>sessionStorage.setItem("exchange-token",value)', token
                )
                page.reload()
                page.get_by_role(
                    "heading", name="A clearer path to settlement."
                ).wait_for()
                page.get_by_role("button", name="New trade", exact=True).click()
                page.get_by_label("Trade reference").fill(ticket["terms"]["trade_id"])
                page.get_by_label("Facility identifier").fill(
                    ticket["terms"]["facility_id"]
                )
                page.get_by_label("Principal (USD)").fill("500000000")
                page.get_by_label("Price (%)").fill("99.75")
                page.get_by_label("Settlement date").fill(
                    ticket["terms"]["settlement_date"]
                )
                page.get_by_role("button", name="Create draft trade").click()
                page.get_by_text(
                    "Trade created. Proposal approval is waiting on the seller trader."
                ).wait_for()
                page.locator(".trades-table tbody tr").first.click()
                page.get_by_role("button", name="Approve & sign").click()
                page.get_by_text("Approval signed and recorded.").wait_for()
                page.locator(".page-heading .pill").filter(
                    has_text="Proposed"
                ).wait_for()
                out = Path(".local/screenshots")
                out.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(out / "institution-trade.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= window.innerWidth"
                )
                page.get_by_role("button", name="Sign out", exact=True).click()
                page.get_by_role("button", name="Sign in with bank SSO").wait_for()
                browser.close()
            assert not errors, errors
            print(
                json.dumps(
                    {
                        "passed": [
                            "bank-SSO login view",
                            "pinned test JWT API authentication",
                            "local trade entry",
                            "officer-signed proposal approval",
                            "role-local data",
                            "mobile layout",
                            "sign out",
                        ],
                        "page_errors": errors,
                        "hardware_scope": "PKCS#11 test double; real bank IdP/HSM not tested",
                    }
                )
            )
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            node.pool.shutdown()
            node.store.engine.dispose()


if __name__ == "__main__":
    main()
