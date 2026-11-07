"""Institution-local REST API. Never mounted on either peer listener.

Bank OIDC proves the officer identity; fresh MFA is required for every approval.
The approval is signed using that officer's configured PKCS#11 key, not a node key.
"""

import base64
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from node.approvals.oidc import BankOidc
from node.audit.store import now
from node.identity.crypto import digest
from node.signer.backends import HsmSigner
from node.transport.protocol import ProtocolError


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str
    reason: str = Field(default="", max_length=1000)
    what_hash: str


def create_app(node):
    if not node.cfg.oidc:
        raise ValueError("bank OIDC configuration required for REST API")
    oidc = node.cfg.oidc
    auth = BankOidc(oidc.issuer, oidc.audience, oidc.jwks_file, oidc.subjects)
    signers = {
        o.officer_id: HsmSigner(
            node.cfg.hsm_module,
            node.cfg.hsm_token,
            node.cfg.officer_hsm_labels[o.officer_id],
            os.environ[node.cfg.hsm_pin_env],
            base64.b64decode(o.signing_key),
        )
        for o in node.cfg.officers
    }
    from node.identity.crypto import verify

    for officer_id, signer in signers.items():
        challenge = {
            "purpose": "officer-key-possession-proof",
            "officer_id": officer_id,
            "nonce": uuid4().hex,
        }
        verify(signer.public_key, challenge, signer.sign(challenge))
    app = FastAPI(
        title="Exchange " + node.cfg.legal_name, docs_url=None, redoc_url=None
    )
    bearer = HTTPBearer(auto_error=False)

    def officer(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        if not credentials:
            raise HTTPException(401, "bank_authentication_required")
        return auth.authenticate(credentials.credentials)

    def step_up(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        if not credentials:
            raise HTTPException(401, "bank_authentication_required")
        return auth.authenticate(credentials.credentials, step_up=True)

    def local(id, kind, body=None, trade_id=""):
        return node.local(
            SimpleNamespace(node_id=id, bank_authenticated=True),
            SimpleNamespace(type=kind, body=body or {}, trade_id=trade_id),
        )

    @app.exception_handler(ProtocolError)
    async def error(request, error):
        return JSONResponse({"detail": error.code}, status_code=error.status)

    @app.middleware("http")
    async def security(request, call_next):
        if request.headers.get("origin") and request.headers["origin"] != str(
            request.base_url
        ).rstrip("/"):
            return JSONResponse({"detail": "cross_origin_denied"}, status_code=403)
        if int(request.headers.get("content-length", "0")) > 1024 * 1024:
            return JSONResponse({"detail": "request_too_large"}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' "
            + oidc.token_endpoint
            + "; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/api/health")
    def health():
        with node.store.transaction() as s:
            identity = node.store.get(s, "node:identity")
            if not identity or identity["node_id"] != node.id:
                raise ProtocolError("node_identity_unavailable", 503)
        return {"status": "ok"}

    @app.get("/api/auth/config")
    def auth_config():
        return {
            k: getattr(oidc, k)
            for k in [
                "authorization_endpoint",
                "token_endpoint",
                "client_id",
                "redirect_uri",
            ]
        } | {
            "institution": node.cfg.legal_name,
            "node_id": node.id,
            "role": node.role,
            "counterparties": {
                **{p.role: p.legal_name for p in node.cfg.peers},
                node.role: node.cfg.legal_name,
            },
        }

    @app.get("/api/me")
    def me(id=Depends(officer)):
        o = node.officers[id]
        return {
            "officer_id": id,
            "name": o.name,
            "institution": node.role,
            "roles": o.roles,
        }

    @app.get("/api/dashboard")
    def dashboard(id=Depends(officer)):
        raw = local(id, "local.status")
        trades = []
        for t in raw["trades"]:
            if t.get("ticket"):
                terms = t["ticket"]["terms"]
            else:
                terms = {**t["public_terms"], "price": "", "trade_date": ""}
            tasks = []
            for task in t["tasks"]:
                remaining = list(task["required_roles"])
                seen = []
                for approval in task["approvals"]:
                    oid = approval["signed"]["officer_id"]
                    seen.append(oid)
                    role = next(
                        (r for r in remaining if r in node.officers[oid].roles), None
                    )
                    if role:
                        remaining.remove(role)
                can = (
                    t["state"]
                    not in ["CLOSED", "SETTLED", "DECLINED", "HARD_STOP", "TRADE_BREAK"]
                    and task["status"] == "pending"
                    and id not in seen
                    and any(r in node.officers[id].roles for r in remaining)
                )
                tasks.append(
                    {
                        **task,
                        "can_approve": can,
                        "summary": task["action"].replace(".", " ").replace("_", " ")
                        + " at "
                        + node.cfg.legal_name,
                        "approvals": [
                            {
                                "officer_id": a["signed"]["officer_id"],
                                "decision": a["signed"]["decision"],
                                "ts": a["signed"]["ts"],
                                "signature": a["signature"],
                            }
                            for a in task["approvals"]
                        ],
                    }
                )
            checks = [
                {
                    "id": a["question"],
                    "label": a["question"].replace("_", " "),
                    "passed": a["result"] is True
                    or isinstance(a["result"], dict)
                    and (
                        a["result"].get("eligible") is True
                        or a["result"].get("match") is True
                    ),
                    "signed_by": a["answered_by"],
                    "kind": "signed",
                }
                for a in t.get("checks", [])
            ]
            trades.append(
                {
                    **t,
                    "terms": terms,
                    "tasks": tasks,
                    "checks": checks,
                    "created_at": t["events"][0]["ts"] if t["events"] else now(),
                    "machine_ms": t.get("machine_ms", 0),
                    "human_ms": t.get("human_ms", 0),
                }
            )
        return {
            "trades": trades,
            "facilities": [],
            "officer_id": id,
            "mode": node.cfg.mode,
            "node": node.cfg.legal_name,
            "role": node.role,
            "audit_valid": raw["audit_valid"],
        }

    @app.post("/api/bank/initialize", status_code=201)
    def initialize(body: dict, id=Depends(step_up)):
        if "administrator" not in node.officers[id].roles:
            raise ProtocolError("administrator_required")
        signed = {
            "node_id": node.id,
            "officer_id": id,
            "action": "bank.initialize",
            "body_hash": digest(body),
            "ts": now(),
        }
        proof = {"signed": signed, "signature": signers[id].sign(signed)}
        return local(id, "local.import", {**body, "initialization_approval": proof})

    @app.post("/api/trades", status_code=201)
    def create(body: dict, id=Depends(step_up)):
        return local(
            id,
            "local.trade.create",
            {"ticket": {"terms": body, "participants": node.roles}},
            body["trade_id"],
        )

    @app.post("/api/trades/{trade_id}/tasks/{task_id}/decision")
    def decide(trade_id: str, task_id: str, body: Decision, id=Depends(step_up)):
        with node.store.transaction() as s:
            t = node.trade(s, trade_id)
            task = next((x for x in t["tasks"] if x["task_id"] == task_id), None)
            if not task or task["what_hash"] != body.what_hash:
                raise ProtocolError("stale_task", 409)
            payload = node.payload(task)
        signed = {
            "officer_id": id,
            "trade_id": trade_id,
            "task_id": task_id,
            "action": task["action"],
            "what_hash": task["what_hash"],
            "payload_hash": digest(payload),
            "decision": body.decision,
            "reason": body.reason,
            "ts": now(),
        }
        return local(
            id,
            "local.approve",
            {
                "task_id": task_id,
                "approval": {"signed": signed, "signature": signers[id].sign(signed)},
            },
            trade_id,
        )

    @app.post("/api/trades/{trade_id}/readiness")
    def readiness(trade_id: str, id=Depends(officer)):
        return local(id, "local.readiness", trade_id=trade_id)

    @app.post("/api/trades/{trade_id}/request-settlement")
    def settlement(trade_id: str, id=Depends(step_up)):
        return local(id, "local.settle.request", trade_id=trade_id)

    @app.get("/api/trades/{trade_id}/document")
    def document(trade_id: str, id=Depends(officer)):
        with node.store.transaction() as s:
            t = node.trade(s, trade_id)
            if not t.get("ticket"):
                raise ProtocolError("document_not_shared_with_this_role")
            return {"text": node.document(t)}

    @app.get("/api/audit")
    def audit(id=Depends(officer)):
        result = local(id, "local.audit")
        # UI displays the chain metadata, not the sensitive bank-owned envelope bodies.
        return {
            "entries": [
                {k: v for k, v in e.items() if k != "envelope"}
                for e in result["entries"]
            ],
            "chain_valid": result["chain_valid"],
        }

    @app.get("/api/admin")
    def admin(id=Depends(officer)):
        if not set(node.officers[id].roles) & {"administrator", "auditor"}:
            raise ProtocolError("administrator_required")
        return {
            "mode": node.cfg.mode,
            "officers": [
                {
                    "officer_id": o.officer_id,
                    "name": o.name,
                    "institution": node.role,
                    "roles": o.roles,
                }
                for o in node.cfg.officers
            ],
            "peers": [
                {"node_id": p.node_id, "role": p.role, "legal_name": p.legal_name}
                for p in node.cfg.peers
            ],
            "production_enabled": node.cfg.mode == "production",
            "limitations": [],
        }

    dist = Path(
        os.getenv(
            "EXCHANGE_UI_DIR", str(Path(__file__).resolve().parents[2] / "ui" / "dist")
        )
    )
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/")
        def index():
            return FileResponse(dist / "index.html")

    return app
