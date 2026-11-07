import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from node.adapters.models import TradeInput
from node.audit.store import Store
from node.documents.agreement import agreement
from node.signer.backends import SoftwareSigner
from node.transport.protocol import ProtocolError
from prototype.legacy.workflow import OFFICERS, Workflow


class Login(BaseModel):
    officer_id: str
    password: str = Field(max_length=200)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str
    reason: str = Field(default="", max_length=1000)
    what_hash: str


def create_app(data_dir=None, password=None, seed_data=True):
    if os.getenv("EXCHANGE_MODE", "demo") != "demo":
        raise RuntimeError(
            "Production startup disabled: SSO, KMS, peer workflow and bank adapters require integration. See docs/STATUS.md."
        )
    path = Path(data_dir or os.getenv("EXCHANGE_DATA_DIR", ".local"))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    password_file = path / "demo-password"
    if password is None:
        password = os.getenv("EXCHANGE_DEMO_PASSWORD")
        if not password:
            if not password_file.exists():
                fd = os.open(password_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(secrets.token_urlsafe(24))
            password = password_file.read_text().strip()
    store = Store(
        os.getenv("EXCHANGE_DATABASE_URL", f"sqlite:///{path / 'exchange.db'}")
    )
    signer = SoftwareSigner.load_or_create(path / "node-key.pem")
    officer_signers = {
        id: SoftwareSigner.load_or_create(path / (id + ".pem")) for id in OFFICERS
    }
    workflow = Workflow(store, signer, officer_signers)
    if seed_data:
        from prototype.legacy.seed import seed

        seed(workflow)
    app = FastAPI(title="Exchange reference sandbox", version="0.1.0")
    app.state.workflow = workflow
    app.state.store = store
    bearer = HTTPBearer(auto_error=False)
    import time

    sessions = {}
    attempts = {}

    @app.middleware("http")
    async def security(request, call_next):
        if request.headers.get("origin") and request.headers.get("origin") != str(
            request.base_url
        ).rstrip("/"):
            return JSONResponse({"detail": "cross_origin_denied"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def authenticated(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
        if not credentials:
            raise HTTPException(401, "authentication_required")
        session = sessions.get(
            hashlib.sha256(credentials.credentials.encode()).hexdigest()
        )
        if not session or session["expires"] < time.time():
            raise HTTPException(401, "session_expired")
        return session["officer"]

    @app.exception_handler(ProtocolError)
    async def protocol_error(request, error):
        return JSONResponse({"detail": error.code}, status_code=error.status)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": "demo", "software_keys": True}

    @app.get("/api/demo/officers")
    def demo_officers():
        return [
            {"officer_id": id, "name": name, "institution": institution, "roles": roles}
            for id, (name, institution, roles) in OFFICERS.items()
        ]

    @app.post("/api/session")
    def login(body: Login, request: Request):
        ip = request.client.host
        bucket = int(time.time() // 60)
        key = (ip, bucket)
        # Bounded per-process development limiter. Production SSO is intentionally unavailable.
        for old in list(attempts):
            if old[1] < bucket - 1:
                attempts.pop(old)
        attempts[key] = attempts.get(key, 0) + 1
        if attempts[key] > 20:
            raise HTTPException(429, "too_many_attempts")
        if body.officer_id not in OFFICERS or not hmac.compare_digest(
            body.password.encode(), password.encode()
        ):
            raise HTTPException(401, "invalid_credentials")
        token = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(token.encode()).hexdigest()] = {
            "officer": body.officer_id,
            "expires": time.time() + 3600,
        }
        with store.transaction() as s:
            store.audit(s, "session.created", {"officer_id": body.officer_id})
        return {"token": token, "officer_id": body.officer_id, "expires_in": 3600}

    @app.delete("/api/session")
    def logout(
        credentials: HTTPAuthorizationCredentials = Depends(bearer),
        officer=Depends(authenticated),
    ):
        sessions.pop(hashlib.sha256(credentials.credentials.encode()).hexdigest(), None)
        return {"signed_out": True}

    @app.get("/api/dashboard")
    def dashboard(officer=Depends(authenticated)):
        with store.transaction() as s:
            trades = store.list(s, "trade")
            facilities = store.list(s, "facility")
        for t in trades:
            for task in t["tasks"]:
                task["can_approve"] = (
                    t["state"]
                    not in [
                        "CANCELLED",
                        "DECLINED",
                        "HARD_STOP",
                        "TRADE_BREAK",
                        "SETTLED",
                        "CLOSED",
                    ]
                    and task["status"] == "pending"
                    and workflow.can_approve(task, officer)
                )
            t["machine_ms"] = sum(e["machine_ms"] for e in t["events"])
            t["human_ms"] = sum(e["human_ms"] for e in t["events"])
            # Current outstanding wait is added at read time.
            if t["events"] and t["state"] not in [
                "SETTLED",
                "CLOSED",
                "CANCELLED",
                "DECLINED",
                "HARD_STOP",
                "TRADE_BREAK",
            ]:
                from datetime import datetime, timezone

                t["human_ms"] += max(
                    0,
                    int(
                        (
                            datetime.now(timezone.utc)
                            - datetime.fromisoformat(t["events"][-1]["ts"])
                        ).total_seconds()
                        * 1000
                    ),
                )
        return {
            "trades": trades,
            "facilities": facilities,
            "officer_id": officer,
            "mode": "demo",
            "node": "Reference sandbox",
            "audit_valid": store.verify_audit_chain(),
        }

    @app.post("/api/trades", status_code=201)
    def create(body: TradeInput, officer=Depends(authenticated)):
        if officer != "seller-trader":
            raise HTTPException(403, "seller_trader_required")
        return workflow.create(body.model_dump(), officer)

    @app.post("/api/trades/{trade_id}/tasks/{task_id}/decision")
    def decide(
        trade_id: str, task_id: str, body: Decision, officer=Depends(authenticated)
    ):
        with store.transaction() as s:
            t = workflow.load(s, trade_id)
            task = next((x for x in t["tasks"] if x["task_id"] == task_id), None)
            if not task or body.what_hash != task["what_hash"]:
                raise HTTPException(409, "stale_task")
        return workflow.decide(trade_id, task_id, officer, body.decision, body.reason)

    @app.get("/api/trades/{trade_id}/document")
    def document(trade_id: str, officer=Depends(authenticated)):
        with store.transaction() as s:
            return {"text": agreement(workflow.load(s, trade_id)["terms"])}

    @app.get("/api/audit")
    def audit(officer=Depends(authenticated)):
        with store.transaction() as s:
            rows = store.audit_rows(s)
        return {
            "entries": rows,
            "chain_valid": store.verify_audit_chain(),
            "node_public_key": base64.b64encode(signer.public_key).decode(),
        }

    @app.get("/api/admin")
    def admin(officer=Depends(authenticated)):
        return {
            "mode": "demo",
            "officers": [
                {
                    "officer_id": id,
                    "name": v[0],
                    "institution": v[1],
                    "roles": v[2],
                    "public_key": base64.b64encode(
                        officer_signers[id].public_key
                    ).decode(),
                }
                for id, v in OFFICERS.items()
            ],
            "peers": [],
            "production_enabled": False,
            "limitations": [
                "No SSO or step-up MFA",
                "No bank KMS or HSM configured",
                "Workflow is a synthetic local sandbox; peer transport is tested separately",
                "No live bank accounts or payment connections",
            ],
        }

    @app.post("/api/demo/trades/{trade_id}/booked-credit")
    def simulate_credit(trade_id: str, officer=Depends(authenticated)):
        if officer != "agent-officer":
            raise HTTPException(403, "agent_officer_required")
        with store.transaction() as s:
            t = workflow.load(s, trade_id)
            # A sandbox-only fixture, explicitly distinct from a real payment confirmation.
            credit = {
                "execution_id": t["execution_id"],
                "amount": t["purchase_price"],
                "account": "DEMO-AGENT-SETTLEMENT",
                "source": "synthetic_camt_fixture",
            }
        return workflow.receive_credit(trade_id, credit)

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
