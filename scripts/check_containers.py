"""Opt-in local Docker smoke tests. Creates and removes only its own containers."""

import json
import os
import secrets
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from node.api.app import create_app
from node.transport.protocol import ProtocolError
from node.workflow.engine import OFFICERS
from sim.seed import sample_terms

DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]
child_env = {
    k: v
    for k, v in os.environ.items()
    if k
    not in [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ]
}


def command(*args, env=None):
    return subprocess.check_output(
        DOCKER + list(args), env=env or child_env, text=True, stderr=subprocess.PIPE
    ).strip()


def wait(fn):
    for _ in range(120):
        try:
            return fn()
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("Container readiness timeout")


def main():
    names = []
    try:
        web = "exchange-smoke-" + uuid4().hex[:8]
        names.append(web)
        command(
            "run",
            "--detach",
            "--name",
            web,
            "--publish",
            "127.0.0.1::8000",
            "exchange-node:0.1.0",
        )
        port = command("port", web, "8000/tcp").split(":")[-1]
        base = "http://127.0.0.1:" + port
        response = wait(lambda: urllib.request.urlopen(base + "/api/health", timeout=2))
        assert json.load(response)["mode"] == "demo"
        assert b"Exchange" in urllib.request.urlopen(base).read()
        password = command("exec", web, "cat", "/data/demo-password")
        payload = json.dumps(
            {"officer_id": "seller-trader", "password": password}
        ).encode()
        session = json.load(
            urllib.request.urlopen(
                urllib.request.Request(
                    base + "/api/session",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
            )
        )
        request = urllib.request.Request(
            base + "/api/dashboard",
            headers={"Authorization": "Bearer " + session["token"]},
        )
        assert len(json.load(urllib.request.urlopen(request))["trades"]) == 3
        pg = "exchange-pg-" + uuid4().hex[:8]
        names.append(pg)
        pg_env = {**child_env, "POSTGRES_PASSWORD": secrets.token_urlsafe(24)}
        command(
            "run",
            "--detach",
            "--name",
            pg,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_PASSWORD",
            "--env",
            "POSTGRES_USER=exchange",
            "--env",
            "POSTGRES_DB=exchange",
            "postgres:16-bookworm",
            env=pg_env,
        )
        pg_port = command("port", pg, "5432/tcp").split(":")[-1]
        from sqlalchemy import create_engine, text

        url = f"postgresql+psycopg://exchange:{pg_env['POSTGRES_PASSWORD']}@127.0.0.1:{pg_port}/exchange"
        engine = create_engine(url)

        def ping():
            with engine.connect() as c:
                return c.execute(text("SELECT 1")).scalar()

        wait(ping)
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            os.environ["EXCHANGE_DATABASE_URL"] = url
            app = create_app(d, password="isolated-test-password")
            w = app.state.workflow
            id = sample_terms()["trade_id"]

            def load():
                with w.store.transaction() as s:
                    return w.load(s, id)

            for _ in range(40):
                t = load()
                if t["state"] == "FUNDING_SENT":
                    break
                task = next(x for x in t["tasks"] if x["status"] == "pending")
                officer = next(o for o in OFFICERS if w.can_approve(task, o))
                w.decide(id, task["task_id"], officer, "approve")
            assert t["state"] == "FUNDING_SENT"
            w.receive_credit(
                id,
                {
                    "execution_id": t["execution_id"],
                    "amount": t["purchase_price"],
                    "account": "DEMO-AGENT-SETTLEMENT",
                },
            )
            task = next(x for x in load()["tasks"] if x["action"] == "settle.execute")
            second = create_app(d, password="isolated-test-password").state.workflow

            def settle(workflow):
                try:
                    return workflow.decide(
                        id, task["task_id"], "agent-officer", "approve"
                    )["state"]
                except ProtocolError as error:
                    return error.code

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(settle, [w, second]))
            assert sorted(results) == ["SETTLED", "task_not_pending"], results
            with w.store.transaction() as s:
                reg = w.store.get(s, "register:FAC-ATLAS-01")
            assert reg == {
                "Meridian Capital": 150_000_000_000,
                "Northstar Bank": 150_000_000_000,
            }
            assert w.store.verify_audit_chain()
            w.store.engine.dispose()
            second.store.engine.dispose()
            os.environ.pop("EXCHANGE_DATABASE_URL", None)
        engine.dispose()
        print(
            json.dumps(
                {
                    "docker_runtime": "passed",
                    "postgresql_16_lifecycle": "passed",
                    "two_independent_workers_racing_settlement": "one settled; second refused",
                    "register_conservation": "passed",
                    "audit_chain": "valid",
                }
            )
        )
    finally:
        for name in names:
            subprocess.run(
                DOCKER + ["rm", "--force", name],
                env=child_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
