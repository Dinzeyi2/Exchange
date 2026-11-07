"""Four institution containers, four isolated PostgreSQL containers, network-only acceptance."""

import json
import os
import secrets
import subprocess
from pathlib import Path
from uuid import uuid4

import yaml

from certify.distributed import Acceptance, camt, wait_for
from certify.provision import ROLES, provision

DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]
ENV = {
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


def command(*args, env=None, input=None):
    result = subprocess.run(
        DOCKER + list(args),
        env=env or ENV,
        input=input,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode().strip()


def write_compose(root, manifest, prefix):
    services = {}
    networks = {"peers": {}}
    for i, role in enumerate(ROLES):
        networks[role + "-private"] = {"internal": True}
        node = manifest["nodes"][role]
        node["host_peer_port"] = 28443 + i
        password = secrets.token_urlsafe(32)
        # These files belong exclusively to this node's deployment configuration.
        envpath = Path(node["root"]) / "runtime.env"
        node["env"]["EXCHANGE_DATABASE_URL"] = (
            f"postgresql+psycopg://exchange:{password}@{role}-db/exchange"
        )
        envpath.write_text("".join(k + "=" + v + "\n" for k, v in node["env"].items()))
        dbpath = Path(node["root"]) / "database.env"
        dbpath.write_text(
            "POSTGRES_USER=exchange\nPOSTGRES_DB=exchange\nPOSTGRES_PASSWORD="
            + password
            + "\n"
        )
        dbpath.chmod(0o600)
        services[role + "-db"] = {
            "image": "postgres:16-bookworm",
            "container_name": prefix + "-" + role + "-db",
            "env_file": [str(dbpath)],
            "networks": [role + "-private"],
            "healthcheck": {
                "test": ["CMD-SHELL", "pg_isready -U exchange -d exchange"],
                "interval": "1s",
                "timeout": "3s",
                "retries": 60,
            },
            "volumes": [role + "-postgres:/var/lib/postgresql/data"],
        }
        services[role] = {
            "image": "exchange-node:distributed",
            "container_name": prefix + "-" + role,
            "env_file": [str(envpath)],
            "volumes": [str(Path(node["root"])) + ":/config:ro", role + "-data:/data"],
            "ports": [f"127.0.0.1:{19443 + i}:9443", f"127.0.0.1:{28443 + i}:8443"],
            "networks": ["peers", role + "-private"],
            "depends_on": {role + "-db": {"condition": "service_healthy"}},
            "read_only": True,
            "tmpfs": ["/tmp"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
        }
    compose = {
        "services": services,
        "networks": networks,
        "volumes": {r + suffix: {} for r in ROLES for suffix in ["-data", "-postgres"]},
    }
    path = root / "compose.yaml"
    path.write_text(yaml.safe_dump(compose))
    return path


def run(root, keep=False):
    root = Path(root).resolve()
    manifest = provision(root, containers=True)
    prefix = "exchange-accept-" + uuid4().hex[:8]
    compose = write_compose(root, manifest, prefix)
    base = ["compose", "--project-name", prefix, "--file", str(compose)]
    try:
        config = yaml.safe_load(compose.read_text())
        for role in ROLES:
            volume = prefix + "-" + role + "-config"
            command("volume", "create", volume)
            command(
                "run",
                "--rm",
                "--user",
                "0",
                "--entrypoint",
                "python",
                "--volume",
                manifest["nodes"][role]["root"] + ":/source:ro",
                "--volume",
                volume + ":/target",
                "exchange-node:distributed",
                "-c",
                "import os,shutil;shutil.copytree('/source','/target',dirs_exist_ok=True);"
                "[(os.chown(r,10001,10001),[os.chown(os.path.join(r,f),10001,10001) for f in files]) for r,dirs,files in os.walk('/target')]",
            )
            config["volumes"][role + "-config"] = {"external": True, "name": volume}
            config["services"][role]["volumes"][0] = role + "-config:/config:ro"
        compose.write_text(yaml.safe_dump(config))
        command(*base, "up", "--detach", "--wait", "--wait-timeout", "120")
        acceptance = None

        def hub(source, destination, payment_id, account):
            container = prefix + "-" + source
            path = "/data/hub/outbox/" + payment_id + ".xml"

            def exists():
                try:
                    command("exec", container, "test", "-f", path)
                    return True
                except subprocess.CalledProcessError:
                    return False

            wait_for(exists)
            xml = command("exec", container, "cat", path)
            from decimal import Decimal

            from lxml import etree as E

            doc = E.fromstring(xml.encode())
            amount = int(Decimal(doc.findtext(".//{*}IntrBkSttlmAmt")) * 100)
            content = camt(payment_id, amount, account)
            target = prefix + "-" + destination
            # A distinct bank hub process drops its notification; no node fabricates credits.
            script = (
                "import os,sys;from pathlib import Path;p=Path('/data/hub/inbox');p.mkdir(parents=True,exist_ok=True);f=p/'incoming.tmp';f.write_bytes(sys.stdin.buffer.read());os.replace(f,p/'"
                + payment_id
                + ".xml')"
            )
            command(
                "exec", "--interactive", target, "python", "-c", script, input=content
            )
            return amount

        acceptance = Acceptance(manifest, hub)
        for role in ROLES:
            wait_for(lambda role=role: acceptance.status(role), timeout=60)
        report = acceptance.run()
        report["deployment"] = (
            "four independent institution containers plus four PostgreSQL containers"
        )
        # Confirm runtime filesystem and network boundaries, without reading DB credentials.
        report["isolation"] = {}
        for role in ROLES:
            metadata = json.loads(command("inspect", prefix + "-" + role))[0]
            mounts = [m["Destination"] for m in metadata["Mounts"]]
            assert sorted(mounts) == ["/config", "/data"]
            networks = list(metadata["NetworkSettings"]["Networks"])
            assert len(networks) == 2
            report["isolation"][role] = {
                "mount_destinations": mounts,
                "networks": networks,
                "node_id": acceptance.status(role)["node_id"],
                "image_id": metadata["Image"],
            }
        (root / "report.json").write_text(json.dumps(report, indent=2))
        return report
    finally:
        if not keep:
            command(*base, "down", "--volumes", "--remove-orphans")
            for role in ROLES:
                subprocess.run(
                    DOCKER + ["volume", "rm", prefix + "-" + role + "-config"],
                    env=ENV,
                    capture_output=True,
                    check=False,
                )


if __name__ == "__main__":
    import sys

    print(json.dumps(run(sys.argv[1]), indent=2))
