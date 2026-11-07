# Exchange

An on-prem loan assignment settlement **reference implementation** based on [the supplied v1 specification](docs/SPEC.md).

This build includes a working React approval workspace, a deterministic synthetic settlement lifecycle, signed officer approvals, a persistent audit chain, and separately exercised peer messaging over pinned mutual TLS 1.3. **It is not the completed production v1.** Read [implementation status](docs/STATUS.md) before connecting bank systems. Production startup deliberately fails closed.

## Run locally

Requires Python 3.12+, Node.js 24 and npm. From this existing checkout (no extra worktree needed):

```sh
export UV_CACHE_DIR=/workspace/.cache/uv   # Cloud workspace; omit on other machines
uv sync --frozen --extra test
npm --prefix ui ci --cache /workspace/.cache/npm
npm --prefix ui run build
.venv/bin/exchange serve
```

The node serves the compiled UI on its local API port (8000). Sign in with a demo officer and the password stored in `.local/demo-password`. Keys and local data are generated on first startup with restricted file permissions. The demo password is shared between synthetic identities; **this is not officer authentication suitable for a bank**. Sign out to switch identities.

Three synthetic $500M assignments are preloaded. Approve a proposal as the seller trader, release KYC as buyer ops, clear KYC as agent KYC, approve SSI as the buyer treasurer and two distinct agent officers, obtain agent and borrower consent, collect three document signatures, then approve funding. As the agent officer, use the explicitly labeled synthetic booked-credit control and approve settlement. The local register transfer is atomic and idempotent. New manually entered trades without matching buyer booked trades go to `TRADE_BREAK` on proposal.

No software in this build connects to a payment network or moves money. The local workflow combines synthetic role data for demonstrations; real institutions must run separate nodes and must never load their raw data into this sandbox.

## Validate

```sh
.venv/bin/pytest -q
.venv/bin/exchange demo
.venv/bin/python -m sim.network
.venv/bin/exchange certify --reference
.venv/bin/exchange verify-audit
```

`demo` runs a fresh synthetic assignment with automated approvals and prints timings and register invariants. `sim.network` starts four distinct mTLS listeners with separate databases and keys, verifies 20 signed question/answer round trips and runs nine questions concurrently. This is not a distributed settlement scenario.

`certify` writes a signed JSON **reference report** under `.local/certification`; `go_live_eligible` is always false. It does not claim the bank certification in §14. Without `--reference`, the command exits with status 2 because go-live requirements remain incomplete. `verify-audit` verifies the local event chain.

Optional UI smoke test (uses installed system Chromium):

```sh
uv pip install playwright
.venv/bin/python scripts/smoke_ui.py
```

It launches its own temporary sandbox, exercises browser login, approvals, officer switching, audit, administration and a mobile viewport, and saves local screenshots under `.local/screenshots`.

## Pilot packaging

```sh
docker build -f deploy/Dockerfile -t exchange-node:0.1.0 .
# Set a local development database password through the shell / your secret manager:
docker compose -f deploy/docker-compose.pilot.yml up --build
```

Compose requires `EXCHANGE_DB_PASSWORD`; do not commit it. In a managed cloud TLS-inspection environment, pass `--secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt` to the Docker build. Certificate verification remains enabled. See [the runbook](docs/RUNBOOK.md) for isolated networking, persistent volumes, and air-gap image transfer.

The Helm reference chart exposes only a ClusterIP service with default-deny egress. It is development packaging, not a signed production release.

## Documentation

- [Implementation status and outstanding requirements](docs/STATUS.md)
- [Validation evidence](docs/VALIDATION.md)
- [Engineering decisions](docs/DECISIONS.md)
- [Security boundaries and review scope](docs/SECURITY.md)
- [Operations runbook](docs/RUNBOOK.md)
- [Reference protocol](protocol/PROTOCOL.md)
