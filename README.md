# Exchange — institution-isolated settlement nodes

Exchange runs as **four independent institution nodes**: seller, buyer, administrative agent and borrower. Every node has its own database, signing identity, agreement key, officer registry, encryption key and payment-hub boundary. No shared settlement application or central database is used.

The deployment entry point is:

```sh
exchange serve --config /config/node.yaml
```

There is no default demo mode, shared password, generated bank book, fake-credit HTTP endpoint or cross-institution officer switch in this runtime. Historical shared code is isolated under `prototype/legacy/` and is excluded from the node image.

## What the runtime executes

1. Seller approval queues a signed trade proposal to the agent and buyer. The buyer affirms only against its independently imported booked trade.
2. Lenders run signed, parallel readiness questions over pinned mutual TLS 1.3. Local positions and SSI remain local; SSI equality uses per-trade X25519/HKDF/HMAC fingerprints.
3. A buyer officer approves the exact required KYC document hashes before release to the agent. Agent KYC clearance requires its own officer approval.
4. SSI release requires the lender treasurer. Acceptance requires two different agent officers; the second must record a callback verification reference.
5. Agent and borrower consent and three document signatures are collected on the appropriate nodes. Signers verify the agreement against their local trade terms.
6. Buyer funding approval creates a durable pacs.008 payment intent for the bank's own hub. **Only a booked camt.054 credit in the agent's own hub inbox can authorize the funding-received state.**
7. A signed seller request and agent officer approval trigger the atomic register transfer. Consent, KYC, document signatures, exact booked funds, seller holdings and idempotency are rechecked in the transaction.
8. The agent issues signed receipts and a separate seller payment instruction. Seller and buyer update only their own positions from the signed agent receipt. The seller closes only after reconciling its independently received payment-hub credit.

Unknown outcomes are persisted as `NEEDS_RECONCILIATION`. A durable inbound execution ledger deduplicates effects across fresh envelopes and restarts. A network retry never gets a new business execution ID. An interrupted payment-file export is never automatically exported again.

## Acceptance evidence

```sh
export UV_CACHE_DIR=/workspace/.cache/uv  # Cloud workspace only
uv sync --frozen --extra test
npm --prefix ui ci --cache /workspace/.cache/npm
npm --prefix ui run build
uv run --frozen pytest -q

# Four separate OS processes, databases, keys and real TLS sockets:
uv run --frozen exchange certify --acceptance --deployment processes

# Four node containers plus four PostgreSQL containers:
docker build -f deploy/four-node/Dockerfile -t exchange-node:distributed .
uv run --frozen exchange certify --acceptance --deployment containers
```

In the managed cloud, add `--secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt` to the Docker build. TLS verification stays enabled.

The acceptance harness represents the four banks' booked records, officers and payment hubs with **explicit test fixtures**. It uses the same node state machine and network protocol as the institution runtime; it does not share node objects or mutate node databases. The fixture controller's credentials are never installed in a bank node. Bank payment-hub test credits do not prove that real money moved.

Reports include JSON, PDF, detached PDF signature, privacy disclosures, independently verified envelope/officer signatures, register/position invariants, duplicate-execution tests and measured timings. `go_live_eligible` remains false until the bank's real integrations and security review are validated. Running `exchange certify` without `--acceptance` therefore exits with status 2 even if fixture acceptance passes.

## Institution deployment

Start with [the production configuration template](deploy/bank-node.example.yaml), not a fixture configuration. Production mode is the default and requires:

- A dedicated PostgreSQL database and least-privilege runtime account. Run `exchange migrate` separately under the authorized migration account; the runtime does not create production tables.
- Bank-provided TLS certificates, exact peer certificate pins, Ed25519 public keys, X25519 identities, legal identities and approved peer officer public-key registrations.
- PKCS#11 node and individual officer keys. Software signing is refused in production.
- Pinned bank OIDC JWKS, issuer/API audience and employee-to-officer mapping. Approvals require MFA within five minutes. Browser sign-in uses authorization code + PKCE.
- An injected 256-bit data-encryption key from the bank's key-management process. SSI, KYC, task payloads, financial outbox payloads and envelope audit bodies are encrypted at rest.
- An approved catalog, bank legal template, bank-approved ISO scheme XSDs, and institution-owned payment inbox/outbox directories.

The local React/REST API runs only when bank OIDC/HSM officer bindings are configured. Serve it behind the bank's internal HTTPS ingress; never expose it as the peer endpoint. The peer listener is 8443; the separately trusted officer mTLS interface is 9443; the internal REST API is 8080. Ports are configurable.

An initial signed, bank-authenticated `local.import` brings that institution's permitted records into its own ledger. It refuses foreign-role data and repeated initialization. This is not a vendor-specific Loan IQ/OMS integration: live source-system reconciliation and operational ownership of this ledger must be validated with the bank before real trading.

[Compose](deploy/docker-compose.pilot.yml) supplies four separate databases/private bank networks. [Helm](deploy/helm/) deploys **one institution per release/namespace**, with explicit peer and DB network policy. Bank-specific HSM modules/devices, hub volumes, TLS ingress and secret delivery must be supplied by the institution.

## Documentation

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Acceptance criteria and their precise scope](docs/ACCEPTANCE.md)
- [Implementation status and remaining bank integration work](docs/STATUS.md)
- [Security model](docs/SECURITY.md)
- [Operations and recovery](docs/RUNBOOK.md)
- [Engineering decisions](docs/DECISIONS.md)
- [Original specification](docs/SPEC.md)
