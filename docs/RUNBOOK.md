# Reference operations runbook

## Startup and health

Follow README.md from the repository root. The local API binds to loopback by
default; `--host 0.0.0.0` is reserved for a controlled container/internal network.
The unauthenticated local `/api/health` returns no trade data. The peer-only
`/v1/health` is a different TLS listener and requires a pinned client certificate.
Live services do not survive a cloud snapshot; restart `exchange serve` after
restoration. Use the existing isolated checkout, not a new worktree.

`.local/` contains the SQLite database, development private keys and sandbox
password. Restrict the containing directory and never commit, attach or email it.
Use `EXCHANGE_DATA_DIR` to relocate it and `EXCHANGE_DATABASE_URL` for pilot
PostgreSQL. Changing the database does not migrate existing synthetic state.
`EXCHANGE_MODE` accepts only `demo` in this release; production fails closed.

## Reference checks

- `pytest -q`: unit, security and integration checks; preserve its exit status.
- `exchange demo`: fresh local $500M assignment with generated keys, automated
  fixture approvals, exact-price credit and unchanged register total.
- `python -m sim.network`: four separate mTLS listeners/DBs/keys on loopback,
  20 signed round trips and nine concurrent catalog checks.
- `exchange verify-audit`: fail on a broken local audit chain.
- `exchange certify --reference --output .local/certification`: signed JSON reference report;
  not bank certification and not a go-live approval. No PDF is generated.

For a broken audit chain stop actions, preserve the database and investigate. Do
not rewrite hashes or remove records to restore a passing result.

## Pilot containers

Build with Docker BuildKit. In cloud TLS inspection environments supply the
combined public CA bundle as the optional `proxy_ca` build secret. Never disable
certificate verification. Runtime containers require no external internet.

Compose uses an isolated internal network, a PostgreSQL volume and a node-data
volume. Only the local REST port is bound to host loopback. Set the demo database
password securely in the environment before running Compose. Never pass real bank
credentials to this sandbox. `docker compose ... down` preserves volumes; adding
`--volumes` destroys local reference data and should only be used intentionally.

The reference Helm chart supplies a PVC, unprivileged pod, probes, namespace-local
ClusterIP, default-deny egress and restricted ingress from labeled UI-client pods.
It is not a bank deployment chart; no HSM/KMS/SSO, peer ingress or signed updates
are configured. Helm/Kubernetes execution must be validated in a real cluster.

For air-gapped **reference evaluation**, transfer the built image with
`docker save -o exchange-reference.tar exchange-node:0.1.0` and load on the isolated
host. Verify the transfer checksum out of band. These are unsigned development
artifacts; they do not satisfy the spec's signed production release process.

## Data, backup and recovery

Stop the reference node before taking a SQLite backup. Preserve DB and all signing
keys together, with restricted permissions; never restore keys into another bank's
identity. For PostgreSQL use bank-standard backup/restore and encryption tooling.
No key recovery, HSM backup, approved certificate rollover, disaster recovery or
release rollback automation is supplied. A signed receipt proves what was signed,
not that a payment left the bank. Do not mark a payment complete based on a file,
a PID or a local simulation.
