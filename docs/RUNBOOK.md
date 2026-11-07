# Institution operations

## Provision one node

Use the existing isolated checkout; do not create another worktree unless requested.
Install with `uv sync --frozen --extra test` for development or build the pinned
Dockerfile. A live node requires explicit `--config`; no shared application starts
without it. Do not use generated certification identities for an actual bank.

Provision the institution's own PostgreSQL database, PKCS#11 module/token/keys,
TLS identity, field-encryption data key, officer identities, pinned peer public
bundles, approved catalog/template, pinned bank OIDC JWKS and hub/XSD configuration.
The full Settings schema is `node/runtime/config.py`; the production example is
`deploy/bank-node.example.yaml`. Secret values belong in bank secret delivery, not
YAML, Git, chat, logs or image layers.

1. Run `EXCHANGE_DATABASE_URL` under the authorized migration DB account and
   `exchange migrate`. This creates the schema and append-only audit triggers.
2. Configure the dedicated runtime DB role with SELECT/INSERT/UPDATE of `records`,
   SELECT/INSERT of `audit_entries`, DELETE of expiring nonce records as required
   by the record store, and sequence usage. It must not own/alter the schema or
   audit triggers. Validate grants against the bank's policy before serving.
3. Deliver `EXCHANGE_DATABASE_URL`, `EXCHANGE_HSM_PIN`, `EXCHANGE_FIELD_KEY` through
   the bank's secret mechanism. The field key is a base64-encoded 32-byte data key.
   Maintain protected backups/rotation procedures; changing it without migrating
   ciphertext will make retained records unreadable.
4. Start `exchange serve --config /config/node.yaml`. Node and officer public-key
   possession is checked; missing production controls fail startup.
5. Expose only 8443 to pinned peer networks. Keep 9443 and 8080 inside the bank.
   Serve the UI/API through the bank's HTTPS ingress, configure trusted forwarding
   correctly, register its exact OIDC redirect URI and enable PKCE/CORS at the bank
   token endpoint. Never expose the internal REST API as the peer endpoint.
6. Use `POST /api/bank/initialize` as a bank-authenticated administrator with fresh
   MFA, or the signed officer `local.import` command. The REST path signs the exact
   initialization hash using that administrator's HSM key. Initialize once for that node's
   approved initial records. It refuses other roles' record families and subsequent
   initialization. Confirm authoritative-book ownership and bank adapter mappings
   before real activity; initialization is not continuous source-system integration.

Production hub inbox/outbox directories must be bank-owned and isolated from peers.
The sender does not generate camt.054 credits; the bank hub supplies booked evidence.
Keep payment outbox files/acknowledgment evidence for reconciliation. The current
file adapter expects its configured inbox/archive path to be writable for moving
processed files; use a bank-controlled drop/archive arrangement with appropriate
least-privilege permissions.

## Health and validation

Peer `/v1/health` requires a pinned mTLS certificate. Local `/api/health` checks the
node identity/database and is available only on the internal REST listener when
bank OIDC is configured. It returns no trade values. Verify audit chains on demand
with the bank auditor interface or `exchange verify-audit --database <local DSN>`;
prefer secure environment/driver configuration instead of exposing credentials in
shell history.

The automatic worker re-runs lender readiness after relevant signed gap events.
An operator can invoke `local.readiness` or the local REST readiness endpoint.
Settlement requires a seller request and an independent agent officer approval;
requesting it before booked credit/prerequisites is refused.

## Unknown network outcome

1. Preserve the outbox record and exact execution ID. Do not create a new trade,
   delete the record, or change the payload to force a retry.
2. An authorized local officer calls signed `local.reconcile` with `outbox_key`.
   The remote execution-status answer is signature-verified and scoped to the
   originating node. A found result resolves delivery without repeating effects.
3. If still unknown, investigate connectivity and the remote node. An explicit
   signed `local.execution.retry` may requeue that same immutable execution with
   a required reason; the receiver ledger prevents a late original request and
   this retry from producing two effects. No automatic financial retry occurs.

## Unknown payment-file outcome

A crash while exporting marks the payment `NEEDS_RECONCILIATION`. Do not delete the
XML/DB row, mark it paid, or issue another payment ID. Obtain the bank hub's durable
acknowledgment/ledger and follow its approved reconciliation process. Automated
bank-hub acknowledgment/retry integration is not yet supplied. Resume only through
an approved bank recovery procedure; this is a go-live integration requirement.

## Acceptance and release

`exchange certify --acceptance --deployment processes` runs four separate processes.
`--deployment containers` runs four node containers and four private PostgreSQL
containers, then removes only its own test resources. The acceptance harness
provisions controlled credentials/books and transfers test hub evidence separately
from the nodes. JSON/PDF reports have signatures and retain explicit bank-control
limitations. Fixture success is not real money movement or a go-live approval.

The default certification command exits 2 until bank evidence is available. Do not
edit the report to claim eligibility. CI does not upload private fixture keys.

Bank image signing, SBOM publication, approved updates, key/certificate rotation,
backup/restore, network firewall policy and change-board approval require the
institution's release process. The included Helm template has not been certified
on a bank cluster. Pin and independently verify release images before use.
