# Node security model

## Identity and transport

Institution peers use a dedicated TLS 1.3-only listener with mutual authentication,
configured peer trust anchors and an exact certificate→envelope-sender fingerprint
check. HTTP clients verify the exact peer certificate and Ed25519 response signer,
recipient, trade ID, protocol version, request nonce and timestamp. RFC 8785
canonical JSON is signed. Replays are cached for at least ten minutes; timestamps
must be within 120 seconds. Unknown message types/routes/questions are refused.

Officer certificates use a separate listener/trust store; a node certificate cannot
call officer commands. Production officer commands additionally require a pinned
bank JWT mapped to the same officer, with fresh MFA for consequential actions.
Local REST uses the same bank identity policy and PKCS#11 officer keys. JWT role
claims are not authority: employee→officer→roles is local approved configuration.
Only EdDSA/RS256 pinned JWKS keys are accepted; untrusted key URL headers and
algorithm confusion are refused.

Both institution and officer HSM key possession are checked at startup. Software
node keys are accepted only in explicit `mode: certification`. Private peer or
officer signing keys are never provisioned into another institution's node.

## Data isolation and release

Each database is bound to one node identity. Import allows only role-owned record
families and is a signed, one-time operation. A seller cannot initialize buyer KYC,
an agent cannot initialize buyer cash, and the borrower receives only the consent
summary and settlement receipt fields, without price/SSI/KYC/funding data.

KYC release binds the policy-required document types/hashes and agent recipient.
SSI release binds its exact hash and recipient; agent acceptance is independently
signed by two distinct officers with a second-officer callback reference.
Documents, consents and funding/settlement approvals bind exact trade hashes.
Signed receipts are independently verified before local position updates.

Sensitive bank records, task and outbox payloads and full peer audit envelopes use
AES-256-GCM with record-specific authenticated context. Keys must be delivered
through the bank's KMS/secret process. Production disk encryption, least-privilege
roles and key backup/rotation are bank deployment controls, not outcomes proved by
fixture tests. Never share a field key across banks.

## Payments and uncertain outcomes

No payment rail connection exists. Only the institution's local hub files are
consumed/exported. Bank-authorized hub directory ownership and the configured ISO
scheme XSDs are required in production. Peer funding notices never substitute for
a booked credit on the agent's own settlement account. Exact amount, account,
execution identity and credit consumption are checked in the settlement transaction.

Network actions have an immutable execution ledger and durable outbox. Repeated
executions return their original result; conflicting reuse is rejected. Restarted
SENDING/EXPORTING records become `NEEDS_RECONCILIATION`. The file adapter does not
blindly re-export an uncertain payment. Manual network retry requires a signed
operator request and preserves the original execution ID and payload.

## Audit and operational trust

Inbound messages are recorded before business dispatch. Outbound records distinguish
send intent, signed response and durable delivery state; a queued entry does not
claim remote receipt. Audit tables have append-only mutation triggers in SQLite
and PostgreSQL. Hash verification runs at startup, hourly and on demand. Production
schema migration and runtime database roles are separate operations.

A database owner can alter triggers or rewrite a whole chain. Bank privilege
separation and external WORM anchoring are still needed against privileged tampering.
JWT-bearing local commands are hash-recorded with credentials redacted. Large local
read responses are hash-anchored instead of recursively embedded in audit exports.

## What must still be reviewed at the bank

Actual HSM capabilities/PIN handling and certificate/key rotation; bank IdP/MFA and
revocation; data-key rotation; source-system reconciliation; legal/consent policy;
payment hub custody/XSDs/acknowledgments; backup/restore and partition recovery;
network/TLS ingress and filesystem mounts; independent penetration testing; signed
release/update verification and dual-admin configuration controls. The acceptance
report explicitly retains `go_live_eligible: false` until such evidence exists.
