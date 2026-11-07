# Implementation status — 0.2.0

## Implemented institution architecture

- Four independent role-specific processes/containers; four private databases;
  separate node/officer/agreement/TLS identities and field-encryption keys.
- Full distributed settlement path through typed, signed envelopes over pinned
  mutual TLS 1.3. No shared node object, database or production fixture seeding.
- Local officer roles and payload-bound signed approvals, two distinct agent SSI
  officers, required second-officer callback reference, independent agreement
  verification, and approval signature rechecking at settlement.
- Per-node book updates from signed agent receipts; exact booked-credit matching
  in the agent's own hub account; separate seller disbursement and reconciliation.
- Durable encrypted outbox, atomic inbound execution ledger, restart recovery,
  signed outcome queries, same-execution manual retry, duplicate/conflict refusal.
- AES-GCM encryption of sensitive local records and envelope audit bodies;
  append-only audit triggers, hash chains, startup/hourly/on-demand verification.
- Bank OIDC pinned-JWKS verification, local employee mapping, fresh MFA checks,
  PKCS#11 node/officer backends and local React/REST workspace. The production
  configuration refuses software signing, missing bank controls or fixture templates.
- Four-container/four-PostgreSQL acceptance harness, negative network security
  tests, independently verified signatures/privacy report and signed JSON/PDF evidence.

Historical shared workflow code is retained only in `prototype/legacy/` for old
tests and source history. It is not a production entry point or image component.

## Required before a bank uses real positions or payments

These are not claims satisfied by the fixture run:

1. Provision and exercise the bank's actual HSM module/token/keys, pinned peer and
   officer identities, and bank OIDC/MFA policy; validate certificate/JWKS/key
   rotation, revocation and break-glass operation.
2. Deliver the bank-managed data key securely and establish field-key rotation,
   retention and recovery. Bank disk encryption, WORM anchoring and administrator
   privilege separation remain deployment responsibilities.
3. Integrate and reconcile the authoritative agency/loan/OMS/KYC/treasury systems.
   The current signed import initializes the node's own ledger; it is not a
   continuously synchronized vendor-specific bank adapter. Initial import is not
   an unrestricted way to overwrite live positions.
4. Supply and validate legal agreement text, consent rules/exemptions/response
   windows, jurisdiction/holiday conventions, and approved catalog parameters.
   Full deemed-consent scheduling and all facility-specific exceptions are not
   certified by the planted consent-required scenario.
5. Supply the bank's official ISO scheme XSDs and real payment-hub file ownership,
   acknowledgments and reconciliation contracts. Production XSD validation is
   mandatory; acceptance fixtures do not substitute for scheme certification.
   Ambiguous export recovery deliberately requires bank investigation and must
   not be resolved by deleting an outbox row or generating a new payment ID.
6. Validate the deployment's bank firewall/network policy, internal HTTPS ingress,
   least-privilege DB roles, backup/restore, failure/partition recovery, sustained
   load and bank WAN latency. The Helm template has not been run in a bank cluster.
7. Complete independent security/vendor review and the remaining release controls:
   signed images/SBOM/update verification and dual-admin configuration/update UI.

`exchange certify --acceptance` means the distributed fixture suite passed.
`go_live_eligible` is false until the above bank-specific evidence exists. This
release must not be sold or operated as an already-certified production bank
installation merely because the architecture and fixture acceptance pass.
