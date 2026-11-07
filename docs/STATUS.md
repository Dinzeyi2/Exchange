# Implementation status — 0.1.0

**This is a reference build, not completed v1 and not ready for bank data or go-live.**
The distinction applies equally to local execution, Docker, Helm and the `certify` command.

| Spec milestone | Delivered | Still required |
|---|---|---|
| 1. Transport, identity, audit | Real pinned mutual TLS 1.3 listeners/client, canonical Ed25519 signing, timestamp/replay/sender binding checks, bounded requests, persistent hash chain, on-demand verification | Bank identity enrollment/rollover, dual admin bundle approval, scheduled verification/WORM anchoring, PostgreSQL append-only privileges/migrations, delivery accounting |
| 2. Catalog and adapters | Fixed question allowlist, per-role authorization, self-position and self-SSI restrictions, signed answers, policy hash, CSV/configured SQL-view readers, integer valuation/ABA/LEI/calendar helpers | Full canonical normalized schema/migrations, live role-specific adapters, bank view conformance and idempotent external register writer, stricter per-question enums/limits, canonical int64 wire strings |
| 3. Workflow | Deterministic persisted local sandbox, ten checks, gap tasks, exact buyer-booked fixture affirmation, terminal hard stops/trade breaks, transactional rechecks | Distributed workflow dispatcher/recovery, nine remote checks integrated into workflow, consent timers/deemed-consent agreements, explicit full transition table/reconciliation states |
| 4. Actions and approvals | Signed local named approvals, officer role rules, distinct SSI dual control, rejection reasons, hash-bound KYC/SSI tasks, synthetic KYC/SSI/consent/doc actions | Actual explicit peer data release with destination restrictions, authenticated bank identities, KYC validation/attestation, signed consent and proposal delivery, per-node document verification |
| 5. Payments and receipts | Exact-price synthetic credit reconciliation, atomic reference register transfer, trade/execution idempotency, signed receipt, durable payment intent, XML builder/parser and explicit XSD helper | Bank XSDs, transactional file/MQ exporter, receipt delivery/acknowledgments, agent-to-seller disbursement, seller camt match, own-book updates, CLOSED and uncertain-outcome reconciliation |
| 6. UI | React/TS local workspace, approval inbox, trade dashboard/checklist/timeline, document preview, reference event durations, audit chain view, officer directory/integration status, search/filter, responsive layouts | Production officer SSO/MFA, internal notifications, editable dual-control peer/catalog/update admin, verified remote answer badges, consent countdown/T+ counters, legal bank templates |
| 7. Simulation | Local synthetic $500M lifecycle; four separate mTLS listeners/keys/databases; nine parallel signed questions; timing reports | Four-container full distributed lifecycle with planted gaps and who-saw-what verification, 20 concurrent trades and throughput load |
| 8. Production security | PKCS#11 signer interface/backend, strict default peer transport, disabled production startup | Tested HSM sessions/rotation, SSO+step-up, bank KMS encryption of sensitive fields, least-privilege DB deployment, signed update enforcement/dual approval, pen test |
| 9. Certification | Signed JSON reference report, unit/security/integration tests | All §12 cases in distributed production context, adapter and all-message conformance, bank hardware metrics, JSON+PDF go-live certification |
| 10. Pilot | Dockerfile, Compose sandbox, Helm sandbox, security/runbook/decisions/spec docs | Signed images, SBOM/reproducible release verification, isolated four-node acceptance, backup/restore and bank installation certification |

The local workflow never sends raw data to peers. No claim is made that this alone
satisfies acceptance criterion 4: the complete four-node workflow has not been
implemented, so its end-to-end who-saw-what report cannot yet be generated.

## Next implementation sequence

1. Normalize persistence and apply PostgreSQL migrations/least-privilege roles.
2. Implement each typed peer action with per-role storage and explicit release policy; bind approvals to the bank-authenticated officer and exact payload.
3. Wire remote signed readiness results and the distributed state machine; add durable outbox, same-execution reconciliation and consent timing.
4. Integrate bank HSM, SSO/MFA, KMS, legal templates and ISO scheme/XSDs.
5. Run four-container acceptance, security/privacy inspection and measured load; generate go-live certification only after those checks pass.
