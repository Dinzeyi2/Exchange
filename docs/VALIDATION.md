# Validation — institution runtime 0.2.0

Executed in this cloud workspace on 2026-11-07. Evidence is for controlled acceptance
fixtures, not a claim that a bank's live systems or money were used.

## Final four-container acceptance

The final image was built after implementation changes and exercised as **four
institution containers plus four independent PostgreSQL containers**. Each node
had only its own config/private keys, data volume and DB credential. Its database
network was isolated from the other institutions. Peer/officer access used pinned
mutual TLS, including the negative security tests.

- All four states: **CLOSED**.
- Trade principal: **$500M**, price **99.75**, exact seller credit **$498.75M**.
- Agent total: **$3B unchanged**. Seller and buyer positions: **$1.5B each**.
- Trade entry → ready: **2,513.31 ms** wall time, including automated fixture approvals.
- Booked agent credit → all receipts: **778.07 ms** wall time.
- **13** signed action approvals, including three-party SSI control and callback reference.
- **13** negative/idempotency checks passed over actual container mTLS connections.
- **482 audited envelope instances** and **28 transported officer-approval instances**
  independently verified. Counts include copies/broadcast records; they are not
  claims of that many distinct trades or unique approvals.
- All four audit chains independently recomputed; privacy disclosures checked.
- Same execution returns its original result, conflicting reuse is refused and a
  second settlement is refused without changing the register again.

The signed evidence is [report.json](acceptance/report.json),
[report.pdf](acceptance/report.pdf) and its [detached signature](acceptance/report.pdf.sig.json).
The JSON includes the tested host source digest and actual container image digest.
The evidence signing key remains outside Git; the report's public key is provided
for integrity verification, not as a bank/go-live trust anchor.

## Additional checks

- **79 Python tests passed**, including independent-process acceptance, OIDC
  signature/audience/issuer/MFA rejection, DB identity isolation, encrypted-record
  context/tamper detection, restart uncertainty and local REST approval boundaries.
  The suite also retains historical prototype regression tests; those are not
  represented as production-node coverage. One upstream Starlette test-client
  deprecation warning remains.
- TypeScript/Vite build passed.
- Chromium browser test passed institution login view, pinned test JWT authentication,
  local trade entry, officer-signed proposal approval, mobile layout and sign-out;
  no JavaScript page errors. That test uses a test IdP key and PKCS#11 software test
  double, **not** a real bank IdP/HSM. It is separate from the container lifecycle.
- JSON signature, PDF hash and detached PDF signature verified independently. PDF
  parsed successfully as a one-page document.
- Default go-live certification returns status 2; explicit `--acceptance` succeeds.
- Python style/import checks and Git whitespace checks passed.

## Not established by these results

Actual bank HSM/IdP/KMS integrations, live authoritative loan-system adapters,
approved legal/consent rules, official bank ISO scheme/XSD behavior, genuine money
movement, bank WAN/sustained-load targets, key rotation, operational recovery,
Kubernetes runtime, signed production updates or independent security approval.
These remain listed in STATUS.md and in the signed report. No environment publish,
external deployment or bank go-live approval is inferred from this run.
