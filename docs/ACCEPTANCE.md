# Specification §17 acceptance

The automated harness uses **independent processes or containers**, real pinned
TLS sockets, separate databases and keys, a $500M assignment, required borrower
consent, a new-lender KYC gap and an incorrect buyer SSI record.

| Criterion | Automated assertion |
|---|---|
| 1. Four-node lifecycle | Seller, buyer, agent and borrower run separately. Proposal, affirmation, KYC request/release/clearance, SSI change, consents, agreement signatures, funding notice, seller request, register transfer, receipts and acknowledgments travel over signed mTLS envelopes. All four reach CLOSED. |
| 2. Timing | End-to-end entry→ready wall time is required to be ≤30 s; booked credit→receipt delivery wall time ≤10 s. These include automated fixture approvals and are not extrapolated to human response times or a bank WAN. |
| 3. Final books | Agent register total stays $3B; seller principal changes $2B→$1.5B and buyer $1B→$1.5B. Seller payment-hub credit matches exactly $498.75M at 99.75. No node updates another node's books. |
| 4. Who saw what | Audit-derived report checks seller/borrower never receive buyer account or KYC values, the borrower never receives price/purchase-price data, and actual funding-release notices go only buyer→agent. The agent receives KYC/SSI with payload-bound officer release signatures. |
| 5. Integrity/security | Audit chains are independently recomputed; accepted node envelopes and officer approvals are independently verified. Negative network tests cover unlisted/wrong-peer questions, replay, stale/tampered envelopes, TLS sender mismatch, non-seller settlement, missing settlement prerequisites, bad ABA and missing KYC documents. Modified answers/receipts fail verification. |
| 6. No second settlement | Duplicate trade creation is refused. The same execution returns its original result; conflicting payload reuse is refused; a new settlement execution on the closed trade is refused. Register positions are checked again. |

## Precise privacy interpretation

A seller already knows the agreed purchase price from its own booked trade. The
specified `funds_available` question includes that purchase price in its signed
parameters. This is **not** a disclosure of the buyer's actual payment-hub credit
record. The privacy assertion concerns actual funding/credit details and buyer
account/KYC data. Hiding the agreed purchase price from the seller would conflict
with its booked trade and the question catalog; the report does not claim that.

The privacy report includes rejected negative-test attempts in the audit history;
they do not become authorized bank data or state changes. No legitimate KYC or SSI
release occurs without the relevant payload-bound officer approval.

## What passing does not establish

Fixture acceptance is not a bank go-live certificate. It does not validate actual
bank HSM hardware, an actual bank IdP/MFA policy, KMS key delivery/rotation, a
vendor loan-system adapter, bank legal documents, bank payment scheme XSDs, real
money movement, independent penetration testing or operational recovery on the
bank's hardware. Those remain explicit report fields, never inferred from the
containers passing. The default certification command fails the go-live gate.
