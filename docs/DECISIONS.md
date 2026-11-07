# Engineering decisions — institution runtime

1. **Four independent services.** The shared workflow was removed from the entry
   point and moved to historical `prototype/legacy/`. No institution runtime imports
   it. Each node has a separate database and validates its persisted identity before
   reading bank records. Use the existing checkout; no extra worktree by default.
2. **Closed protocol.** Each message has a Pydantic schema, fixed origin/destination
   roles and an execution ID. Peer and officer TLS interfaces have separate trust
   stores. The local REST API is never mounted on either peer listener.
3. **Exactly-once local effects.** PostgreSQL advisory locking serializes node
   mutations; effects and inbound execution results commit together. A transactional
   outbox handles cross-node messages. This does not pretend to be a distributed
   database transaction: failures are represented explicitly and reconciled.
4. **Human authority.** Bank employee identity comes from pinned OIDC keys and a
   local subject mapping; fresh MFA gates approvals. Officer approval records are
   signed with the corresponding PKCS#11 key. The officer command listener requires
   both its pinned certificate/signature and bank authentication in production.
5. **Explicit release.** KYC document types/hashes and agent recipient are bound to
   the buyer's approval. SSI content is hash-bound to the lender treasurer and two
   distinct agent officers; the second officer records callback evidence. Borrower
   messages deliberately omit price, account, KYC and payment-hub details.
6. **Own books only.** The agent writes only its register, each lender writes only
   its positions and the seller reconciles its own hub credit. No node owns another
   node's DB credential or private key. Bank vendor-system integration is an
   explicit boundary, not implied by initializing the node's ledger.
7. **No invented funds.** Funding approval creates a payment intent/file, not a
   credit. Agent settlement requires its own booked camt.054 credit with the exact
   account, execution and purchase price. Seller closure requires a separate credit.
8. **Crash safety over automatic retry.** Uncertain messages/exports retain their
   execution identity and become reconciliation work. A signed operator may retry
   only the same network execution; interrupted hub-file export is never blindly
   retried. Bank hub acknowledgment recovery still needs bank-specific integration.
9. **Canonical values.** Backend money is integer cents/Decimal with half-up rounding.
   JSON integer inputs are limited to RFC 8785's safe integer range; larger int64
   values require a future canonical decimal-string wire representation. Payment
   execution references are deterministic hashes fitting ISO Max35Text.
10. **Production vs test credentials.** Production is the default and requires HSM,
    OIDC, approved policy/template and payment XSD configuration. Certification is
    an explicit configuration of the same runtime, with generated fixture keys,
    books and hub evidence. It is not an alternate shared workflow.
11. **Evidence scope.** Reports verify independent execution, books, privacy, signatures,
    rejection cases and timing with controlled fixtures. They cannot establish actual
    bank HSM/IdP/KMS/payment/loan-system readiness or independent security approval.
    JSON/PDF evidence is signed; default go-live certification remains refused.
12. **No external telemetry.** Runtime code has no analytics, LLM, central storage or
    payment-rail connection. OIDC JWT verification uses locally pinned JWKS; browser
    sign-in goes to the bank's own IdP. Package downloads occur only at build time.
