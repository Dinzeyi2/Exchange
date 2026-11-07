# Exchange v1 — Product & Engineering Specification
**On-prem loan trade settlement network**
Version 1.0 · Owner: Obed Mpaka · Status: build spec for implementation

> **Instructions for the coding agent (Codex):** Build exactly what this document describes. Where it says MUST, it is a requirement. Where something is not specified, choose the simplest secure option and record the choice in `docs/DECISIONS.md`. Never add a feature that sends a bank's raw data to another party unless this spec explicitly lists it. A working reference prototype exists (`prototype/exchange_v1_colab.py`); reuse its logic, but production code must follow the structure below.

---

## 1. What Exchange is (one paragraph)

Exchange is software that each institution in a syndicated loan trade (seller, buyer, administrative agent, borrower) installs **inside its own environment**. Each installation is called a **node**. Nodes talk directly to each other over encrypted, mutually authenticated connections. Instead of sending each other files, emails and spreadsheets, nodes ask each other **pre-approved questions** and receive **signed answers**, then carry out **pre-approved actions** after a named person clicks **Approve**. The result: a loan trade that today takes ~T+16 to T+23 business days becomes **ready to settle the same day** and settles on the next business day or sooner, while each bank's data stays in its own systems.

**One line:** *They move the trade or the data. Exchange removes the waiting, without moving the data.*

---

## 2. Scope of v1

### 2.1 In scope
- **One trade type:** secondary **par assignment** of a US syndicated term loan (USD, LSTA-style market practice).
- **Four roles:** Seller, Buyer, Administrative Agent, Borrower.
- **Full lifecycle:** trade entry → affirmation → readiness checks → gap resolution (KYC onboarding, settlement-instruction update) → consents → assignment agreement signing → funding → lender-register update → settlement receipts → close.
- **Approval screen** with one-click signed approvals.
- **On-prem deployment** (Docker + Helm), works with no outbound internet except to pinned peer nodes.
- **Adapters:** one reference adapter (database/CSV), one adapter interface for loan systems (e.g., Loan IQ-style agency systems), file-based payment hub adapter (ISO 20022).

### 2.2 Out of scope for v1 (do NOT build)
- Participations, distressed trades, primary allocations, revolvers with unfunded commitments, non-USD.
- Trading / price discovery (that is Octaura's job).
- Moving money directly. Exchange **never** connects to Fedwire/ACH/SWIFT itself; it hands ISO 20022 files to the bank's own payment hub.
- Replacing ClearPar. (A ClearPar export adapter is a v2 item.)
- Any AI/LLM in the decision path. All logic is deterministic: same input → same output.
- Twin data, tokenized data copies, blockchain.

---

## 3. Speed targets (MUST be measured and reported)

| Metric | Target (on a bank LAN / WAN) |
|---|---|
| Single signed question → answer round trip | p95 ≤ 500 ms |
| Full readiness check set (≥9 checks, parallel) | ≤ 5 s |
| Gap detected → right person notified on approval screen | ≤ 2 s |
| Machine time, trade entry → "Ready to settle" (excluding human clicks and borrower decision) | ≤ 30 s |
| Funds-received notice → register updated → receipts delivered | ≤ 10 s |
| Approval click → next step started | ≤ 1 s |
| Throughput per node | ≥ 1,000 trades/day, ≥ 20 concurrent trades |
| Business outcome | "Ready to settle" same day; settled T+1 to T+3 when people respond |

Every trade records a timeline (`trade_events` table) so each metric can be computed per trade. The dashboard shows **machine time** and **waiting-on-human time** separately.

---

## 4. Architecture

```
          Bank A (Seller)                     Bank C (Agent)                     Bank B (Buyer)
 ┌───────────────────────────┐      ┌───────────────────────────┐      ┌───────────────────────────┐
 │ Loan/position system      │      │ Agency loan system        │      │ OMS / KYC / Treasury      │
 │        │ adapter (read)   │      │        │ adapter (r/w)    │      │        │ adapter (read)   │
 │   ┌────▼──────────────┐   │ mTLS │   ┌────▼──────────────┐   │ mTLS │   ┌────▼──────────────┐   │
 │   │ Exchange Node     │◄──┼──────┼──►│ Exchange Node     │◄──┼──────┼──►│ Exchange Node     │   │
 │   │ API · Catalog ·   │   │      │   │                   │   │      │   │                   │   │
 │   │ Workflow · Signer │   │      │   └────▲──────────────┘   │      │   └───────────────────┘   │
 │   │ Audit · UI        │   │      │        │ mTLS             │      │                           │
 │   └───────────────────┘   │      └────────┼──────────────────┘      └───────────────────────────┘
 │  Bank HSM/KMS · Postgres  │               │
 └───────────────────────────┘      ┌────────▼──────────────────┐
                                    │ Borrower Node (light)     │
                                    └───────────────────────────┘
```

- **No central server holds data.** Nodes connect peer-to-peer. Optional **Relay** (v1.1) forwards encrypted envelopes it cannot read, for banks that refuse inbound connections.
- **Exchange (the company) has no access** to any node, database, key or log. No telemetry containing data leaves a node.

### 4.1 Node components (each is a module in the codebase)

| Component | Responsibility |
|---|---|
| `transport` | mTLS 1.3 server + client, certificate pinning, envelope signing/verification, nonce & timestamp checks |
| `identity` | Node identity (Ed25519 signing key, X25519 key-agreement key, TLS cert), peer registry (pinned public keys/certs), officer keys |
| `signer` | All signing goes through an interface with two backends: `SoftwareSigner` (dev/test) and `HsmSigner` (PKCS#11). Private keys never leave the HSM in production |
| `catalog` | Questions and actions this node will answer/perform, who may call each, parameter limits. Loaded from bank-approved config, hashed (policy hash) |
| `adapters` | Read (and for agent: write) access to the bank's own systems, mapped into the canonical data model |
| `workflow` | Trade state machine, readiness checks, gap detection, task routing, retries, timeouts |
| `approvals` | Approval tasks, officer authentication, signed approval records, dual control rules |
| `documents` | Assignment agreement generation from the bank's template, hashing, multi-party signature collection |
| `payments` | ISO 20022 pacs.008 generation, camt.054 ingestion (file drop or MQ), reconciliation |
| `audit` | Append-only, hash-chained audit log of every inbound/outbound message, answer, approval and action |
| `api` | Local REST API for the bank's own systems and the UI (never exposed to peers) |
| `ui` | Approval screen + trade dashboard + admin console (web, served locally) |
| `ops` | Health checks, metrics (counts and latencies only — no data values), config validation, update verification |

---

## 5. Canonical data model (all adapters map into this)

Monetary amounts: integers in **cents** (`int64`) or `Decimal` strings. Never floats. Dates: ISO 8601. All tables in the node's own PostgreSQL.

```text
Facility        facility_id, borrower_name, type, total_outstanding, rate_desc, maturity,
                min_assignment, assignment_multiple, borrower_consent_required,
                consent_exempt_assignee_types[], agent_consent_required, assignment_fee
LenderPosition  facility_id, lender_legal_name, lender_lei, amount, as_of        (agent: golden source)
OwnPosition     facility_id, amount, pledged_amount, as_of                       (seller/buyer books)
BookedTrade     trade_ref, facility_id, side, amount, price, counterparty, trade_date
KycRecord       lender_legal_name, lei, status(cleared|pending|none), cleared_at, doc_hashes{}
KycFile         document_type → document (bytes) + metadata                       (buyer only)
Ssi             owner_legal_name, bank_name, aba, account, currency, effective_at  (each holds its own; agent holds lenders')
DqList          entity_legal_name                                                 (agent / borrower)
Officer         officer_id, name, title, roles[], public_key
Trade           trade_id, facility_id, amount, price, purchase_price, seller, buyer,
                trade_date, settlement_date, state, created_at
TradeEvent      trade_id, ts, type, actor, machine_ms, payload_hash
Approval        approval_id, trade_id, officer_id, what_hash, summary, decision, ts, signature
Answer          answer_id, trade_id, question_id, params, result, answered_by, policy_hash, ts, signature
Receipt         trade_id, status, payload, signature
AuditEntry      seq, ts, direction(in|out|local), peer, type, body, prev_hash, hash
```

**Validation rules (MUST):** ABA routing checksum, LEI ISO 17442 mod-97 check, US federal holiday business-day calendar, amount = multiple of `assignment_multiple` and ≥ `min_assignment`, purchase price = amount × price / 100 rounded half-up to cents.

---

## 6. Network protocol

### 6.1 Transport
- HTTPS over **TLS 1.3 only**, **mutual TLS**. Server requires client certificate. Each node trusts **only pinned peer certificates** (no public CAs).
- The TLS client certificate MUST match the pinned certificate of the envelope's `from` node, otherwise reject.
- Endpoint: `POST /v1/envelope` (single endpoint, typed messages). Health: `GET /v1/health` (peers only, returns no data).

### 6.2 Envelope
```json
{
  "v": 1,
  "from": "node-id", "to": "node-id",
  "type": "ask | trade.propose | kyc.request_package | ...",
  "trade_id": "LT-20261107-AB12CD",
  "body": { },
  "ts": "2026-11-07T15:22:01.123Z",
  "nonce": "uuid4-hex",
  "sig": "ed25519 over canonical JSON of all fields except sig"
}
```
- **Canonical JSON:** keys sorted, no whitespace, UTF-8 (RFC 8785 JCS).
- Reject if: unknown sender, wrong recipient, bad signature, |now − ts| > 120 s, nonce already seen (store nonces ≥ 10 min).
- Every response is itself a signed envelope from the responder.
- Every inbound and outbound envelope is written to the audit log **before** processing / after sending.

### 6.3 Peer onboarding
Peers are added by a bank admin in the admin console: paste/import the peer's **identity bundle** (node id, legal name, LEI, Ed25519 public key, X25519 public key, TLS certificate, endpoint URL). Requires dual approval (two admins). Exchange the bundles out-of-band (signed file). No passwords or shared secrets are ever exchanged.

### 6.4 Comparing values without sending them (fingerprints)
For equality checks (e.g., SSI on file vs. SSI held by the lender):
1. Both nodes derive a per-trade key: `HKDF-SHA256(X25519(own_priv, peer_pub), info="exchange-v1|" + trade_id)`.
2. Each computes `HMAC-SHA256(key, canonical_json(value))`.
3. The holder of the reference copy compares and returns a signed `{match: true|false}`.
The raw value is never transmitted. Note: this is an equality check between two parties that each legitimately hold the value; it is not a zero-knowledge proof.

---

## 7. Question catalog (v1, par assignment)

Each question: `id`, who may ask, params, what the answering node reads, what it returns. Answers are signed objects:
`{question, params, result, answered_by, ts, policy_hash, sig}`.

| ID | Answered by | Allowed askers | Params | Returns |
|---|---|---|---|---|
| `lender_holds_at_least` | Agent | Seller, Buyer | lender, facility_id, amount | `true/false` |
| `my_register_position_matches` | Agent | any lender | facility_id, claimed_position | `true/false` — compares **only against the asker's own** holding |
| `assignment_eligible` | Agent | Seller, Buyer | assignee, facility_id, amount | `{eligible, reasons[]}` (DQ list, minimum, multiple) |
| `consent_requirements` | Agent | Seller, Buyer | facility_id, assignee_relationship | `{borrower_consent_required, agent_consent_required, assignment_fee}` |
| `lender_kyc_cleared` | Agent | Seller, Buyer | lender | `true/false` |
| `my_ssi_matches` | Agent | any lender | trade_id, fingerprint | `{match}` — only the asker's own SSI |
| `consent_status` | Agent | Seller, Buyer | trade_id | `{agent, borrower}` statuses |
| `funds_available` | Buyer | Seller | purchase_price | `true/false` |
| `relationship_to_borrower` | Buyer | Seller, Agent | facility_id | `none / existing_lender / affiliate / approved_fund` |
| `position_free_to_sell` | Seller (local) | — | facility_id, amount | `true/false` (amount − pledged ≥ trade amount) |

**Rules (MUST):** A question not in the catalog, or asked by a node not in `allowed`, returns `403 question_not_permitted` and is audited. Answers never include raw operands (no balances, no account numbers, no documents). Banks can disable any question or tighten params in config; they cannot add free-form queries.

---

## 8. Action catalog (v1)

Every action requires the listed approvals before it executes. Approvals are signed by officer keys.

| Action | Executed by | Triggered by | Required approvals | Effect |
|---|---|---|---|---|
| `trade.propose` | Seller | Seller desk | Seller trader | Signed ticket sent to Buyer + Agent |
| `trade.affirm` | Buyer | automatic on receipt | none if it matches the buyer's own booked trade exactly; otherwise trade break task | Signed affirmation |
| `kyc.request_package` | Agent → Buyer | gap: buyer KYC not cleared | Buyer: Loan Ops officer approves release | Buyer sends **only the documents the agent's policy requires**, with a signed attestation |
| `kyc.clear` | Agent | package received & validated | Agent KYC officer | Lender added to KYC-cleared list |
| `ssi.update` | Lender → Agent | gap: SSI mismatch | Lender treasurer + Agent officer + Agent second officer (dual control / callback) | Agent's SSI on file updated (ABA checksum validated) |
| `consent.agent` | Agent | consent required | Agent officer | Signed agent consent |
| `consent.request` | Agent → Borrower | borrower consent required | Borrower treasurer | Signed CONSENTED / DECLINED. Auto-decline if assignee on borrower's blocked list |
| `doc.sign` | Seller, Buyer, Agent | ready for documents | One authorized signatory each | Each node verifies the document matches its own booked trade before signing; signature over doc hash |
| `funding.release` | Buyer | all readiness items green | Buyer treasurer | pacs.008 to the agent settlement account written to bank's payment hub outbox |
| `settle.execute` | Agent | Seller request + camt.054 credit booked | Agent officer | Register moved seller → buyer in one DB transaction; pacs.008 agent → seller; signed receipt |
| `settle.receipt` | Seller, Buyer, Borrower | agent receipt | none | Each verifies agent signature and updates its own books |

**Settlement preconditions (agent MUST check all, atomically):** agent consent, borrower consent (if required), all 3 document signatures verified, buyer KYC cleared, buyer funds booked in agent settlement account for the exact purchase price, seller still holds ≥ amount, trade not already settled (idempotency on `trade_id`).

**Uncertain outcomes:** if a network call's result is unknown, the action is marked `NEEDS_RECONCILIATION` and is never automatically retried in a way that could double-pay or double-move the register. Retries use the same `execution_id`.

---

## 9. Trade workflow (state machine)

```
DRAFT → PROPOSED → AFFIRMED → CHECKING → GAPS_OPEN ⇄ RESOLVING → CHECKS_PASSED
      → CONSENTS_PENDING → CONSENTS_DONE → DOCS_PENDING → READY_TO_SETTLE
      → FUNDING_SENT → FUNDS_RECEIVED → SETTLED → CLOSED
Side exits: TRADE_BREAK, HARD_STOP (eligibility/position/funding fail), DECLINED (borrower), CANCELLED, NEEDS_RECONCILIATION
```

- **Checks run in parallel.** Gaps become **tasks** routed to the responsible institution's approval screen.
- **Hard stops** (position not held, not eligible, insufficient funds, DQ) are never auto-fixed; they require a business decision.
- **Borrower consent timer:** configurable response window per credit agreement (e.g., N business days, deemed-consent rule if the agreement provides one). Show countdown on the dashboard.
- Re-run all checks automatically after any gap is resolved and again immediately before `settle.execute` (positions can change).

---

## 10. Approval screen (the "button")

**Goal:** an officer can approve any step in under 10 seconds because everything is already checked.

- **Inbox:** list of tasks for the logged-in officer, sorted by trade age; badge counts.
- **Task card shows:** trade summary, exactly what will happen if approved, which checks passed (with "signed by Agent" badges), any warnings, the document preview (for signing), and a single **Approve** / **Reject (reason required)** pair.
- **Approve =** officer authenticates (bank SSO/SAML or OIDC + step-up MFA), node creates the approval record and signs it with the officer's key in the HSM.
- **Dual control:** actions marked dual require two different officers.
- **Notifications:** email/Teams/Slack webhook inside the bank (content: "Task waiting: trade LT-…", no data values).
- **Trade dashboard:** live checklist per trade (green / red / waiting on whom), timeline, machine time vs. waiting time, T+ counter vs. T+7.
- **Audit view:** every message, answer, approval for a trade, with signature verification status.
- **Admin console:** peers, catalog on/off and limits, officers and roles, templates, update approval.

UI stack: React + TypeScript, served by the node, accessible only on the bank's internal network.

---

## 11. Adapters

Interface (Python protocol / abstract class):
```python
class LoanSystemAdapter:
    def get_facility(facility_id) -> Facility
    def get_lender_positions(facility_id) -> list[LenderPosition]   # agent
    def get_own_position(facility_id) -> OwnPosition                # seller/buyer
    def get_booked_trade(trade_ref | match_keys) -> BookedTrade
    def get_kyc_record(lender) -> KycRecord                         # agent
    def get_kyc_documents(types: list[str]) -> dict[str, bytes]     # buyer, only after approval
    def get_own_ssi() -> Ssi
    def get_ssi_on_file(lender) -> Ssi                              # agent
    def apply_register_transfer(facility_id, from, to, amount, effective_date, execution_id)  # agent, idempotent
```
- v1 ships: `SqlAdapter` (reads the bank's tables via configured SQL views) and `CsvAdapter` (for pilots).
- Adapters are **read-only** except `apply_register_transfer` on the agent node, which MUST be idempotent by `execution_id`.
- Payment hub adapter: write pacs.008 XML to a configured outbox directory or MQ queue; read camt.054 from inbox directory or queue. Validate against ISO 20022 XSDs.

---

## 12. Security requirements

- **Data never leaves a node** except: signed answers, signed approvals/receipts, documents the buyer's officer explicitly released to the agent (KYC), SSI the lender's treasurer explicitly sent to the agent, and the assignment agreement text (trade terms only).
- **Keys:** node signing keys and officer keys in the bank's HSM via PKCS#11 in production. Software keys only in dev/test, clearly flagged.
- **Encryption at rest:** Postgres with bank-managed disk encryption; sensitive columns (SSI, KYC docs) additionally encrypted with a KMS data key.
- **Least privilege:** node DB user cannot read other schemas; adapters use read-only DB accounts.
- **Input validation** on every envelope body (JSON schema per message type, size limit 1 MB except KYC packages ≤ 25 MB).
- **Rate limiting** per peer.
- **No telemetry with data.** Metrics are counts and latencies only.
- **Audit log** is append-only and hash-chained; `verify_audit_chain()` runs hourly and on demand; optional daily anchor of the latest hash to the bank's WORM storage.
- **Security tests that MUST pass in CI:** unauthorized question refused; question asked by wrong peer refused; replayed envelope refused; stale envelope refused; tampered answer/receipt fails verification; TLS cert not matching `from` refused; settlement without all approvals refused; settlement requested by non-seller refused; double settlement prevented; SSI with bad ABA refused; KYC package with missing doc refused.

---

## 13. Deployment & updates (on-prem, bank-controlled)

- Artifacts: signed Docker images + Helm chart + `docker-compose` for pilots. Air-gapped install supported (image tarballs).
- Requirements: Linux x86_64, 4 vCPU, 8 GB RAM, PostgreSQL 15+, bank HSM/KMS, one inbound port for peers (or relay).
- **Update process:**
  1. Exchange publishes a release: images signed (Sigstore/cosign), SBOM, release notes, reproducible build instructions.
  2. Bank change board reviews, tests in its staging node (runs the certification suite).
  3. Bank admin approves in the admin console (dual approval); node verifies the image signature and digest before starting.
  4. Bank can refuse, pin a version, or roll back at any time.
- **Protocol versioning:** envelopes carry `v`; nodes support current and previous minor versions so banks can upgrade at different times.

---

## 14. Certification suite (same result in every bank)

A command `exchange certify` runs against a node in staging and MUST pass before go-live:
- Adapter conformance: canonical model fields present and valid for sample records.
- Protocol conformance with a reference peer (all message types, signatures, errors).
- The full end-to-end par assignment scenario (seller/buyer/agent/borrower reference nodes) with planted gaps: new-lender KYC, SSI mismatch, borrower consent required.
- All security tests from §12.
- Performance: targets from §3 on the bank's hardware.
Output: signed certification report (JSON + PDF).

---

## 15. Repository structure

```
exchange/
  node/
    transport/   identity/   signer/   catalog/   adapters/   workflow/
    approvals/   documents/  payments/ audit/     api/        ops/
  ui/                    # React approval screen + dashboard + admin
  protocol/              # JSON schemas per message type, PROTOCOL.md
  catalog/               # default par-assignment questions & actions (YAML)
  templates/             # assignment agreement template placeholders (bank supplies its own text)
  certify/               # certification suite
  deploy/                # Dockerfile, helm/, docker-compose.pilot.yml
  sim/                   # 4-node local network + synthetic market generator for demos/tests
  prototype/             # exchange_v1_colab.py (reference only)
  docs/                  # SPEC.md (this file), DECISIONS.md, SECURITY.md, RUNBOOK.md
  tests/                 # unit, integration, security, performance
```

**Stack:** Python 3.12, FastAPI + Uvicorn, PostgreSQL (SQLAlchemy + Alembic), `cryptography`, `python-pkcs11`, `pydantic` for schemas, `lxml` for ISO 20022 XSD validation, pytest, React + TypeScript + Vite for UI. Config in YAML, validated at startup.

---

## 16. Build milestones (in order)

| # | Milestone | Done when |
|---|---|---|
| 1 | Protocol + transport + identity + audit | Two nodes exchange signed envelopes over mTLS; all transport security tests pass |
| 2 | Catalog + ask engine + canonical model + CSV/SQL adapters | All §7 questions answered and signed between nodes |
| 3 | Workflow engine + state machine + tasks | Trade runs from DRAFT to CHECKS_PASSED with gap tasks |
| 4 | Actions + approvals (software signer) | KYC, SSI, consents, document signing work end to end |
| 5 | Payments (pacs.008/camt.054) + settlement + receipts | Trade reaches SETTLED; register and books correct; idempotent |
| 6 | Approval screen + dashboard + admin console | An officer completes a trade only by clicking |
| 7 | `sim/` 4-node docker-compose demo + timing report | One command runs the full demo and prints §3 metrics |
| 8 | HSM signer, SSO, encryption at rest, signed updates | Production security controls in place |
| 9 | Certification suite | `exchange certify` passes on a clean install |
| 10 | Pilot package | Install guide, security package (architecture, data-flow diagram, pen-test scope), runbook |

---

## 17. Acceptance criteria for v1

1. A $500M par assignment with planted gaps (new-lender KYC, SSI mismatch, borrower consent required) goes from trade entry to SETTLED across 4 nodes on 4 separate machines/containers.
2. Machine time trade entry → READY_TO_SETTLE ≤ 30 s; funds received → SETTLED + receipts ≤ 10 s.
3. Final books: agent register total unchanged; seller −amount; buyer +amount; seller received purchase price (camt.054 matched).
4. "Who saw what" report generated from audit logs shows: seller and borrower never received the buyer's account number, KYC documents or funding amount; agent received only what officers explicitly released.
5. All audit chains verify; all signatures verify; all §12 security tests pass.
6. Re-running the same trade id is rejected (no double settlement).
7. The same build, with only config changes, passes certification for each of the four roles.

---

## 18. What to say (and not say) about v1

- **Say:** "Ready to settle the same day." "Each bank's data stays in its own systems; only signed answers move." "No blockchain, no central platform." "Every step approved by a named person, signed and auditable."
- **Don't say:** "settles in seconds" (people and borrower consent take time), "zero compliance" (Exchange still needs SOC 2 and bank vendor review), "replaces ClearPar".

---

## 19. Glossary

- **Par assignment:** sale of a performing loan position where the buyer becomes a lender of record.
- **Administrative agent:** the bank that keeps the official lender register and moves payments for the facility.
- **SSI:** standard settlement instructions (bank account details for payments).
- **KYC:** know-your-customer onboarding the agent must complete before adding a new lender.
- **DQ list:** disqualified lenders who may not buy into the facility.
- **pacs.008 / camt.054:** ISO 20022 messages for a credit transfer and a credit notification.
- **T+N:** business days from trade date to settlement.
- **HSM:** hardware security module; the bank's key vault.