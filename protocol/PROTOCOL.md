# Exchange signed protocol v1

`POST /v1/envelope` on the institution peer port is the only action endpoint.
`GET /v1/health` requires a pinned peer certificate and returns no trade data.
TLS is restricted to 1.3; exact certificate fingerprints bind TLS identity to `from`.
Ed25519 signs RFC 8785 canonical JSON of every envelope field except `sig`.
Timestamps must be within 120 seconds; nonces are retained at least ten minutes.

Signed replies include `body.request_nonce` and either `body.answer` or `body.error`.
The client checks signature, sender, recipient, trade, version, timestamp and request
nonce even for negative HTTP responses. Question answers have an independently
verified signature and policy hash. This response-correlation wrapper is an explicit
protocol extension preventing another valid answer from substituting for a reply.

`protocol/messages/` contains the generated closed action schemas. The role matrix
in `node/runtime/messages.py` is normative: proposal seller→buyer/agent, affirmation
buyer→seller/agent, KYC request agent→buyer and release buyer→agent, SSI lender→agent,
consents agent↔borrower, documents agent↔seller/buyer, funding seller→buyer→agent,
settlement seller→agent, receipts agent→seller/buyer/borrower and signed acknowledgments.
Questions are fixed catalog operations; no free-form query endpoint exists.

Every business message includes `execution_id`. The receiver scopes its durable
execution ledger by sender and execution ID and checks payload hash, message type
and trade. Identical retries return the original result without applying effects;
conflicting reuse is refused. `execution.status` is a signed, origin-scoped query
for uncertain outcomes. A new transport nonce never creates a new business execution.

Peer bodies are limited to 1 MiB; approved KYC release packages to 25 MiB. The local
signed initialization command may also carry a bank-owned package up to 25 MiB.
HTTP headers are limited to 16 KiB; requests have a 15-second total read deadline;
verified peer requests are limited to 600 per minute. Officer TLS certificates are
not trusted on the peer listener, nor institution certificates on the officer port.

Verified input is recorded before processing. Outbound send intents and signed
responses are distinct audit events; intent is not proof of delivery. Sensitive
envelopes are encrypted in the audit store. JWT-bearing local commands are recorded
by hash with credentials redacted. No raw account or document is returned by a
catalog question; only the defined boolean/status result and approved parameters.
