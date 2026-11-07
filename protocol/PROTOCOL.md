# Reference transport v1

The dedicated peer listener serves only `POST /v1/envelope` and `GET /v1/health`.
TLS is restricted to 1.3 and requires a client certificate. The trust store contains
only explicitly configured peer certificates, then the DER SHA-256 fingerprint is
compared with the envelope sender's pin. Local REST routes are never mounted there.

Ed25519 signatures cover RFC 8785 canonical JSON, excluding `sig`. A persistent
10-minute nonce cache rejects replay; timestamps must be within 120 seconds.
The client checks the response signature, recipient, version, timestamp, trade,
and request nonce. Every response body includes `request_nonce`; answers live in
`body.answer`, protocol errors in `body.error`. This correlation wrapper is a
reference-build extension to the spec. No response may be accepted on TLS trust alone.

Only `ask` is dispatched on the network in this release. Other message types fail
closed with `message_not_implemented`. Workflow actions run in the explicitly
synthetic local sandbox; they must not be represented as bank-to-bank actions.
Local REST is authenticated by demo bearer sessions, not peer certificates.

Unknown peers, certificate mismatch, replay, stale messages, bad signatures, catalog
refusals and invalid bodies are rejected. Envelope rejects are audited by hash;
verified inbound messages are recorded before dispatch. Responses are durably
recorded before writing to the socket (an intent, not proof of delivery).

Limits: 1 MiB messages, 16 KiB HTTP headers, 15-second read timeout, 600 verified
messages per peer per minute. KYC network delivery is disabled, so the 25 MiB
exception is not enabled. No raw KYC or SSI export routes exist in the local API.
