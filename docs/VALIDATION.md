# Validation evidence

Validated in this cloud workspace on 2026-11-07. These results describe the
reference build, not production v1 or a fresh published environment.

- Python: **60 passed** (`.venv/bin/pytest -q`). One upstream Starlette warning about
  its httpx test-client backend; no failed, skipped or expected-failure tests.
- React/TypeScript: `npm --prefix ui run build` passed.
- Browser: system Chromium through Playwright; login, seller proposal, officer
  switching, KYC release, all remaining approval steps, synthetic credit, SETTLED,
  audit, administration and mobile viewport passed; no JavaScript page errors.
  The smoke runner starts and removes its own temporary sandbox.
- Synthetic workflow: $500M principal at 99.75; 13 software-signed approvals; final
  seller and buyer register positions $1.5B each, original total $3B preserved.
  Last measured reference run: readiness 123.03 ms; credit-to-receipt 15.52 ms.
  Approvals were automated in this timing run; they were separately clicked in
  the browser run. This is a local synthetic wall-time measurement, not WAN SLA.
- Peer network: four separate mTLS listeners with individual databases and signing,
  agreement and TLS keys; 20 signed round trips, p95 19.96 ms; nine concurrently
  dispatched signed catalog questions in 106.87 ms. All chains verified.
  All listeners ran on loopback in one process. Not a four-bank settlement test.
- Docker: multi-stage image built with TLS verification enabled and the environment
  CA supplied as a build secret. Runtime served UI, health, authentication and
  the authenticated dashboard.
- PostgreSQL 16: full synthetic lifecycle, conserved register total and valid audit
  chain. Two independent workflow/store instances raced the same settlement:
  exactly one settled, the second received `task_not_pending`. Test containers
  were removed by the runner.
- Certification: signed reference JSON verifies; default go-live certification exits
  with status 2. `--reference` succeeds only for the explicitly scoped reference
  checks and retains `go_live_eligible: false`.

Not validated: bank HSM/KMS/SSO, official payment scheme XSDs, four-container full
settlement, privacy reports for distributed actions, Helm/Kubernetes runtime,
20 concurrent trades, sustained throughput, bank WAN latency, signed production
updates, go-live certification or publication. See STATUS.md for requirements
that still need implementation rather than just external configuration.
