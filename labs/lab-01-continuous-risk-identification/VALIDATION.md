# Validation record · 2026-09-06

Status: executable learning prototype; one scenario family, synthetic evidence, editorial review pending.

## Expected and observed

Engine revision: investigation-harness-3. Pinned model: gpt-4.1-mini-2025-04-14.

- 49,200 source/context records across two fixture collections: 8,000 Okta, 40,000 Zscaler, 1,000 HR and 200 services.
- 47,998 security events validated against the embedded OCSF 1.8.0 schemas; two intentionally malformed vendor-shaped records quarantined.
- All six worker/service clusters investigated in each collection; every cluster receives an explicit disposition.
- Real API batch 1: three candidates, 26 tool calls, 61,717 API-reported total tokens.
- Real API batch 2: one candidate, 21 tool calls, 24,571 API-reported total tokens.
- Twelve of twelve authored dispositions matched. Candidate precision and recall are 1.0 on these twelve cases; citation sets, ordered tool-use requirements and tool budgets passed.
- The deterministic reference also gets twelve of twelve. There is no demonstrated detection improvement from the model on this benchmark.
- The notebook executed in a fresh Python kernel in replay mode, including the source-mutation exercise. Saved trace versions and local evidence must match before replay.
- Sixteen offline tests cover OCSF projection, identity ambiguity and absence, temporal order, citations, assessment scope, ingestion integrity, cache behavior, scorecard logic, API pagination and cross-origin credential protection. The API connector tests use an injected fake transport; no live tenant is claimed. The model test substitute cannot pass the live trace check.

The 86,288 total tokens above describe only the two retained successful runs. Earlier development attempts, including a failed investigation, incurred additional usage. These are API-reported token totals, not dollar costs or a throughput benchmark.

## Corrections demonstrated

- Expected HR identity no longer fills an empty observed-identity list.
- Access after a successful disable still supports investigation. A partial pair after disable remains insufficient evidence.
- Model tools receive no reference disposition or supported-cluster count.
- Each tool call is schema-validated and every closed cluster must have an inspected timeline and business context.
- Explicit progress feedback and required closure fixed a live failure in which the model submitted the final candidate but did not close its cluster.
- A failed model run releases its SQLite connection and is not cached as completed.
- The local exercise appends two vendor JSON records after deactivation, changes the ingestion fingerprint and changes P0001's reference disposition from contradicted to candidate-submitted. It uses no model call.

## Interpretation review

See SEMANTIC-REVIEW.md. Structural correctness and citation membership do not prove a business consequence or establish who used an account. Raw model statements and rationales are preserved, including their limitations.

The benchmark is authored by the lab creator and closely follows the declared method. It is a regression check, not an independent held-out benchmark. Model variance, adversarial prompt injection resistance and open-ended discovery have not been established.

## Visual and release checks

The executed notebook produced the investigation board, source-volume figure, pipeline reduction chart, evidence relationship and history plot. Exported PNGs were visually inspected locally. Browser-level Jupyter screenshot review was blocked by the tool approval service's account usage limit; no browser QA success is claimed.

Public packaging uses an explicit file allowlist and a credential-pattern scan. Generated source data, private environment files and runtime history are excluded. The archive includes code that regenerates fictional inputs, saved real model traces and executed notebook outputs.

The original single-lab archive was extracted into an empty temporary directory and tested with OPENAI_API_KEY removed from the subprocess environment: fourteen tests, saved-output evaluation and fresh-kernel notebook execution all passed. After the multi-lab repository restructure and connector addition, the current sixteen-test suite, saved-output evaluation and fresh-kernel notebook execution passed from the new lab directory. This uses the existing pinned Python environment.

Docker verification passed on 2026-09-06 after enabling the Windows WSL 2 prerequisites and rebooting. Docker Desktop 4.89.0 / Engine 29.7.2 built the image from python:3.12-slim with a fresh dependency installation. The then-current fourteen tests and full fresh-kernel notebook execution passed in separate disposable containers using --network none, no API credentials and no host mounts. Image ID: sha256:59817beaa2a8fce9f6158f0e3f9abe3dadc134d1b8aa99995c9ee6f3a717084a. GitHub CI independently rebuilds the current code and executes the current suite. This local record does not claim a live model call, live Okta collection or Compose browser test.

## Deliberate boundaries

- File-based collection; no live Okta/Zscaler connector, scheduler or source completeness guarantee.
- Identity resolution is a narrow observed-UID check against supplied HR context. Web evidence joins by login/service; it does not prove a shared session.
- Target-profile context is supplied, not inferred maturity or risk scoring.
- No likelihood, impact scoring, treatment, acceptance or external risk-register writes.
- A per-window contradiction is not proof of globally revoked access; absent events are not proof of resolved risk.
- No public repository or LinkedIn article has been published by this task.
