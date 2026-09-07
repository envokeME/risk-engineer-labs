# Lab 01 implementation scope

Status: experimental standalone risk.engineer learning lab for editorial review. It does not modify the public site's Release 0.1 evidence-plane scope.

## Objective

Revision: added an all-cluster agent investigation harness, explicit abstention/contradiction dispositions, and a twelve-case synthetic evaluation scorecard. General multi-scenario discovery remains unimplemented; HR is optional in the risk schema but required by the current worked adapter.

Teach continuous cyber risk identification as a data pipeline: collect changing system evidence, normalize security telemetry, add business context, correlate deterministic conditions, reduce evidence, draft cited candidate risk statements with a bounded LLM, and preserve history.

## Scenario

Fictional former-worker access across Okta authentication, Zscaler web activity, HR termination status, and a business-service catalog. The desired outcome is NIST CSF `PR.AA-05`. This is one supported scenario family, not universal risk discovery.

## Implemented

- [x] Generate 49,200 deterministic vendor-shaped mock records across two collection batches.
- [x] Preserve raw JSON and quarantine malformed rows.
- [x] Register supported sources, land content-addressed copies, and record checksums and received batch counts in a validated receipt. Upstream completeness is not established.
- [x] Map security records to OCSF 1.8.0 Authentication, Account Change, and HTTP Activity classes.
- [x] Validate every emitted security event against the packaged OCSF schema.
- [x] Store normalized events and business context in Parquet.
- [x] Group by worker login/service and verify a unique observed identity against supplied HR expectations; retain ambiguity and absence explicitly.
- [x] Create neutral investigation clusters for every terminated worker without leaking hidden benchmark outcomes.
- [x] Reduce evidence before any model call.
- [x] Require the agent to inspect timeline and business context, then close every cluster with a candidate, abstention, contradiction, or ambiguity disposition.
- [x] Evaluate twelve author-labeled synthetic cases for candidate precision/recall, disposition accuracy, citations, scope, and tool budget.
- [x] Persist repeated results under stable scenario IDs and cache identical completed runs.
- [x] Execute a replayable Jupyter notebook with native charts and a candidate register view.
- [x] Supply offline tests, Docker configuration, CI, MIT licensing, and an allowlisted archive.
- [x] Exercise source mutation after deactivation and compare real model results with the deterministic baseline.
- [x] Preserve the model's original wording and document interpretation limitations for editorial review.
- [ ] Execute Docker on a Docker-enabled machine.
- [ ] Obtain Ahmed's editorial approval before public release.

## Completion criteria

Batch 1: 49,200 inputs, 47,998 OCSF events, two quarantined rows, 11 relevant terminated-user events, six investigated clusters, and three model candidates.

Batch 2: six investigated clusters and one model candidate. P0001 changes from candidate to contradicted, P0005 to insufficient evidence, and P0006 remains a candidate. Earlier history remains available.

No assessment or external publication is performed.

## Approval boundaries

Only fictional data was sent to the previously authorized OpenAI endpoint. No source-system changes, accounts, new keys, paid services, public repositories, canonical LifeOS updates, automatic risk acceptance, or external publishing are authorized.
