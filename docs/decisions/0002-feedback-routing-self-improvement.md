# 0002 — Deterministic routes and evidence-gated local improvement

- Status: Accepted
- Date: 2026-08-14

## Context

The v1 workflow verifies work but leaves every AI phase on the host's selected
model and does not turn test, review, correction, cost, or latency outcomes into
bounded improvement evidence.

## Decision

Keep routing in `workflowctl` deterministic. Retrieval and reduction start on
GPT-5.6 Luna, implementation on Terra, and complex design and independent
review on Sol. Failures advance at most once per higher model tier. Mechanical
verification remains model-free.

Persist only structured route and outcome metadata. Create an improvement
candidate after 20 newly completed tasks or three matching failures. Candidate
changes are restricted to engineering-workflow assets and are built and tested
in a retained candidate clone. The full gate and Sol review run against that
clone before transactional, rollback-protected copy-back under a repository
lock. Validated candidates can activate only a versioned local runtime release.
Installation and every rollback use a durable
activation journal around the atomic current pointer. Release directories are
made read-only after their health check; the previous release and database
backup remain available for rollback.

## Consequences

Model selection is replayable and does not need a classifier model. Write jobs
cost an extra disposable clone but cannot copy unclaimed edits into the source
checkout. Local runtime upgrades become reversible. Automatic merge, push, and
external deployment remain out of scope.
