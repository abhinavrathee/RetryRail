# ADR 0004: Nonce-derived blind protocol before detector-v2 development

- Status: Accepted; R2 candidate frozen before blind nonce
- Date: 2026-09-01

## Context

Detector v1 honestly failed its consumed held-out partition. Reusing that split
to tune a replacement and then calling the result held-out would leak labels.
Proceeding directly to recovery execution would also leave a known-unqualified
detector adjacent to a consequential action path.

## Decision

RetryRail inserts an M3 remediation sequence before M4. A versioned development
batch and the structure of a nonce-derived blind batch are committed before the
candidate exists. The official nonce is unavailable until code, thresholds,
matching and evaluation are frozen.

R2 implements that freeze as `detector_v2.freeze.json`. It binds the
hierarchical/actionability-aware detector, configuration, matcher, evaluator,
shared contracts and development prediction/report identities. Development
success cannot set runtime action eligibility or qualify the release.

Blind runtime events and blind labels have separate public functions and
artifacts. Predictions must be persisted before label loading. Any later code
or configuration change requires a new nonce; all failed results remain
committed. Runtime integration occurs only from a generated qualified release
decision.

## Consequences

This protocol makes accidental target chasing detectable and produces a clear
audit sequence without needing cloud infrastructure. It also delays M4 until a
detector is fit to sit beside recovery policy.

The issuer hierarchy separates early visibility from later confirmation: sparse
issuer evidence may set the first-signal timestamp, but a bounded subsequent
traffic requirement must pass before a candidate becomes a confirmed incident.
Method-level confirmation requires continued fresh evidence so the precommitted
ten-minute burst remains suppressed.

The benchmark remains synthetic and locally authored. A nonce makes exact
outcomes unpredictable after candidate freeze, but it does not make the public
scenario distribution externally double-blind. Production claims still require
merchant traffic and a separate evaluation program.
