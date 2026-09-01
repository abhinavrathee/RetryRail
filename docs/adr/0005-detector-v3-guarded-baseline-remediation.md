# ADR 0005: Preserve the benchmark and remediate detector baselines in v3

- Status: Accepted; official run consumed and preserved blocked/invalid
- Date: 2026-09-01

## Context

Detector v2's official synthetic blind run found every true incident with no
false positive and correct top-1 attribution, but the release was blocked. Its
median first-signal delay was 900 seconds against a 600-second target, and two
matched incidents used rolling baselines that ended 20 minutes after the
seeded degradation began.

The failed run is now revealed development evidence. Editing v2 in place,
reusing its nonce, or changing the benchmark after seeing the failures would
erase the audit boundary or weaken comparability.

## Decision

M3R.4 creates a separately versioned detector-v3 candidate. Detector v2 and
all of its evidence remain immutable. V3 may use exactly two labelled
development partitions: the original v2 development batch and the revealed,
blocked v2 official run.

The nonce-derived v2 benchmark generator and scenario distribution remain
unchanged. V3 must introduce an explicit baseline guard in candidate
configuration, require the guard to cover the maximum current-window length,
keep baseline and current windows non-overlapping, and freeze the baseline
after the first passing signal. Exact thresholds remain tunable only on the
two approved development partitions.

Both development partitions must independently meet the unchanged release
targets before the candidate and blind runner can be frozen. Only after that
freeze may one fresh public, non-secret nonce be created. Known test nonces and
the v2 official nonce are forbidden. Prediction bytes must be persisted and
reproduced before truth access, and every result is append-only.

## Consequences

The baseline fix is structural rather than scenario-specific, while preserving
an honest comparison with the failed candidate. A fresh nonce still makes the
exact synthetic outcomes unpredictable after freeze, but this remains a
locally authored benchmark rather than an external double-blind evaluation.

M4 remains blocked. Development success cannot qualify the detector, and even
a qualifying blind decision still enters M4 through deterministic policy and
merchant approval rather than enabling direct mutation.

## Recorded outcome

The separately frozen v3 candidate passed both allowed development partitions.
Its one official synthetic blind run then failed the unchanged precision and
recall targets at 833,333 ppm each. The frozen canonical writer also omitted
the nullable-but-required `resolved_at` field for one open incident, so its
persisted report fails the frozen reload contract. The evidence and blocked
decision remain byte-immutable. The run cannot be retried, repaired in place or
used as blind evidence for another candidate; any future attempt needs a new
versioned precommit boundary and fresh nonce.
