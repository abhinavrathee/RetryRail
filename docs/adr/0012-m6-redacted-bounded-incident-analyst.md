# ADR-0012: Keep model analysis redacted, advisory and reproducibly evaluated

- Status: Accepted
- Date: 2026-09-05
- Decision owners: RetryRail maintainers
- Milestone: M6

## Context

RetryRail needs useful AI reasoning for incident explanation without allowing a
model to detect degradation, see unnecessary payment/customer data, authorize a
merchant decision or reach Razorpay. Free-form prompts and unvalidated prose
would weaken the deterministic detector and recovery boundary already proven in
M3–M5. Selecting a model without a fixed comparison would also turn a brand
choice or a successful screenshot into unsupported evidence.

## Decision

Only the `IncidentSnapshot` allowlist crosses the model boundary. It contains
aggregate detector statistics, bounded cohort predicates, verified attribution
citations, merchant-local hypotheses, explicit unknowns, at-risk opportunity,
currency, eligibility and synthetic status. It deliberately excludes merchant
identity, payment identity, raw events, notes, descriptions, contact fields,
credentials, approval tokens and action authority.

The provider receives a strict JSON Schema and may return only a typed incident
brief plus one advisory `standard_payment_link` proposal. The proposal must
preserve the observed amount and currency, all eight stop-condition categories,
external merchant approval, `executable=false` and notifications disabled. The
model has no tools. Provider-side response storage is disabled.

The OpenAI adapter uses one bounded Responses API request, a 12-second runtime
timeout and at most one schema-regeneration attempt. It does not automatically
retry transport or provider failures. Refusal, timeout, unavailable service,
malformed output and provider errors become low-cardinality reason codes and
immediately return the deterministic M4.5 rules analysis. Invalid provider text
is neither logged nor persisted nor copied into a repair prompt.

Successful output crosses a second deterministic grounding gate. Every claim
must cite an event identifier already verified for the incident; opportunity,
currency, template and stopping controls must exactly match server-owned facts;
and unsupported merchant-global or ecosystem-wide claims are rejected. A
rules-only baseline is persisted before any provider call. Accepted model
analysis is content-addressed, append-only and bound to the snapshot, dated
model snapshot, prompt version, output schema and evaluator version. Durable
telemetry includes bounded latency, token counts, repair count and estimated
cost, but never raw provider output.

Model selection uses the fixed 24-case synthetic corpus
`incident_analyst_v1.cases.json`. Every dated candidate receives identical
snapshots and controls. The report scores completion, schema validity, evidence
grounding, abstention, safe trajectory, unsafe-action rate, redaction, latency,
tokens and estimated cost. Safety gates precede quality, cost and latency in the
selection rule. Per-case report rows retain only booleans, reason codes and
telemetry—not generated prose.
The official report path is create-only so a failing or noisy first complete
run cannot be silently replaced by a more favorable retry.

## Consequences

A provider outage cannot block the recovery path and a successful model answer
still cannot create a plan, approve it or call Razorpay. The extra validation
may reject a fluent but unsupported response; that is intentional. A model call
adds latency and cost only when the server is explicitly configured for it.

Model evaluation requires an operator-supplied OpenAI Platform API key and
available billing. The key remains process-only. A missing key is an external
evidence gap, not a reason to fabricate a benchmark or weaken the default
rules-only runtime.

## Rejected alternatives

- **Send sanitized raw webhook payloads.** Rejected because an allowlist is
  easier to audit and avoids prompt injection and accidental PII propagation.
- **Let the model choose arbitrary actions or call a provider tool.** Rejected
  because action selection, approval and execution are deterministic trust
  boundaries.
- **Repair invalid output by echoing it back.** Rejected because untrusted model
  text should not be amplified or retained.
- **Persist full prompts and completions for debugging.** Rejected because the
  release evidence needs provenance and scores, not an additional sensitive
  data store.
- **Choose one model without a bakeoff.** Rejected because model selection must
  be supported by the same fixed safety and quality cases.

## Revisit condition

Revisit the provider adapter only when a separately evaluated model or approved
internal proxy improves the fixed corpus without weakening redaction,
grounding, fallback, policy or external approval. A new prompt, schema,
evaluator or corpus requires a new version and report rather than rewriting M6
evidence.
