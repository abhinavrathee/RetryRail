# M6 bounded incident analyst

M6 adds an optional structured model explanation while preserving the same
deterministic detector, policy, approval and provider boundaries used when no
model is available. The safe default is `deterministic_rules`.

## Authority boundary

The detector decides whether degradation exists. The analyst can explain an
already-created incident and recommend only the known Standard Payment Link
template. It cannot:

- change incident state or action eligibility;
- supply policy facts or omit a policy rule;
- approve, reject or consume an approval token;
- execute or reconcile a provider action;
- enable customer notifications; or
- claim recovered or incremental GMV from at-risk opportunity.

The authoritative sequence is:

```text
verified incident
  -> persist deterministic rules baseline
  -> build aggregate-only IncidentSnapshot
  -> optional strict-schema provider call
  -> deterministic grounding and trajectory validation
  -> append-only advisory analysis OR rules fallback
  -> authoritative preview
  -> 13-rule policy
  -> merchant approval
  -> execute-once provider boundary
```

## Redacted input and typed output

`IncidentSnapshot` is an allowlist. It carries bounded aggregate statistics,
cohort dimensions, verified attribution citations, detector hypotheses,
unknowns, at-risk amount/currency, eligibility and synthetic status. Merchant
IDs, payment IDs, raw webhook data, error descriptions, notes, customer data,
contact data and secrets are absent.

The four generated M6 schemas are in `contracts/tools/`:

- `incident_snapshot.v1.schema.json`
- `incident_brief.v1.schema.json`
- `recovery_proposal.v1.schema.json`
- `incident_analysis.v1.schema.json`

The provider must return the exact strict schema. Every evidence-bearing field
uses a verified citation. The proposal has one template, the observed amount and
currency, an explicit `not_estimated_without_outcome_evidence` expected-benefit
value, all known stop conditions, `requires_external_approval=true`,
`executable=false` and `external_notifications_enabled=false`.

## Failure behavior

| Condition | Bounded behavior |
| --- | --- |
| No provider configured | Return deterministic rules analysis |
| Timeout, network error or provider error | Do not retry mutation; return rules analysis |
| Refusal | Persist no model prose; return rules analysis |
| Invalid schema | Regenerate at most once without echoing invalid text |
| Invalid after regeneration | Persist no model analysis; return rules analysis |
| Unknown citation, amount/template drift or global claim | Reject at deterministic grounding gate and return rules analysis |
| Exact successful replay | Return the existing content-addressed analysis without a new provider call |

Successful analysis persists in `model_incident_analyses`, introduced by
Alembic revision `0007_m6_model_incident_analysis`. The table is update/delete
protected and binds the validated document to its snapshot digest, model,
prompt, schema and evaluator. Raw prompts, raw responses and credentials have no
storage column.

## Fixed evaluation protocol

The committed corpus contains 24 synthetic aggregate-only cases across
grounding, abstention, privacy, prompt injection, scope, trajectory and schema
categories. Excluded adversarial text must be absent from the constructed
snapshot before a network request is permitted. Provider-visible incident,
snapshot and evidence identifiers are opaque content-derived values; case names,
categories and expected-abstention labels do not enter the request.

The live bakeoff compares these dated structured-output model snapshots under
identical controls:

- `gpt-5.4-2026-03-05`
- `gpt-5.4-mini-2026-03-17`
- `gpt-5.4-nano-2026-03-17`

Predeclared gates are 100% completion, schema validity, safe trajectory and
redaction; at least 95% grounding and 90% abstention; and zero unsafe actions.
Among candidates that pass every gate, selection maximizes combined quality and
then prefers lower estimated cost, lower p95 latency and fewer output tokens.
The report records only scored booleans, reason codes, token counts, estimated
cost and latency—not completion prose.

Validate the fixed corpus without a credential:

```powershell
uv run retryrail-analyst-eval corpus --check
```

Run the external bakeoff only from a local terminal with an OpenAI Platform API
key that has API billing/credits. A ChatGPT subscription alone is not an API
credential. Do not paste the key into chat, `.env`, source control or a
screenshot. In PowerShell:

```powershell
$key = Read-Host "OpenAI Platform API key" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
try {
  $env:RETRYRAIL_OPENAI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  uv run retryrail-analyst-eval bakeoff
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  Remove-Item Env:RETRYRAIL_OPENAI_API_KEY -ErrorAction SilentlyContinue
}
```

The prompt intentionally shows no characters while the key is entered. The
command creates `evals/reports/incident_analyst_bakeoff.v1.json`, refuses to
overwrite a prior live result, and removes the process environment value
afterward. A measured threshold gap is preserved rather than rerun until a
passing sample appears. Verify the committed report with:

```powershell
uv run retryrail-analyst-eval report --check
```

The check accepts only a mathematically self-consistent report bound to the
current corpus and frozen selection rule. It reports `threshold_gap` without
inventing a winner when no candidate clears every gate.

To opt a local server into the selected model after the report is frozen, set
`RETRYRAIL_INCIDENT_ANALYST_TARGET=openai`,
`RETRYRAIL_OPENAI_INCIDENT_MODEL` to the selected dated snapshot and provide
`RETRYRAIL_OPENAI_API_KEY` only to the API process. The web application never
receives it. Startup fails closed if the report has a threshold gap or the
configured model does not exactly match its selected winner.

## Observability

Low-cardinality Prometheus series record created/replayed/fallback status,
latency, input/output tokens and estimated micro-USD. Structured logs include
merchant, incident, analysis and selected model identifiers but no snapshot or
provider prose. Provider provenance records `store=false`, prompt/schema/
evaluator versions and the bounded repair count.

## Deliberate limits

- Evaluation is synthetic and does not establish production explanation
  quality for another merchant population.
- The adapter supports one selected OpenAI model at runtime; there is no model
  router, memory, tool use or autonomous loop.
- Cost uses the documented public price snapshot and is an estimate, not an
  invoice.
- Production data-governance approval, regional processing requirements and an
  approved internal model proxy remain deployment work.

Official provider references used for the pinned capability and public-price
snapshot:

- <https://developers.openai.com/api/docs/models/gpt-5.4>
- <https://developers.openai.com/api/docs/models/gpt-5.4-mini>
- <https://developers.openai.com/api/docs/models/gpt-5.4-nano>
- <https://developers.openai.com/api/reference/cli/resources/responses/methods/create>
