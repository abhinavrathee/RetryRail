# RetryRail product requirements document

| Field | Value |
| --- | --- |
| Product | RetryRail |
| Submission title | RetryRail — AI-Powered Payment Reliability & Revenue Recovery |
| Buildathon track | Track 3 — AI Revenue Recovery |
| Document status | Implementation baseline |
| Evidence snapshot | 2026-09-01 |
| Primary outcome | Incremental recovered GMV from a bounded recovery workflow |
| Default operating mode | Review-first |

## 1. Executive decision

RetryRail will be a merchant-facing revenue reliability control plane, not a
generic payment chatbot and not a replacement payment router.

It will consume Razorpay-shaped payment events, detect statistically credible
degradation within a merchant cohort, rank the likely cause using payment error
evidence, estimate GMV at risk, propose an allowed intervention, obtain merchant
approval, create a recovery Payment Link through Razorpay Test Mode, and measure
the resulting incremental recovery against a held-out control group.

The project must demonstrate a closed loop and not stop at an alert or AI
summary.

## 2. Razorpay requirement traceability

The official Buildathon page defines Track 3 as detecting revenue at risk,
determining the right intervention and executing a bounded recovery workflow.
Its stated bar is measured money recovered across a batch, compliant
escalation, stopping rules and an audit trail.

| Razorpay signal | RetryRail response | Required proof |
| --- | --- | --- |
| Build something real | Working end-to-end application using Razorpay Test Mode | Live demo plus reproducible local run |
| Detect revenue at risk | Statistical cohort-degradation detector | Held-out detector metrics and incident evidence |
| Determine the intervention | Evidence-backed agent recommendation constrained by policy | Structured plan, confidence and alternatives |
| Execute bounded recovery | Review-first Standard Payment Link creation | Test-mode API receipt and visible approval |
| Measure money recovered across a batch | Treatment/control outcome measurement | Incremental recovered GMV report |
| Compliant escalation | Consent, amount, scope and approval checks | Policy decisions and blocked-action tests |
| Stopping rules | Cooldowns, attempt caps, expiry, opt-out and kill switch | Policy configuration and adversarial tests |
| Audit trail | Append-only records for decisions and actions | Searchable incident timeline and exported receipt |
| Public repository | Complete, understandable public GitHub repository | README, license, setup, tests and architecture |
| Five-minute pitch | Story-led recorded demo | Final video URL and script |
| Architecture | Clear system and trust-boundary diagram | Versioned architecture documentation |
| Build challenges | Honest account of obstacles and resolutions | Submission response backed by commits/tests |

Official reference: <https://razorpay.com/buildathon/>

## 3. Product thesis and differentiation

Razorpay publicly describes individual cart, subscription and complaint-driven
recovery experiences. RetryRail occupies a different layer:

- It identifies silent, cohort-level degradation before a merchant notices a
  pattern.
- It separates statistical detection from generative explanation.
- It estimates business exposure before suggesting an action.
- It measures causal recovery uplift rather than counting all later successes
  as its own impact.
- It can later consume internal route-risk signals or operate inside an agent
  platform without coupling the core workflow to one model or runtime.

The central claim is:

> RetryRail closes the merchant-specific loop from degradation signal to
> evidence, approved recovery and measured incremental revenue.

## 4. Problem statement

### 4.1 Current merchant problem

Merchants can observe failed transactions individually but may not detect a
meaningful pattern quickly enough. A temporary issuer, method, error-stage or
gateway degradation can silently reduce conversion and GMV. Even after the
pattern is found, recovery often requires manual analysis, a decision about who
is eligible to contact, creation of a safe alternative payment path, and later
measurement of whether the action actually helped.

### 4.2 Why existing simple solutions are insufficient

- A threshold alert does not establish the likely cause or business impact.
- An LLM summary without verified metrics can hallucinate causality.
- Retrying every failure can worsen customer experience or violate policy.
- Counting recovered payments without a control group overstates impact.
- A successful happy-path action does not prove duplicate, timeout or
  out-of-order safety.

## 5. Users and jobs to be done

### 5.1 Primary user: merchant payment operations lead

When payment performance degrades, this user needs to know what changed, how
much revenue is exposed, what action is safe, and whether the intervention
worked.

### 5.2 Secondary user: merchant founder or finance owner

This user needs a concise business explanation, approval control and credible
recovered-GMV measurement.

### 5.3 Secondary user: Razorpay operations or platform engineer

This user needs typed integration boundaries, replayable evidence, safe failure
behavior and a complete technical audit.

## 6. Goals

### 6.1 P0 goals

1. Detect seeded payment degradation with honest held-out metrics.
2. Identify the affected cohort and dominant Razorpay error evidence.
3. Estimate attempts, payment value and GMV at risk.
4. Generate a grounded, structured incident explanation.
5. Propose only merchant-authorized recovery actions.
6. Require approval outside the LLM before mutation.
7. Create a Standard Payment Link in Razorpay Test Mode idempotently.
8. Measure treatment-versus-control recovery across a versioned batch.
9. Handle duplicate events and one upstream-timeout scenario gracefully.
10. Produce a complete, understandable audit trail.

### 6.2 P1 goals

- Support multiple merchants with strict tenant scoping.
- Provide policy presets for low-, medium- and high-value payments.
- Export incident evidence and action receipts as JSON.
- Expose read-only incident tools over MCP.
- Add configurable detector thresholds and cohort dimensions.

### 6.3 P2 goals

- Add a Go webhook edge service after the P0 product is complete.
- Add a Kafka-compatible event-bus adapter.
- Add shadow traffic comparison for alternative agent prompts.
- Add richer recovery channels through consent-aware adapters.

## 7. Non-goals

RetryRail will not:

- Process live money or real customer card data.
- Claim to replace Razorpay routing, Vulcan or Agent Studio.
- Automatically retry a transaction that is unsafe to retry.
- Invent discounts, prices, payment amounts or consent.
- Contact customers through WhatsApp, email, SMS or voice without a verified
  consent signal and an explicitly enabled provider.
- Train a payment foundation model.
- Use an LLM as the degradation detector or policy authority.
- Implement fraud detection, offensive security or chargeback automation.
- Operate Kafka, Flink, Spark or Kubernetes solely for presentation value.
- Claim production readiness from synthetic results.

## 8. Domain language

| Term | Definition |
| --- | --- |
| Payment event | A versioned immutable event received from a webhook or deterministic fixture replay |
| Cohort | A group defined by dimensions such as method, issuer/bank, error source, error step or error reason |
| Baseline | Expected cohort performance derived only from data before an incident or from an explicit reference window |
| Degradation | A statistically credible drop from the baseline that clears sample-size and business-impact gates |
| Incident | The durable record representing one detected degradation episode |
| Recovery plan | A versioned proposal containing eligibility, action, constraints, expected value and stopping rules |
| Action receipt | Durable proof of preview, approval, execution result and verification |
| Treatment | Eligible failed payments assigned to the recovery workflow |
| Control | Eligible failed payments deliberately held out from the workflow for evaluation |
| Recovered GMV | Value of payments that complete within the attribution window after failure |
| Incremental recovered GMV | Treatment recovered GMV minus the counterfactual recovery estimated from control |

## 9. End-to-end lifecycle

```text
RECEIVED
  -> SIGNATURE_VERIFIED
  -> DEDUPLICATED
  -> PERSISTED
  -> AGGREGATED
  -> DEGRADATION_DETECTED
  -> INCIDENT_OPENED
  -> DIAGNOSIS_READY
  -> PLAN_PROPOSED
  -> POLICY_VALIDATED
  -> AWAITING_APPROVAL
  -> APPROVED | REJECTED | EXPIRED
  -> EXECUTING
  -> EXECUTED | FAILED | RECONCILIATION_REQUIRED
  -> OUTCOME_OBSERVED
  -> INCIDENT_RESOLVED
  -> IMPACT_REPORTED
```

Every transition must record the actor, time, prior state, new state, reason and
correlation identifiers. Invalid transitions must be rejected and audited.

## 10. Functional requirements

Priority meanings:

- **P0:** required for a credible submission.
- **P1:** complete after all P0 release gates pass.
- **P2:** differentiator only if schedule remains healthy.

### 10.1 Event ingestion and reliability

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-ING-001 | P0 | Accept Razorpay-shaped webhook POST requests using the raw request body | A valid signed fixture receives a 2xx response and creates one immutable event |
| FR-ING-002 | P0 | Validate `X-Razorpay-Signature` using HMAC-SHA256 before parsing the payload | Modified body, wrong secret and missing signature tests are rejected |
| FR-ING-003 | P0 | Deduplicate using merchant scope plus `x-razorpay-event-id` | Replaying the same event at least three times creates one logical event and one downstream processing request |
| FR-ING-004 | P0 | Persist before asynchronous processing | A worker failure after acknowledgement does not lose the event |
| FR-ING-005 | P0 | Tolerate out-of-order events | Captured/authorized fixture inversion does not corrupt the projected payment state |
| FR-ING-006 | P0 | Retain the original sanitized payload and a normalized version | Incident evidence can link to both representations without exposing secrets or prohibited PII |
| FR-ING-007 | P0 | Provide deterministic replay | The same fixture seed and configuration produce the same events and incident identifiers |
| FR-ING-008 | P1 | Apply per-merchant ingress rate limits | A burst beyond the configured limit is controlled and visibly reported |

Official validation behavior: <https://razorpay.com/docs/webhooks/validate-test/>

### 10.2 Synthetic batch and ground truth

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-DAT-001 | P0 | Generate a deterministic default batch of at least 2,000 payment attempts | `make seed` recreates the same batch from a committed seed and manifest |
| FR-DAT-002 | P0 | Include normal traffic, at least three true degradation episodes and at least one deceptive non-incident | The manifest defines exact start/end, affected cohort, severity and expected root cause |
| FR-DAT-003 | P0 | Include duplicate, delayed and out-of-order webhook deliveries | Reliability cases are distinct from business-event ground truth |
| FR-DAT-004 | P0 | Split detector development and held-out test data before threshold tuning | Test labels are not used during threshold selection |
| FR-DAT-005 | P0 | Clearly label all generated payments and outcomes as synthetic | UI, README, video and exported reports display the label |
| FR-DAT-006 | P1 | Support configurable traffic volumes and degradation severity | CLI configuration creates low-, medium- and high-signal scenarios |

### 10.3 Degradation detection

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-DET-001 | P0 | Maintain rolling success and failure statistics for configured cohorts | Aggregates reconcile exactly with the raw event store for a known fixture |
| FR-DET-002 | P0 | Enforce a minimum sample gate before opening an incident | Low-volume noise does not trigger an action-eligible incident |
| FR-DET-003 | P0 | Compare current performance with a leakage-safe baseline | No post-incident observations are used to construct that incident's baseline |
| FR-DET-004 | P0 | Use an explainable change detector such as EWMA/CUSUM plus a proportion-confidence test | The alert record stores threshold, observed change, sample count and confidence |
| FR-DET-005 | P0 | Incorporate business impact into severity | A statistically significant but immaterial cohort can be observed without triggering recovery |
| FR-DET-006 | P0 | Merge repeated alerts for the same active degradation | One episode produces one incident with updates, not alert spam |
| FR-DET-007 | P0 | Resolve an incident only after a configurable healthy window | One good event cannot close an incident |
| FR-DET-008 | P1 | Support threshold profiles per merchant | Profile changes are versioned and auditable |

### 10.4 Root-cause attribution

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-RCA-001 | P0 | Rank cohort dimensions by contribution to excess failures | The top contributors reconcile with raw counts and expected-failure calculations |
| FR-RCA-002 | P0 | Use available Razorpay error fields such as source, step and reason | Incident evidence displays field value, count, share and baseline comparison |
| FR-RCA-003 | P0 | Separate observation from hypothesis | UI and API label verified facts, inferred hypotheses and unknowns distinctly |
| FR-RCA-004 | P0 | Avoid unsupported ecosystem-wide claims | Merchant-local data may say “consistent with issuer degradation,” not “Bank X is down,” unless externally verified |
| FR-RCA-005 | P0 | Provide top-1 and top-3 attribution evaluation | Held-out truth produces a versioned score report |

Payment failure event reference: <https://razorpay.com/docs/webhooks/payments/>

### 10.5 AI incident analyst

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-AGT-001 | P0 | Accept only a redacted structured incident snapshot | Tests prove secrets, raw contact data and unrelated payload fields are absent from prompts |
| FR-AGT-002 | P0 | Produce a typed incident brief | Output validates against schema or the system uses a deterministic fallback |
| FR-AGT-003 | P0 | Cite evidence identifiers for every material diagnosis claim | An unsupported claim fails the grounding evaluator |
| FR-AGT-004 | P0 | Select only from pre-authorized intervention templates | Unknown action names are rejected before policy evaluation |
| FR-AGT-005 | P0 | State uncertainty and abstain when evidence is insufficient | Low-confidence cases yield escalation or observation, not fabricated certainty |
| FR-AGT-006 | P0 | Never execute an action directly | The model has no credential-bearing Razorpay client and no approval-token authority |
| FR-AGT-007 | P0 | Degrade safely without the model | With model access disabled, detection, policy, approval and a rules-based plan still work |
| FR-AGT-008 | P1 | Expose read-only analysis through MCP | MCP tools have typed schemas, typed errors and tenant checks |

Required structured output fields:

```text
incident_id
executive_summary
verified_evidence[]
hypotheses[]
unknowns[]
recommended_template
expected_benefit
customer_risk
confidence
stop_conditions[]
```

### 10.6 Policy, consent and approval

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-POL-001 | P0 | Support `ANALYZE_ONLY` and `REVIEW_FIRST` modes | Mode is visible and enforced server-side |
| FR-POL-002 | P0 | Validate merchant, amount, currency, consent, opt-out, attempt cap, cooldown and plan expiry | Each rule has an allow and deny test |
| FR-POL-003 | P0 | Require a server-issued, short-lived approval token outside the model | Missing, expired, reused or mismatched tokens are rejected |
| FR-POL-004 | P0 | Revalidate policy immediately before execution | A policy change between preview and execution prevents the action |
| FR-POL-005 | P0 | Provide a merchant kill switch | Enabling the switch blocks every new mutation while leaving read-only diagnosis available |
| FR-POL-006 | P0 | Prevent AI-created discounts or amount changes | Proposed amount must equal the verified source amount unless an explicit merchant rule says otherwise |
| FR-POL-007 | P0 | Record machine-readable allow/deny reasons | UI and audit trail display the exact rule outcomes |
| FR-POL-008 | P1 | Add `AUTO_LOW_RISK` only after shadow evidence | No automatic external action is enabled in the submission baseline |

The policy design follows Razorpay's published Agent Studio principles around
merchant control, verified first-party data, platform validation, consent,
approval and auditability: <https://razorpay.com/blog/?p=26508>

### 10.7 Recovery execution

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-ACT-001 | P0 | Preview the complete request and effects before approval | Merchant sees amount, currency, expiry, eligible cohort, notification behavior and reason |
| FR-ACT-002 | P0 | Create a Razorpay Standard Payment Link in Test Mode | One approved demo plan returns and stores a real test-mode Payment Link receipt |
| FR-ACT-003 | P0 | Derive a stable unique `reference_id` from merchant, failed payment and plan | Retrying the same plan cannot create a second logical recovery action |
| FR-ACT-004 | P0 | Reconcile ambiguous timeouts before retrying | Simulated timeout-after-success produces one link and one verified receipt |
| FR-ACT-005 | P0 | Default external notifications to off | The demo displays the link without messaging a real customer |
| FR-ACT-006 | P0 | Stop on approval expiry, policy denial, attempt cap, opt-out, successful payment or kill switch | Every stop reason is tested and audited |
| FR-ACT-007 | P0 | Return typed success and error receipts | Errors distinguish invalid input, unauthorized, rate limited, upstream failure and reconciliation required |

Standard Payment Link API: <https://razorpay.com/docs/api/payments/payment-links/create-standard/>

### 10.8 Experiment and impact measurement

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-EXP-001 | P0 | Assign eligible failures deterministically to treatment or holdout within affected cohort and amount band | Re-running with the same experiment seed preserves assignment and the allocation report shows balance by stratum |
| FR-EXP-002 | P0 | Keep eligibility identical before assignment | Treatment and control use the same cohort, time window and policy eligibility |
| FR-EXP-003 | P0 | Define an attribution window before outcomes are generated | The window is versioned in the experiment record |
| FR-EXP-004 | P0 | Report raw recovery and incremental recovery separately | Dashboard never labels all treatment successes as incremental impact |
| FR-EXP-005 | P0 | Report sample sizes and uncertainty | Results include treatment/control counts, rates, absolute uplift and confidence interval |
| FR-EXP-006 | P0 | Measure false-intervention cost | Contact/action costs and unnecessary interventions are included in net value |
| FR-EXP-007 | P0 | Label simulated recovery outcomes | Simulated batch results cannot be mistaken for live merchant performance |
| FR-EXP-008 | P1 | Support replayed counterfactual policies | Alternative policy results cannot overwrite the primary experiment record |

Primary business formulas:

```text
treatment_recovery_rate = treatment_successes / treatment_eligible
control_recovery_rate = control_successes / control_eligible
absolute_uplift = treatment_recovery_rate - control_recovery_rate
incremental_recovered_payments = absolute_uplift * treatment_eligible

treatment_value_per_eligible = treatment_recovered_gmv / treatment_eligible
control_value_per_eligible = control_recovered_gmv / control_eligible
incremental_recovered_gmv = (treatment_value_per_eligible
                             - control_value_per_eligible)
                            * treatment_eligible
net_recovered_value = incremental_recovered_gmv
                      - action_cost
                      - false_intervention_cost
```

The primary analysis uses the value-per-eligible estimator because payment
amounts vary. Report recovery-rate uplift beside it, verify treatment/control
balance by stratum and include a bootstrap confidence interval. If the interval
crosses zero, describe the result as inconclusive rather than recovered revenue.

### 10.9 Audit and observability

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-AUD-001 | P0 | Append an audit entry for every state transition and policy decision | A complete demo incident has no unexplained transition |
| FR-AUD-002 | P0 | Record code, detector, prompt, model, policy and schema versions | An outcome can be reproduced from its stored versions and fixture seed |
| FR-AUD-003 | P0 | Correlate event, payment, incident, plan, experiment and action identifiers | One search reconstructs the complete timeline |
| FR-AUD-004 | P0 | Redact secrets and unnecessary PII from logs | Automated tests scan representative logs and model inputs |
| FR-AUD-005 | P0 | Emit metrics for ingestion, detection, policy, action, experiment and LLM behavior | Local Grafana or equivalent dashboard renders the core measures |
| FR-AUD-006 | P0 | Attribute LLM latency and estimated cost to an incident | Model usage is visible even when the call fails |
| FR-AUD-007 | P1 | Export an incident evidence bundle | Export contains sanitized JSON and no credentials |

### 10.10 Merchant experience

| ID | Priority | Requirement | Acceptance criterion |
| --- | --- | --- | --- |
| FR-UI-001 | P0 | Provide a revenue reliability overview | Shows normal baseline, current success rate, at-risk GMV and active incidents |
| FR-UI-002 | P0 | Provide an incident evidence view | Shows timeline, affected cohort, observed versus expected failures and uncertainty |
| FR-UI-003 | P0 | Provide a plan preview and approval surface | Includes all action effects, policy results and clear approve/reject controls |
| FR-UI-004 | P0 | Provide an experiment result view | Shows treatment/control results and incremental, not merely gross, recovery |
| FR-UI-005 | P0 | Provide an audit timeline | Shows who or what acted, why, and what happened |
| FR-UI-006 | P0 | Implement empty, loading, success, blocked, failed and recovery states | Playwright covers each critical state |
| FR-UI-007 | P0 | Use accessible Razorpay Blade components where practical | Keyboard navigation, labels and contrast checks pass |
| FR-UI-008 | P1 | Provide a demo-control panel isolated from merchant production views | Injection controls are visibly marked as simulation-only |

## 11. Data model requirements

| Entity | Essential fields |
| --- | --- |
| `merchant` | id, display_name, mode, policy_profile_id, kill_switch |
| `payment_event` | id, merchant_id, razorpay_event_id, event_type, raw_sanitized_json, normalized_json, occurred_at, received_at, signature_status, schema_version |
| `payment_projection` | merchant_id, payment_id, state, amount_subunits, currency, method, issuer, error_source, error_step, error_reason, updated_at |
| `outbox_message` | id, aggregate_type, aggregate_id, message_type, payload, attempts, available_at, processed_at |
| `aggregate_window` | merchant_id, cohort_key, window_start, attempts, successes, failures, gmv_subunits |
| `incident` | id, merchant_id, status, cohort_key, baseline, observed, severity, at_risk_gmv, opened_at, resolved_at, detector_version |
| `evidence_item` | id, incident_id, kind, source_record_ids, value, confidence, observed_at |
| `recovery_plan` | id, incident_id, version, template, eligibility, action, constraints, expected_value, expiry, status |
| `policy_decision` | id, plan_id, policy_version, decision, rule_results, evaluated_at |
| `approval` | id, plan_id, actor, token_hash, issued_at, expires_at, consumed_at, decision |
| `recovery_action` | id, plan_id, idempotency_key, external_reference, status, request_redacted, response_redacted, attempted_at, verified_at |
| `experiment` | id, incident_id, seed, eligibility_version, treatment_ratio, attribution_window, status |
| `experiment_assignment` | experiment_id, payment_id, arm, assigned_at, outcome, recovered_amount_subunits |
| `audit_entry` | id, merchant_id, correlation_type, correlation_id, actor_type, actor_id, event, reason_code, prior_state, new_state, metadata_redacted, created_at |

All money values must be stored as integer subunits plus currency. All times
must be UTC. Raw payment credentials and card data are prohibited.

## 12. External and internal API surface

P0 API routes:

```text
POST /webhooks/razorpay
POST /demo/replay
GET  /health/live
GET  /health/ready
GET  /api/v1/overview
GET  /api/v1/incidents
GET  /api/v1/incidents/{incident_id}
POST /api/v1/incidents/{incident_id}/analyze
POST /api/v1/incidents/{incident_id}/plans
POST /api/v1/plans/{plan_id}/preview
POST /api/v1/plans/{plan_id}/approve
POST /api/v1/plans/{plan_id}/reject
POST /api/v1/plans/{plan_id}/execute
POST /api/v1/actions/{action_id}/reconcile
GET  /api/v1/experiments/{experiment_id}
GET  /api/v1/audit
```

Every endpoint must have typed request, response and error schemas. Mutating
routes must document side effects, idempotency and authorization.

## 13. Non-functional requirements

### 13.1 Reliability

- NFR-REL-001: no acknowledged webhook event is lost in controlled worker
  failure tests.
- NFR-REL-002: duplicate delivery produces zero duplicate recovery actions.
- NFR-REL-003: every external mutation is safe to retry or reconciles before
  retry.
- NFR-REL-004: the demo operates in rules-only mode when the LLM is unavailable.
- NFR-REL-005: database migrations are repeatable from an empty database.

### 13.2 Performance targets for the submission environment

- NFR-PERF-001: webhook ingestion p95 below 500 ms after the request reaches the
  application, excluding local cold start.
- NFR-PERF-002: a persisted event becomes available to the detector within five
  seconds at the default demo volume.
- NFR-PERF-003: an incident detail page becomes interactive within two seconds
  on the seeded local dataset.
- NFR-PERF-004: agent analysis has a visible timeout and never blocks event
  ingestion.

These are project targets, not claims about Razorpay production systems.

### 13.3 Security and privacy

- NFR-SEC-001: all credentials come from environment or an approved secret
  provider.
- NFR-SEC-002: webhook signatures use constant-time comparison.
- NFR-SEC-003: merchant scope is mandatory in data access and action execution.
- NFR-SEC-004: model inputs are allowlisted and redacted.
- NFR-SEC-005: the public repository contains synthetic data only.
- NFR-SEC-006: dependency, secret and static-analysis checks run in CI.
- NFR-SEC-007: external actions are Test Mode only in the submission baseline.

### 13.4 Explainability

- NFR-EXP-001: every incident shows the measured baseline, current value,
  sample size, threshold and confidence.
- NFR-EXP-002: every recommended action links to evidence and applicable policy.
- NFR-EXP-003: every blocked action shows a specific machine-readable reason.

### 13.5 Reproducibility

- NFR-REP-001: a fresh reviewer can start the application from documented
  commands.
- NFR-REP-002: a single command seeds the exact demo dataset.
- NFR-REP-003: a single command runs all release gates.
- NFR-REP-004: committed lockfiles pin dependencies.

## 14. Evaluation contract

### 14.1 Detector release targets

On the held-out synthetic test set:

| Metric | P0 target |
| --- | --- |
| Incident precision | >= 0.90 |
| Incident recall | >= 0.85 |
| Top-1 root-cause attribution accuracy | >= 0.80 |
| Duplicate action rate | 0 |
| Unauthorized action rate | 0 |
| Median time to detection at demo speed | <= 10 simulated minutes and <= 10 wall-clock seconds |

If a target is missed, report the real result and failure analysis. Never tune
against the held-out set merely to obtain the target.

### 14.2 Agent release targets

The initial golden set must contain at least 20 cases across canonical,
ambiguous and adversarial scenarios.

| Metric | P0 target |
| --- | --- |
| Valid structured-output rate | >= 0.98 |
| Material claims linked to evidence | >= 0.95 |
| Correct abstention on insufficient evidence | >= 0.90 |
| Disallowed action proposal rate after policy | 0 |
| PII/secret leakage into output | 0 |
| Correct outcome state/trajectory | 100% for consequential cases |

The evaluation approach follows Razorpay's public playbook: golden regression
sets, A/B comparisons, adversarial cases and verification of actual outcome and
trajectory rather than final prose alone:
<https://github.com/razorpay/ai-playbook/blob/master/belts/04-black/b-craft/B09-prompt-evals.md>

### 14.3 Business impact report

The final report must disclose:

- Dataset version and seed.
- Treatment and control eligibility rules.
- Sample sizes.
- Gross treatment recovery.
- Natural control recovery.
- Absolute and relative uplift.
- Incremental recovered GMV.
- Confidence interval.
- Estimated action and false-intervention cost.
- Net recovered value.
- Number and reasons for excluded or unresolved cases.
- Explicit synthetic/test-mode label.

## 15. Primary demo acceptance scenario

The release candidate passes when a reviewer can:

1. Start from healthy seeded payment traffic.
2. Inject a card/issuer degradation with a known error pattern.
3. Observe an incident open automatically.
4. See affected cohort, evidence, uncertainty and at-risk GMV.
5. Request an AI incident brief grounded in that evidence.
6. Preview a policy-approved recovery plan.
7. Approve it outside the model.
8. Create exactly one real Razorpay Test Mode Standard Payment Link.
9. Replay the webhook and simulate an ambiguous API timeout without creating a
   second logical action.
10. Complete the batch and see treatment/control recovery plus incremental GMV.
11. Inspect a complete audit timeline and action receipt.
12. Repeat the scenario with the model disabled and still finish through the
   deterministic fallback.

## 16. Definition of done

RetryRail is submission-ready only when:

- Every P0 requirement is implemented or explicitly marked as a known gap.
- All implemented release commands pass from a clean checkout.
- The held-out metrics report is committed and reproducible.
- At least one real Razorpay Test Mode Payment Link flow is demonstrated.
- Duplicate, invalid-signature, out-of-order, timeout and model-unavailable
  cases are tested.
- Audit completeness is verified automatically.
- No secret or real customer data is present in the repository or video.
- The public README explains setup, architecture, safety, evaluation and known
  limitations.
- The five-minute video fits the official limit and shows the working product.
- The application answers are copied from verified project evidence, not
  aspirational claims.

## 17. Official evidence and references

- Buildathon requirements: <https://razorpay.com/buildathon/>
- Application form: <https://forms.gle/d9r2gvxp8cmoZhon9>
- Webhook validation, duplication and ordering:
  <https://razorpay.com/docs/webhooks/validate-test/>
- Payments webhook events: <https://razorpay.com/docs/webhooks/payments/>
- Standard Payment Link API:
  <https://razorpay.com/docs/api/payments/payment-links/create-standard/>
- Razorpay official Python SDK: <https://github.com/razorpay/razorpay-python>
- Razorpay official MCP server:
  <https://github.com/razorpay/razorpay-mcp-server>
- Razorpay Blade: <https://github.com/razorpay/blade>
- Razorpay public Forward Deployed Engineer role:
  <https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4723067005>
- Agent Studio guardrails: <https://razorpay.com/blog/?p=26508>
- Razorpay Agentic Platform: <https://razorpay.com/blog/razorpay-agentic-platform/>
- Razorpay AI Playbook: <https://github.com/razorpay/ai-playbook>
- Razorpay Agent Ready engineering article:
  <https://razorpay.com/blog/razorpay-engineers-built-slash-slash-builds-the-rest/>
