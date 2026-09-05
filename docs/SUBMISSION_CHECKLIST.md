# RetryRail Razorpay submission checklist

This checklist mirrors the official Buildathon page and the application form
structure, last re-verified on 2026-09-04. Do not submit until every required
claim is supported by the public repository or video.

## 0. Submission clock

- [ ] Treat **September 5, 2026** as the final submission date. Razorpay
  Careers says “Apply by 5 Sep.”
- [ ] Do not assume the form remains open until 11:59 PM. The official landing
  page, Careers notice and application form publish no cutoff hour or timezone.
- [ ] Submit early enough to reopen the public repository and video links in a
  signed-out browser before sending the irreversible final form response.

Deadline references:
<https://www.linkedin.com/posts/razorpay-careers_razorpaybuildathon-aiinterns-hiring-activity-7497899727838076929-UjeL>
and <https://razorpay.com/buildathon/>.

## 1. Eligibility and internship choices

- [ ] The applicant is currently a student.
- [ ] Graduation year is one of the form's available choices: 2027, 2028 or
  2029.
- [ ] The in-person Bangalore availability question has been answered honestly.
- [ ] If available, a preferred duration has been selected: 6-month or 12-month
  internship.
- [ ] Track 3 — AI Revenue Recovery is selected.

The public page states that the internship is in person in Bangalore, begins
from September, pays a ₹75,000 monthly stipend and can be 6 or 12 months.
Reference: <https://razorpay.com/buildathon/>

## 2. Exact application fields

The official form asks for:

- [ ] Email.
- [ ] Full Name.
- [ ] College Name.
- [ ] Graduation Year.
- [ ] In-person Internship availability starting September.
- [ ] Preferred Internship Duration when applicable.
- [ ] Selected Track.
- [ ] Project Name / Title.
- [ ] Project Objectives — “What does it solve?”
- [ ] GitHub Repository URL.
- [ ] 5-min Pitch Video Link.
- [ ] Build Challenges & Technical Obstacles — what issues were faced and how
  they were solved.
- [ ] Final Submission Confirmation.

The confirmation says that the response is the official final submission and
cannot be changed afterward. Treat the final submission as irreversible.

Form reference: <https://forms.gle/d9r2gvxp8cmoZhon9>

## 3. Recommended form content

### Project Name / Title

```text
RetryRail — AI-Powered Payment Reliability & Revenue Recovery
```

### Project Objectives draft

Update the bracketed values with verified final results. Do not claim a result
that is not reproduced in the repository.

```text
RetryRail helps Razorpay merchants detect silent, cohort-level payment
degradation before it becomes significant revenue loss. It consumes
Razorpay-shaped payment events, identifies the affected payment method or
issuer cohort with evidence, estimates GMV at risk, and uses a bounded AI
analyst to propose only merchant-authorized interventions. A deterministic
policy engine enforces consent, approval, stopping rules and idempotency before
creating a recovery Payment Link through Razorpay Test Mode. RetryRail then
measures treatment versus holdout outcomes so it reports incremental recovered
GMV rather than taking credit for natural recovery. On our held-out synthetic
batch of [N] attempts, the detector achieved [precision] precision and [recall]
recall, while the recovery workflow produced [uplift] absolute uplift and
[amount] in simulated incremental recovered GMV, with zero duplicate or
unauthorized actions.
```

### Build Challenges & Technical Obstacles draft structure

Use three or four evidence-backed obstacles. Strong candidates are:

```text
1. Duplicate and out-of-order payment events
Razorpay webhooks can be duplicated or arrive out of order. We validated the
signature against the raw body, deduplicated by merchant plus
x-razorpay-event-id, persisted an immutable event log and used a transactional
outbox. We proved the design with three duplicate redeliveries, an expired
worker claim and captured-before-authorized order; it produced one logical
event/processing chain and the correct final payment state.

2. Distinguishing real degradation from low-volume noise
Simple percentage thresholds generated false alarms. We introduced a minimum
sample gate, leakage-safe baseline, EWMA/CUSUM change detection and a
proportion-confidence check, then froze thresholds before evaluating on a
held-out set. Final precision/recall were [values], with [false-positive cost].

3. Preventing an AI explanation from becoming an unsafe money action
M4 proves this boundary with the model unavailable: the rules analyst can
recommend only a predefined template and has no approval, credential or
execution authority. A deterministic policy layer rechecks amount, consent,
scope, cooldown, approval and kill switch immediately before execution. M6 must
prove that any added LLM sees only the redacted structured snapshot and remains
behind exactly the same boundary before this paragraph is used in a submission.

4. Measuring actual recovery rather than correlation
Some customers would recover naturally. M5 must assign eligible failures
deterministically to treatment and holdout groups, fix the attribution window
before outcomes, and report both gross and incremental recovered GMV with
uncertainty. Do not convert this to past tense until that versioned experiment
passes; M4's at-risk opportunity and fake receipt are not causal evidence.
```

Only retain challenges actually encountered and solved. Add links to the most
relevant tests, ADRs or evaluation report in the public README.

## 4. Public repository gate

- [ ] Repository visibility is Public.
- [ ] Default branch contains the exact submission commit.
- [ ] A version tag such as `buildathon-submission-v1` marks the submission.
- [x] README begins with the problem, outcome and a 60-second review/demo path.
- [x] README contains a polished system map and a parseable recovery sequence.
- [x] README states Test Mode and synthetic-data limitations prominently.
- [x] Setup has been tested from a clean checkout.
- [x] Lockfiles are committed.
- [x] `.env.example` contains names and safe placeholders only.
- [x] No key, secret, token, personal contact data or real transaction data is
  present in Git history.
- [ ] `make seed`, `make demo` and `make check` work as documented.
- [x] Held-out detector report is committed.
- [x] Agent golden/adversarial evaluation report is committed.
- [ ] Screenshots show the final current UI.
- [x] Known limitations and unresolved exceptions are honest.
- [x] License and attribution are present.
- [ ] Repository opens and renders correctly when signed out of GitHub.

### 4.1 Reviewer deployment gate

- [x] A versioned Render Blueprint provisions the API/UI, dedicated worker and
  PostgreSQL in one region.
- [x] The deployment image builds the exact locked frontend and backend, then
  serves them from one origin.
- [x] The `review` environment requires strong distinct secrets, a PostgreSQL
  store, deterministic adapters and an enabled recovery kill switch.
- [x] Database migrations run before the web rollout and readiness checks the
  exact Alembic head.
- [x] Synthetic tuning data is seeded through authenticated ingestion rather
  than inserted around the application boundary.
- [x] The judge seed ends at a verified healthy baseline; the protected demo
  advances the same stream to a tested active-incident boundary.
- [x] The deployment and UptimeRobot procedure is documented in
  `docs/DEPLOYMENT.md`.
- [x] The exact deployment image, empty-database migration, API/UI/worker
  startup, review-mode security surface and full synthetic initial hook were
  rehearsed locally with zero replay expectation mismatches.
- [x] The remote container gate rebuilds the Render reviewer image from the
  committed Dockerfile on every main-branch release run.
- [ ] Render shows the web service, worker and database as healthy.
- [ ] `GET /health/ready` returns HTTP 200 from the assigned public hostname.
- [ ] UptimeRobot monitors `/health/ready` and has a working alert contact.
- [ ] The deployed root and a nested incident URL work in a signed-out browser.
- [ ] Final screenshots were recaptured from the verified deployment URL.
- [ ] The verified deployment URL is linked from the README.

## 5. Product proof gate

- [ ] The demo begins from a healthy baseline.
- [ ] A deterministic batch triggers a real detected incident.
- [ ] The incident shows measured evidence and at-risk GMV.
- [ ] The AI explanation cites evidence and uncertainty.
- [ ] The plan preview shows action effects and stopping rules.
- [x] Approval occurs outside the model.
- [x] One real Razorpay Test Mode Standard Payment Link is created.
- [x] Duplicate replay produces no duplicate logical action.
- [x] Ambiguous timeout is reconciled safely.
- [x] Treatment/control results show incremental recovered GMV.
- [x] Synthetic outcome labels are visible.
- [x] A complete audit receipt is visible.
- [x] Model-unavailable fallback has been tested.

## 6. Five-minute video gate

- [ ] Final duration is at most 5:00; target is 4:40.
- [ ] Video opens with the merchant problem, not team introductions.
- [ ] Product is visible within the first 25 seconds.
- [ ] Live behavior is shown; slides do not replace the demo.
- [ ] At least one failure is handled visibly.
- [ ] The real Test Mode receipt is visible without exposing credentials.
- [ ] Metrics identify dataset size and synthetic/test-mode status.
- [ ] Architecture and trust boundaries are explained briefly.
- [ ] Claims match the tagged public commit.
- [ ] Text is readable at normal playback resolution.
- [ ] Audio is clear and background notifications are disabled.
- [ ] Video link is accessible without requesting permission or signing in.

Recommended timing:

```text
0:00–0:25  problem and promise
0:25–0:50  differentiation
0:50–1:20  degradation injection and detection
1:20–1:55  evidence and diagnosis
1:55–2:25  bounded AI analysis
2:25–3:05  policy, approval and stopping rules
3:05–3:35  Razorpay Test Mode action
3:35–4:00  duplicate/timeout failure handling
4:00–4:25  treatment/control recovered-GMV result
4:25–4:40  architecture, audit and close
```

## 7. Final pre-submit audit

- [ ] Run the full test and evaluation suite from the tagged commit.
- [ ] Save or link the final CI run.
- [ ] Verify the repository URL in a signed-out/private browser session.
- [ ] Verify the video URL in a signed-out/private browser session.
- [ ] Spell-check the project title and objective.
- [ ] Replace every bracketed placeholder in the form drafts.
- [ ] Remove every unimplemented feature from the application text and video.
- [ ] Confirm no confidential screenshots, keys or account identifiers appear.
- [ ] Rehearse the exact demo twice from a clean seed.
- [ ] Confirm the selected internship duration and in-person answer are correct.
- [ ] Review the final confirmation language once more.
- [ ] Submit only when all irreversible-final-submission fields are correct.

## 8. Evidence index to prepare

| Claim | Evidence location |
| --- | --- |
| Detector precision/recall | V1 remains failed; v2 remains blocked on delay/leakage; v3 remains blocked and procedurally invalid. V4 official synthetic blind run `detector_v4_official_blind_5497598109b06d21c625` records 1,000,000 ppm precision and recall and passes every frozen detector target. Label it synthetic and do not imply production performance or active recovery |
| Root-cause accuracy | V1 held-out remains unscorable after the miss; v2/v3 official evidence records 1,000,000 ppm top-1 attribution but failed other release gates. The qualified v4 official synthetic blind report records 1,000,000 ppm top-1 attribution |
| Agent grounding/safety | `evals/reports/agent-golden.json` |
| No duplicate action | `services/api/tests/recovery/test_workflow.py` concurrent execute/replay cases and immutable action receipt |
| Timeout reconciliation | `services/api/tests/recovery/test_workflow.py` before/after-create ambiguity cases plus the committed Test Mode receipt: the one accepted POST was followed by a crash-equivalent parse failure and recovered by GET only |
| Incremental recovered GMV | `evals/reports/recovery_experiment_v1.report.json` |
| Razorpay integration | `evals/reports/razorpay_test_mode_receipt.v1.json` |
| Complete audit | The committed Test Mode receipt plus `services/api/tests/recovery/test_m4_release_gate.py`; reviewer UI timeline remains M7 |
| Clean release | Public CI run for tagged commit |

Later-milestone paths remain required targets. V4's qualifying synthetic
detector decision, R5.5 verification and M4's deterministic model-unavailable
fake recovery loop are complete. The fake receipt is explicitly simulated;
the one human-approved Razorpay Test Mode execution and the treatment/control
experiment now close M5. If any strong component metric is used in the
application, its synthetic limitation and relevant blocked predecessor context
must appear beside it. V3's
report-contract defect must still be disclosed wherever its official metrics
appear. V4 R5.2 results remain revealed development evidence;
only the append-only R5.4 run may be described as v4 blind qualification.
