# RetryRail security baseline

## Scope

M0–M7 contain no live-money Razorpay action or customer messaging. M5 adds a
Test Mode-only Standard Payment Link boundary and synthetic causal measurement.
Its one external reviewer action was human-approved, carried no customer contact
and used a Test key; the adapter cannot accept a live key. M6 permits an optional
aggregate-only model call but grants it no policy, approval or provider
authority. M7 keeps both provider credentials outside the browser.

## Threats and current controls

| Threat | Current control | Verification |
| --- | --- | --- |
| Forged or modified webhook | Bounded exact-byte read, HMAC-SHA256 before parsing and constant-time comparison | Missing, malformed, wrong and modified-after-signing tests |
| Parser ambiguity or memory exhaustion | Duplicate JSON keys rejected; content length and streamed bytes capped | Duplicate-key and oversized-body integration tests |
| Secret or secret-shaped identifier committed to Git | Environment-only configuration, provider patterns, sensitive-key entropy scan and fail-closed GitGuardian pre-push hook | `retryrail-security-scan` plus `retryrail-pre-push` |
| Live credential reaches the Test Mode adapter | Configuration and adapter both require `rzp_test_` and reject any configured `rzp_live_` identifier | Configuration and adapter negative tests |
| Crash or timeout causes a duplicate Payment Link | Approval, action, attempt and immutable dispatch commit before network I/O; execute replay never re-POSTs and recovery is GET-only by stable reference | Crash-after-dispatch, timeout-before/after-create and replay tests |
| Provider secret, PII or raw response enters evidence | Process-only masked secrets, PII-free request contract, notifications off and allowlisted bounded response models | Credential-redaction, request-shape, response-validation and schema tests |
| Model sees payment/customer data or injected notes | Aggregate-only `IncidentSnapshot` allowlist excludes identities, raw events, notes, descriptions, contact data and credentials | Snapshot contract and 24-case privacy/prompt-injection corpus |
| Model fabricates evidence, global scope or unsafe action | Strict output schema, citation subset check, unsupported-scope scan, exact amount/currency/template/stop validation and non-executable proposal | Grounding, scope, trajectory and unsafe-action tests/evaluation |
| Model outage blocks recovery | Rules baseline persists before the call; timeout/refusal/invalid/provider error returns deterministic fallback | Provider-failure and full no-model workflow tests |
| Browser persists a merchant or approval credential | Merchant authorization and one-time bearer remain in memory; lock/refresh clears the session and lock/execution clears the bearer | Component tests for secret clearing and execution lifecycle |
| Gross or cherry-picked recovery is claimed as impact | Full qualified batch scan, remote pre-outcome assignment freeze, independent assignment/outcome namespaces, control subtraction and explicit uncertainty | `retryrail-experiment freeze --check` and `evaluate --check` |
| PII/card data in fixtures or normalized events | Explicit field allowlist and prohibited-key scan | Sanitization and fixture scanner tests |
| Evaluation-label leakage into runtime data | Physically separate truth artifacts and schemas | Split-isolation and forbidden-field tests |
| Detector threshold changed after blind result | Committed config hash and byte-reproducible reports | `retryrail-eval --check` plus exact-result tests |
| V2 blind output influences candidate tuning | Generator/protocol precommit, source/config/matcher/runner freeze, post-freeze nonce, event-first prediction receipt and separate truth loader | `retryrail-v2-data --check`, `retryrail-v2-candidate --check`, `retryrail-v2-blind --check` and isolation tests |
| V3 remediation reuses revealed evidence as blind or retries after failure | Exact development-evidence allowlist, unchanged generator digest, prior/test nonce denylist, separate candidate/runner freezes and one terminal official-run slot | `retryrail-v3-protocol --check`, `retryrail-v3-freeze --check`, `retryrail-v3-blind-postrun` and v3 isolation tests |
| V4 parent/child state hides evidence or emits duplicate incidents | Canonical-cohort lifecycle, per-cohort cooldown, label-free connected-component arbitration and typed loser dispositions | `retryrail-v4-candidate --check` and v4 lifecycle/arbitration tests |
| Required nullable report data is silently omitted | Null-preserving canonical writer, strict typed reload, open-incident field inspection and exact byte round-trip | V4 report-contract regression and artifact checks |
| Concurrent or replayed blind stage opens truth twice | Exclusive create-only stage locks, append-only receipts, byte-for-byte prediction replay and terminal completion/failure state | Blind workflow concurrency, tamper and replay-refusal tests |
| Clean checkout silently omits ignored blind inputs | V2 public-reveal reproduction is confined, digest-bound and create-only; v3 reproduces both derived inputs in memory and validates any existing bytes without rewriting | `retryrail-v2-blind-reproduce`, `retryrail-v3-blind-postrun` and reproduction tamper tests |
| Sparse high failure percentage creates an action incident | Current/baseline sample, excess-failure and GMV gates | Held-out wallet hard-negative test |
| Incident baseline absorbs incident traffic | Opening reference interval is frozen for every update | Per-observation leakage assertions |
| No traffic is mistaken for recovery | Resolution requires a sample-eligible window with the rate drop below threshold | No-traffic lifecycle regression test |
| Cross-merchant incident read or evidence link | No caller-controlled merchant scope; record/configured merchant match plus composite incident/merchant FK | API not-found and database rejection tests |
| Detector evidence rewritten | Observation/run update and delete blocked by database triggers | Integration immutability test |
| Cherry-picked or mutable synthetic results | Fixed seed, SHA-256-derived draws and committed manifest digest | Byte-determinism and artifact-digest tests |
| Unsafe production defaults | Startup validation rejects placeholder secret, SQLite and localhost CORS | Configuration refusal tests |
| Duplicate or reordered delivery | Merchant/event uniqueness, atomic outbox, monotonic state rank | Triple-delivery and captured-before-authorized tests |
| Acknowledged event lost after crash | Event and outbox commit together; finite claims are reclaimable | Controlled expired-lease recovery test |
| Poison event blocks the worker | Terminal reason codes and explicit dead-letter state | Mixed poison/healthy batch test |
| Event history changed after acceptance | Database triggers reject update and delete | Migration immutability tests |
| Demo replay exposed in production | Replay defaults off, production refuses enablement, API token compared in constant time | Configuration and replay-authentication tests |
| Browser embedding or content sniffing | `DENY`, `nosniff`, no-referrer and no-store headers | Health response tests |
| Vulnerable dependency | Locked dependency audits and high-severity CI gate | `pip-audit`, `retryrail-pnpm-audit` |
| Supply-chain script execution | pnpm runs scripts only for reviewed `esbuild` and `styled-components` packages | `pnpm-workspace.yaml` allowlist |
| CI action substitution | Third-party actions pinned to full commit SHAs | `.github/workflows/ci.yml` review |
| Mutable container image substitution | Python, Node and PostgreSQL images use explicit versions plus immutable multi-architecture SHA-256 manifest pins | `retryrail-security-scan`, pin-policy regression tests and the CI container build |

## Secret handling

- `.env` and every `.env.*` variant except `.env.example` are ignored.
- `.env.example` contains names and conspicuous local placeholders only.
- Razorpay keys are required only by the approved M5 Test Mode provider process
  and must never use a `VITE_` prefix.
- An OpenAI key is required only for the explicit M6 bakeoff or opted-in API
  analyst. It is process-only, masked by settings, absent from reports and must
  never use a `VITE_` prefix.
- The reviewer CLI reads Razorpay's two-row CSV directly from an operator path
  outside the repository. It validates exact row labels, file size and the Test
  key prefix; values are held as masked secrets and are never copied into `.env`.
- Production secrets must be injected by an approved secret provider; they may
  not appear in Compose files, logs, screenshots, fixtures, prompts or tests.
- Database URLs are held as masked secret values and revealed only to the
  connection/migration boundary; settings representations do not expose them.
- Error responses and scanner findings emit reason codes and paths, never
  suspected secret values.

## Fixture privacy policy

Committed fixtures must be synthetic and may not contain account, card,
customer, contact, address, name, email, note, token, secret or VPA fields. Any
allowlist expansion requires a documented privacy review and tests. The M1
fixtures and manifest contain invented identifiers only; generated outcomes are
prominently labelled synthetic.

## Commands

```bash
uv run bandit -c pyproject.toml -r services/api/app
uv run retryrail-security-scan
uv run pip-audit
uv run retryrail-pnpm-audit
```

The pnpm audit wrapper pins the public npm registry, discards inherited package
manager configuration and credentials, disables audit-ignore modes, requires a
structured registry report before it can succeed, and retries incomplete
results at most three times. A high or critical vulnerability report fails
immediately; abnormal exits, repeated timeouts and registry errors fail closed.

The repository scan is intentionally first-party: it prunes `.git`, virtual
environments, dependency stores and build output, then scans source/config text,
parses JSON/JSONL fixtures structurally, and rejects mutable container images in
Dockerfiles, Compose files and GitHub workflows. Multi-stage Dockerfiles may
refer to an earlier named stage or `scratch`; every external image must carry an
immutable SHA-256 digest. CI dependency audits cover the pruned third-party
trees.

## Protected pushes

`infra/git-hooks/pre-push` runs the offline repository scanner, a complete
Git-history scan and then GitGuardian's official outgoing-commit scan. All
stages are fail-closed, secret values stay hidden, repository `.env` files are
not loaded by ggshield, and the committed `.gitguardian.yaml` does not disable
detectors, paths or known incidents. The wrapper pins the public GitGuardian
instance, rejects environment-based scan bypasses and still covers every ref
and commit when the upstream pre-push optimization limits its incremental
scan. Activate it after authenticating ggshield:

```bash
uv run ggshield auth login
make install-security-hook
```

On Windows without GNU Make, run the commands from the
`install-security-hook` target directly. The hook is repository-local and is
not activated automatically by cloning because Git intentionally does not trust
committed hooks. Like every client-side hook, it can be bypassed explicitly
with Git's `--no-verify`; the CI security job therefore reruns the offline scan,
and remote GitGuardian monitoring remains the backstop for the shared
repository. Required branch protection should include that CI job.

GitGuardian incident `#36779282` classified the official blind truth-access
receipt identifier as a generic high-entropy secret. It is a synthetic internal
identifier derived from the already-public nonce commitment and grants no
access. The append-only evidence is not rewritten. The offline scanner permits
only that exact historical path/value digest; any different high-entropy value
assigned to a sensitive-looking key fails before future pushes. The dashboard
incident is classified as a false positive, not as a revoked credential.

The v3 truth-access receipt repeated the same secret-shaped identifier design.
It was detected before staging or pushing. GitGuardian now has one anchored
exact-value pattern exclusion scoped only to `abhinavrathee/RetryRail`; no
detector, path or global source was excluded. A path scan reports zero detected
and one ignored value. RetryRail's independent scanner separately permits only
the immutable v3 receipt path and exact SHA-256 value digest, with a regression
test proving that a one-character variation remains blocked. A future blind
runner must use a plainly non-secret-shaped receipt identifier before its
pre-nonce freeze rather than adding a general exception.

## M4 recovery threat boundary

ADR-0007 freezes the recovery boundary before any mutating route exists. The
only template preserves the verified source amount, disables external
notifications and has no production execution target. Policy results must
include merchant scope, qualified detector evidence, mode, template, money,
consent, opt-out, attempts, cooldown, expiry, kill switch and prior-recovery
checks; one denial makes the complete decision deny.

Approval is an authenticated merchant action outside the model. M4.3 returns an
opaque bearer once, but permits only a server-keyed hash in persistence. It is
bound to the merchant, incident, plan and preview-policy digests, expires within
fifteen minutes and is consumed by an atomic one-winner insert. The raw bearer
is prohibited from logs, audits, traces and action receipts.

The M4 action contract distinguishes the deterministic fake from Razorpay Test
Mode, binds each action to one payment and an unchanged amount/currency, and
requires a fresh execution-stage policy result. Ambiguous provider outcomes
require reconciliation and explicitly forbid blind retry. M4.1 itself adds no
endpoint, token issuer, database table, credential or provider call.

M4.2 implements policy as a pure function over validated internal facts. It
evaluates all 13 rules even after a denial, rejects unknown evaluator versions
and non-UTC timestamps, and derives its idempotent identifier from the complete
canonical context. The result is evidence, not an approval credential. A client
or model must never supply policy facts.

M4.3 now constructs those facts from locked merchant-scoped incident, payment
projection and recovery-control records plus the immutable source event and
validated server configuration. The request cannot carry money, mode, consent,
eligibility, kill-switch or decision fields. Each immutable preview stores exact
source provenance and canonical plan/policy/evidence digests. Recovery-control
defaults are created only for explicitly synthetic fixtures; missing
non-synthetic first-party controls fail closed.

Approve/reject routes use a constant-time-checked single-merchant authorization
secret and a server-configured actor identity outside the model. An approval
bearer contains 256 random bits, is returned only once, and is stored only as an
HMAC-SHA-256 digest under a separate production-required key. Exact API replay
does not repeat the bearer. Approval expiry is capped at fifteen minutes and at
plan expiry. A separate append-only consumption row has a unique approval
constraint, so concurrent uses have one winner. Missing, malformed, unknown and
mismatched tokens expose one non-oracular invalid reason.

M4.4 exposes execute and reconcile only for the injected deterministic fake.
Execution locks the plan and approval, reassembles current server-owned facts,
persists a fresh execution-stage policy result, and stops before provider access
on any denial. On allow, approval consumption, the action, its initial immutable
transitions and the bounded attempt increment share one transaction. Stable
references and database uniqueness make exact replay safe; an ambiguous timeout
can perform lookup-only reconciliation and can never retry create.

The fake request is explicitly synthetic, carries no customer contact or
credential, preserves integer amount/currency and forces external notifications
off. Its recorded side effect is `simulated_external_mutation`; it cannot attest
a Razorpay Test Mode or production action. No Razorpay key is loaded by this
path.

M4.5's rules analyst imports no model provider and cannot detect, approve or
execute. It rejects unverified evidence citations and keeps facts, hypotheses,
unknowns and observed at-risk opportunity distinct. The audit verifier requires
a pre-action brief plus the source event, incident, plan, both policy decisions,
merchant approval, token consumption, terminal transition and attempt control.

ADR-0009 adds detector-v4 activation without changing the frozen candidate,
blind report or release. Startup verifies their exact digests and qualification;
only open, synthetic incidents with the exact activated version/configuration
identity can pass recovery policy. Failed v1–v3 identities and forged v4 hashes
remain denied.

## M5 Test Mode and measurement boundary

ADR-0010 adds the network edge without moving the trust boundary into Razorpay.
The fixed HTTPS client disables redirects and automatic create retries, bounds
timeouts and response size, and sends only amount, INR currency, stable
reference, description and expiry. Partial payments, SMS, email and reminders
are disabled. Known 4xx results become typed terminal failures; a transport,
5xx or malformed-success response is ambiguous and can only be reconciled with
GET by the stored reference.

The completed external proof exercised that recovery boundary: the sole POST
returned 200, but positive provider-clock skew stopped local result validation.
The durable action remained `executing` and was completed with one GET by its
stable reference, with no repeated create. Bounded skew is now normalized while
larger skew remains typed and lookup-only after a create response.

The pre-network transaction consumes the hash-bound approval, increments the
bounded attempt control and appends the action plus provider dispatch. Only
after that transaction commits may the adapter perform one POST. A second
transaction stores the allowlisted result and SHA-256-bound provider receipt.
Both provider tables are update/delete protected. Neither table has a column for
an API key, authorization header, customer object or unbounded response body.

The reviewer CLI creates no authority during `prepare`. `execute` requires an
exact plan-specific phrase from an interactive terminal before issuing the
merchant approval token. A model response, pipe or API key alone cannot satisfy
that step. The sanitized evidence contract requires Test Mode, complete audit,
notifications off, synthetic scope and explicit `credentials_persisted=false`
and `raw_provider_response_persisted=false` values.

ADR-0011 separates the experiment into outcome-free freeze and outcome/report
stages. Commit `191ec3f` is the remote boundary containing the protocol and all
assignments before official outcomes. Every result is deterministically
reproducible and structurally labelled
`synthetic_batch_not_live_merchant_performance`; it cannot be represented as
observed merchant performance.

## M6 model boundary

ADR-0012 defines an allowlist rather than redacting an open-ended payload. The
provider receives merchant-local aggregate statistics and verified evidence
identifiers only. `store=false`, no tools, a bounded response size, a request
timeout and at most one clean schema regeneration limit provider behavior.
Invalid response text is never logged, persisted or copied into the next
request.

All accepted output passes strict Pydantic validation and deterministic
grounding. Event citations must be a subset of the verified incident evidence;
opportunity and currency must match the snapshot; the only template is the
known Standard Payment Link; all stop conditions and approval requirements are
mandatory; and global/provider-wide claims are rejected. Successful evidence is
append-only and content-addressed. Telemetry is stored separately from prose and
must agree with the validated document.

The fixed evaluation report retains no completion text. A model API key does not
unlock merchant approval, create an action or grant Razorpay access. The default
runtime remains deterministic rules when the key or external provider is
unavailable. Opted-in model startup requires a passing, corpus-bound report and
an exact configured-model match to its frozen winner.

## M7 browser boundary

The M7 API client strictly validates server responses and renders bounded reason
codes on errors. The browser never calls Razorpay or OpenAI. It stores the local
merchant secret and one-time approval bearer only in memory, clears them at the
end of authority use and does not place them in a URL or persistent browser
store. Ambiguous actions expose reference lookup only.

The synthetic demo endpoint is protected by a separate replay token, defaults
off and is rejected in production. It replays ingestion/detection only and
cannot issue approval or call a provider. Synthetic labeling remains visible in
the application shell and every impact statement.

## Known M0–M7 limits

- The M6 provider comparison is synthetic and requires an operator-owned
  OpenAI Platform key with billing. Production governance, regional processing
  review and an approved internal model proxy are not implemented.
- The M7 merchant session is a local single-merchant shared secret held in
  browser memory. It is not production IAM, RBAC, revocation, CSRF/session
  infrastructure or database row-level security.
- The P0 API currently serves one configured merchant. Recovery writes require
  a shared merchant authorization secret, but per-user sessions, roles,
  revocation and database row-level security are not yet implemented. This is a
  bounded demo control, not a production IAM claim.
- Edge/WAF rate limiting, per-user IAM and customer-facing recovery do not exist
  yet. Durable dispatch and Test Mode execution are implemented, but only the
  separately typed, sanitized Test Mode receipt may be presented as external
  provider evidence; fake receipts remain simulated-only.
- The Test Mode credential is currently operator-supplied from a local CSV for
  the one reviewer action. Production secret-manager integration, credential
  rotation automation and multi-account key selection are later hardening work.
- The M5 impact result is a versioned synthetic benchmark, not a live merchant
  experiment. Production inference requires prospective traffic, a population-
  appropriate design and operational consent/governance.
- Dead letters are retained and observable but have no operator requeue API;
  manual database mutation is intentionally not documented as a workflow.
- Local Compose placeholders are development-only and are rejected by the
  production configuration validator.
- Detector v1 failed held-out precision and recall. It is not safe to use as a
  release-qualified recovery trigger; this is a product-quality blocker, not a
  hidden security exception. Its generated release-decision artifact is bound
  to the frozen configuration hash, packaged with the service and forces
  persisted v1 incidents to remain action-ineligible.
- The default detector scans one configured merchant and refreshes from all
  completed facts. Row-level security and high-volume incremental stream
  processing remain production gaps.
- Detector-v2 R3 completed one append-only official synthetic blind run after
  the candidate and runner freezes. Prediction bytes were persisted and
  reproduced before truth access, and the public nonce was revealed only after
  the release decision. The candidate passed precision, recall, attribution,
  hard-negative and reconciliation targets but failed median detection delay
  and baseline leakage. Its generated release decision is blocked, forces
  runtime action eligibility to false and creates no recovery authorization
  path. The public nonce is reproducibility material, not a credential.
- Detector-v3 R4.4 consumed its only official synthetic blind slot. It failed
  precision and recall, and the frozen writer produced report bytes that its
  required-nullable field contract cannot reload. The exact evidence is
  preserved as `blocked` and `invalid`; runtime action eligibility and M4
  approval remain false. The separate post-run audit verifies the one known
  omission and rejects any other schema or digest difference without changing
  official evidence.
- Detector-v4 R5.1 precommits the boundary, R5.2 implements the candidate,
  R5.3 freezes the candidate plus blind runner, and R5.4 consumes one official
  synthetic blind slot only after remote freeze verification.
  The three revealed partitions are explicitly development-only, prediction
  bytes are created before truth loading, and canonical-cohort arbitration uses
  no labels or model output. The open-incident report emits `resolved_at=null`,
  strictly reloads and reproduces identical bytes. The protocol binds consumed
  and test nonce digests for future reuse rejection. Fifteen adversarial cases
  cover temporal,
  hierarchy, overlap, ordering, hard-negative, provenance and serialization
  boundaries. The runner uses repository-confined create-only writes, exclusive
  stage locks, redacted failure receipts and prediction reproduction before
  truth authorization. Its truth-access marker uses a fixed, typed `receipt_id`
  instead of a nonce-derived value under a credential-like key, preventing the
  earlier false-positive pattern by design. A report must strictly reload and
  reproduce exact bytes before completion. After a successful terminal run,
  the public-nonce reproducer creates only missing derived inputs, rejects
  symlinks and refuses to overwrite differing bytes. No new GitGuardian
  exclusion is authorized. R5.4 run
  `detector_v4_official_blind_5497598109b06d21c625` passes every unchanged
  target and its strict report contract. The public reveal was scanned as
  non-secret, the typed release is qualified for integration review, and R5.5
  release verification passed. Its frozen historical action flags remain false;
  the separate hash-bound M4 activation permits only the exact qualified v4
  identity to enter the synthetic fake or human-approved Test Mode recovery
  boundary.
