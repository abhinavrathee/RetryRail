# RetryRail security baseline

## Scope

M0–M3 contain no live Razorpay action, customer messaging or model call. M3
adds deterministic aggregates, diagnosis and incident reads; it cannot initiate
a payment or customer-facing mutation.

## Threats and current controls

| Threat | Current control | Verification |
| --- | --- | --- |
| Forged or modified webhook | Bounded exact-byte read, HMAC-SHA256 before parsing and constant-time comparison | Missing, malformed, wrong and modified-after-signing tests |
| Parser ambiguity or memory exhaustion | Duplicate JSON keys rejected; content length and streamed bytes capped | Duplicate-key and oversized-body integration tests |
| Secret or secret-shaped identifier committed to Git | Environment-only configuration, provider patterns, sensitive-key entropy scan and fail-closed GitGuardian pre-push hook | `retryrail-security-scan` plus `retryrail-pre-push` |
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
- Razorpay keys are not required before M5 and must never use a `VITE_` prefix.
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

## Known M0–M3 limits

- The P0 API currently serves one configured merchant. Full merchant
  authentication/authorization and database row-level security are not yet
  implemented; a mismatched merchant path fails closed.
- Edge/WAF rate limiting, approval tokens, policy revalidation and recovery
  action receipts do not exist until their planned milestones. No endpoint
  currently claims those protections.
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
  non-secret, the typed release is qualified for integration review, and all
  runtime action flags remain false pending R5.5 and M4.
