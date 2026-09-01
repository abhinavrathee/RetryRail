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
| Secret committed to Git | Environment-only configuration plus pattern scan | `retryrail-security-scan` |
| PII/card data in fixtures or normalized events | Explicit field allowlist and prohibited-key scan | Sanitization and fixture scanner tests |
| Evaluation-label leakage into runtime data | Physically separate truth artifacts and schemas | Split-isolation and forbidden-field tests |
| Detector threshold changed after blind result | Committed config hash and byte-reproducible reports | `retryrail-eval --check` plus exact-result tests |
| V2 blind output influences candidate tuning | Generator/protocol precommit, source/config/matcher/runner freeze, post-freeze nonce, event-first prediction receipt and separate truth loader | `retryrail-v2-data --check`, `retryrail-v2-candidate --check`, `retryrail-v2-blind --check` and isolation tests |
| Concurrent or replayed blind stage opens truth twice | Exclusive create-only stage locks, append-only receipts, byte-for-byte prediction replay and terminal completion/failure state | Blind workflow concurrency, tamper and replay-refusal tests |
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
| Vulnerable dependency | Locked dependency audits and high-severity CI gate | `pip-audit`, `pnpm audit --audit-level high` |
| Supply-chain script execution | pnpm runs scripts only for reviewed `esbuild` and `styled-components` packages | `pnpm-workspace.yaml` allowlist |
| CI action substitution | Third-party actions pinned to full commit SHAs | `.github/workflows/ci.yml` review |

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
pnpm audit --audit-level high
```

The repository scan is intentionally first-party: it prunes `.git`, virtual
environments, dependency stores and build output, then scans source/config text
and parses JSON/JSONL fixtures structurally. CI dependency audits cover the
pruned third-party trees.

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
- Detector-v2 R2 and the R3 blind procedure are frozen and pass development
  and orchestration tests, but no official nonce or blind result exists. Its
  prediction, report and release models force runtime action eligibility to
  false; it does not change the blocked v1 runtime decision or create a
  recovery authorization path.
