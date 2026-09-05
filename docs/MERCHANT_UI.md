# M7 merchant control room

M7 turns the already-proven detector-to-impact backend into a reviewer-facing
merchant workflow. It is a control room, not a chat interface. Model analysis is
advisory; every consequential action stays behind deterministic policy and an
explicit merchant decision.

## Views

| Route | Purpose |
| --- | --- |
| `/` | Reliability overview, healthy/incident states, payment volume and GMV at risk |
| `/incidents/:incidentId` | Detector evidence, affected cohort, verified attribution and bounded analysis/fallback |
| `/incidents/:incidentId/recover` | Cited candidate, authoritative preview, all 13 policy rules, approval, execution and audit |
| `/impact` | Frozen treatment/control result, uncertainty and incremental—not gross—recovered GMV |
| `/demo` | Token-protected local synthetic replay and deterministic detection |

Every page sits inside one responsive navigation shell and labels synthetic
evidence, UTC timestamps and INR units. The production bundle lazy-loads route
content while preserving an accessible loading state.

## Browser trust boundary

The browser receives no Razorpay or OpenAI key. The local merchant authorization
secret is held in React memory only. It is never written to local storage,
session storage, the URL or rendered logs, and it is cleared when the merchant
locks or refreshes the session. Escape closes the dialog and discards unsaved
values. The one-time approval bearer is also memory-only and is cleared on
lock, after execution or after an execution error.

API responses are validated by Zod before display. Server errors are reduced to
typed reason codes; arbitrary upstream response bodies are not rendered.

## Recovery interaction

The recovery view follows the backend authority chain:

1. Authenticate and load only failed payments cited by verified incident
   evidence.
2. Select one candidate and request a fresh server-owned preview.
3. Review exact integer-subunit amount, currency, target, side effect, expiry,
   attempt cap, cooldown, notification state and all 13 policy results.
4. Confirm the review checkbox, then approve once or reject.
5. Execute with the one-time bearer; policy is reevaluated before provider
   access.
6. Inspect the immutable receipt and complete audit timeline.
7. If the outcome is ambiguous, perform reference lookup only. The UI exposes no
   second create action.

A policy denial renders a blocked state and no approval control. Rejection is
terminal. Test Mode links are rendered only from a validated successful provider
receipt and open in a separate tab.

## Required states

The components explicitly cover empty/no incident, healthy monitoring,
loading/replay, detected incident, unavailable analysis with fallback,
policy-blocked preview, awaiting approval, executing action, successful action,
ambiguous reconciliation, incomplete experiment and complete experiment. Error
states are local to the affected action and include a safe retry only where the
server contract permits it.

## Isolated synthetic demo

`POST /v1/demo/run` is local-only and requires the replay token. It replays the
fixed tuning partition, drains the transactional outbox through the real
projector and runs deterministic detection. It returns aggregate counts and
incident identifiers only. The endpoint is disabled by default and production
configuration rejects replay entirely.

The demo control does not create a plan, generate merchant approval or call a
provider. The normal authenticated recovery screens remain the only path to an
external Test Mode effect.

For local use, copy `.env.example` to `.env`, set
`RETRYRAIL_REPLAY_ENABLED=true`, replace `RETRYRAIL_REPLAY_TOKEN`, then start the
API and web application. Enter only the replay token on `/demo`; never enter a
Razorpay or OpenAI key in the browser.

## Verification

Vitest covers the complete successful path, policy denial, keyboard rejection,
secret clearing, ambiguous reconciliation, typed API errors and lookup-only
request shape. Playwright covers the primary evidence → fallback → preview →
keyboard approval → execution → audit → impact → demo story and the independent
keyboard rejection path. The M7 demo gate is:

```powershell
uv run pytest services/api/tests/integration/test_replay_and_migrations.py -q -k bounded_demo_run
pnpm --filter @retryrail/web exec playwright test tests/m7-workflow.spec.ts --workers=1
```

Desktop and 390-pixel responsive layouts were visually reviewed. Reduced-motion
preferences are honored, focus targets remain native controls and no color-only
signal carries policy or outcome meaning.

## Deliberate limits

- Authentication is a single-merchant local shared-secret boundary, not
  production user IAM, RBAC or revocation.
- The responsive narrow layout is reviewer convenience, not a claimed native
  mobile product.
- The impact page presents the frozen synthetic M5 batch and cannot be
  generalized to live merchant performance.
- Deployment, external TLS/WAF and public signed-out verification belong to M8
  and M9.
