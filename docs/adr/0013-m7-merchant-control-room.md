# ADR-0013: Present recovery as a merchant control room, not a chat surface

- Status: Accepted
- Date: 2026-09-05
- Decision owners: RetryRail maintainers
- Milestone: M7

## Context

The complete backend path is credible only if a merchant or judge can understand
the evidence, control the consequential step and distinguish gross recovery
from incremental value in a short demo. A generic AI chat window would obscure
the deterministic detector, policy, approval and audit boundaries. Browser code
must also avoid receiving Razorpay or OpenAI credentials.

## Decision

The reviewer surface is a React and TypeScript control room using Razorpay Blade
at the application boundary. It has five task-oriented routes: reliability
overview, incident evidence, recovery control, experiment impact and an isolated
synthetic demo. Routes are lazy loaded inside a responsive shell with explicit
synthetic, UTC and INR-unit labels.

The browser validates every API response with Zod. Merchant authorization and
the one-time approval bearer live only in component memory. Lock/refresh clears
the session; locking or completing execution also clears the bearer; Escape
discards unsaved dialog values. Provider credentials remain server-only. The
recovery route reveals cited candidates only after merchant authentication,
then renders the exact amount, target, external effect, expiry, stopping
controls and all 13 deterministic policy outcomes before approval. Rejection is
terminal. Approval requires an explicit review checkbox and remains outside the
model.

Execution renders the durable receipt and audit timeline. Ambiguous outcomes
offer only reference lookup; the UI has no blind create-retry path. A successful
validated provider receipt may expose its Test Mode URL. The impact route keeps
gross treatment recovery, estimated natural recovery, incremental recovered GMV,
modeled cost, net value and uncertainty visually distinct.

The demo route is local-only, token protected and prominently synthetic. It
replays a fixed tuning partition through ingestion, the transactional outbox and
the deterministic detector. Production configuration rejects replay. The demo
does not bypass merchant approval or grant model/provider authority.

Loading, empty, healthy, detected, analysis-fallback, policy-blocked,
awaiting-approval, executing, succeeded, ambiguous reconciliation,
experiment-incomplete and experiment-complete states are explicit. Keyboard
tests cover approval and rejection, and responsive visual review covers desktop
and narrow mobile layouts.

## Consequences

The primary story follows the real product sequence and makes safety controls
visible without asking reviewers to infer them from logs. Memory-only secrets
mean a refresh or route reset may require unlocking again; this is preferable to
persisting a demo secret in browser storage. The single-merchant shared-secret
boundary remains a documented demo limitation, not production IAM.

## Rejected alternatives

- **Use a chat window as the main UI.** Rejected because the product is a
  reliability and recovery workflow, and the model has advisory authority only.
- **Store tokens in local storage.** Rejected because long-lived browser storage
  is unnecessary for the demo and expands credential exposure.
- **Let the browser call Razorpay or OpenAI directly.** Rejected because it would
  expose server credentials and bypass durable policy/audit controls.
- **Hide individual policy results behind one allow/deny badge.** Rejected
  because a merchant must see why an action is allowed or blocked.
- **Combine gross and incremental recovery in one headline.** Rejected because
  gross treatment receipts are not causal lift.

## Revisit condition

Revisit session storage and navigation when real multi-user IAM, roles,
revocation and row-level merchant isolation exist. Those production controls
must replace—not silently extend—the current local shared-secret session.
