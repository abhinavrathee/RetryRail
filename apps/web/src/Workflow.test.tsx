import { BladeProvider } from '@razorpay/blade/components';
import { bladeTheme } from '@razorpay/blade/tokens';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';

const INCIDENT_ID = 'inc_ui_001';
const PAYMENT_ID = 'pay_ui_001';
const PLAN_ID = 'plan_ui_001';
const ACTION_ID = 'action_ui_001';
const NOW = '2026-08-31T10:15:00Z';
const EVENT_ID = 'evt_ui_001';

const INCIDENT_SUMMARY = {
  incident: {
    schema_version: '1.0.0',
    incident_id: INCIDENT_ID,
    merchant_id: 'merchant_synthetic_001',
    status: 'open',
    detector_version: 'detector_v4_0_0',
    opened_at: '2026-08-31T10:00:00Z',
    last_observed_at: NOW,
    resolved_at: null,
    affected_cohort: [
      { dimension: 'method', value: 'upi' },
      { dimension: 'issuer', value: 'HDFC' },
    ],
    evidence_event_ids: [EVENT_ID],
    evidence: {
      baseline_attempts: 500,
      baseline_successes: 470,
      current_attempts: 120,
      current_successes: 70,
      minimum_attempts: 60,
      observed_success_rate_drop_bps: 3567,
      confidence_ppm: 990000,
      excess_failures: 43,
    },
    likely_error_sources: ['issuer'],
    gmv_at_risk_subunits: 149900,
    currency: 'INR',
    synthetic: true,
  },
  action_eligible: true,
  detector_config_sha256: 'a'.repeat(64),
  diagnosis: {
    verified_attributions: [
      {
        dimension: 'error_source',
        value: 'issuer',
        rank: 1,
        contribution_ppm: 1000000,
        confidence_ppm: 990000,
        evidence_event_ids: [EVENT_ID],
        evidence_kind: 'verified_observation',
      },
    ],
    hypotheses: [
      {
        statement: 'Merchant-local failures are concentrated at the issuer.',
        confidence_ppm: 900000,
        evidence_event_ids: [EVENT_ID],
        evidence_kind: 'inferred_hypothesis',
      },
    ],
    unknowns: ['Provider-wide conditions are not independently verified.'],
    likely_causes: ['issuer'],
  },
};

const POLICY_RULES = [
  'merchant_scope',
  'incident_action_eligibility',
  'operating_mode',
  'template_enabled',
  'original_amount',
  'currency',
  'contact_consent',
  'customer_opt_out',
  'attempt_cap',
  'cooldown',
  'plan_expiry',
  'kill_switch',
  'already_recovered',
].map((rule) => ({ rule, outcome: 'pass', reason_code: `POLICY_${rule.toUpperCase()}_PASS` }));

const PREVIEW = {
  disposition: 'created',
  preview: {
    plan: {
      plan_id: PLAN_ID,
      incident_id: INCIDENT_ID,
      mode: 'review_first',
      template: 'standard_payment_link',
      policy_version: 'recovery_policy_v1',
      created_at: NOW,
      stopping_rules: {
        maximum_actions: 1,
        maximum_attempts_per_payment: 1,
        cooldown_seconds: 900,
        expires_at: '2026-08-31T10:45:00Z',
        stop_after_recovery: true,
        merchant_kill_switch_enforced: true,
      },
      requires_external_approval: true,
      synthetic: true,
    },
    payment_id: PAYMENT_ID,
    amount_subunits: 149900,
    currency: 'INR',
    execution_target: 'deterministic_fake',
    provider_reference_id: 'rr_ui_reference_001',
    effect: 'simulated_external_mutation',
    external_notifications_enabled: false,
    preview_policy_allowed: true,
    policy_result: {
      policy_result_id: 'policy_ui_001',
      decision: 'allow',
      rule_results: POLICY_RULES,
    },
    persisted_at: NOW,
    synthetic: true,
  },
};

const TRANSITIONS = [
  { prior_state: null, new_state: 'previewed', occurred_at: NOW, actor: 'system', reason_code: 'ACTION_PREVIEWED' },
  { prior_state: 'previewed', new_state: 'awaiting_approval', occurred_at: NOW, actor: 'system', reason_code: 'ACTION_AWAITING_APPROVAL' },
  { prior_state: 'awaiting_approval', new_state: 'approved', occurred_at: NOW, actor: 'merchant', reason_code: 'ACTION_APPROVED' },
  { prior_state: 'approved', new_state: 'executing', occurred_at: NOW, actor: 'worker', reason_code: 'ACTION_EXECUTING' },
  { prior_state: 'executing', new_state: 'succeeded', occurred_at: NOW, actor: 'deterministic_fake', reason_code: 'ACTION_PROVIDER_VERIFIED' },
];

const RECEIPT = {
  action_id: ACTION_ID,
  plan_id: PLAN_ID,
  incident_id: INCIDENT_ID,
  payment_id: PAYMENT_ID,
  state: 'succeeded',
  execution_target: 'deterministic_fake',
  execution_side_effect: 'simulated_external_mutation',
  external_notifications_enabled: false,
  provider_action_id: 'plink_ui_001',
  transitions: TRANSITIONS,
  error: null,
  synthetic: true,
};

const EXPERIMENT = {
  report_id: 'recovery_experiment_report_v1',
  experiment_id: 'recovery_experiment_v1',
  generated_at: '2026-10-04T00:05:00Z',
  source_rows_scanned: 5760,
  eligible_count: 280,
  treatment: {
    eligible_count: 224,
    recovered_count: 116,
    recovery_rate_ppm: 517857,
    recovered_gmv_subunits: 20088400,
    action_count: 224,
  },
  control: {
    eligible_count: 56,
    recovered_count: 7,
    recovery_rate_ppm: 125000,
    recovered_gmv_subunits: 1999300,
  },
  value: {
    currency: 'INR',
    gross_treatment_recovered_gmv_subunits: 20088400,
    observed_control_recovered_gmv_subunits: 1999300,
    estimated_natural_recovery_in_treatment_subunits: 7997200,
    incremental_recovered_gmv_subunits: 12091200,
    action_cost_subunits: 44800,
    false_intervention_cost_subunits: 32400,
    net_recovered_value_subunits: 12014000,
    absolute_recovery_rate_uplift_bps: 3929,
  },
  uncertainty: {
    confidence_level_ppm: 950000,
    incremental_gmv_lower_subunits: 4444700,
    incremental_gmv_point_subunits: 12091200,
    incremental_gmv_upper_subunits: 18939100,
    incremental_gmv_interval_includes_zero: false,
    recovery_rate_uplift_lower_bps: 2813,
    recovery_rate_uplift_point_bps: 3929,
    recovery_rate_uplift_upper_bps: 4955,
    recovery_rate_interval_includes_zero: false,
    replicates: 10000,
  },
  conclusion: 'statistically_positive_synthetic_incremental_value',
  gross_recovery_is_not_incremental: true,
  metric_scope: 'synthetic_batch_not_live_merchant_performance',
  synthetic: true,
};

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

interface ApiScenario {
  previewBlocked?: boolean;
  ambiguousExecution?: boolean;
}

function installHappyPathApi(scenario: ApiScenario = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    await Promise.resolve();
    const url = requestUrl(input);
    const method = init?.method ?? 'GET';
    if (url.endsWith('/health/ready')) {
      return jsonResponse({ status: 'ready', service: 'retryrail-api', version: '0.1.0' });
    }
    if (url.includes('/api/v1/overview')) {
      return jsonResponse({
        detector_version: 'detector_v4_0_0',
        detector_release_status: 'qualified',
        detector_release_failed_targets: [],
        active_incidents: 1,
        action_eligible_incidents: 1,
        total_incidents: 1,
        at_risk_gmv_subunits: 149900,
        currency: 'INR',
        data_as_of: NOW,
        synthetic: true,
      });
    }
    if (url.endsWith('/api/v1/incidents?limit=50')) {
      return jsonResponse({ items: [INCIDENT_SUMMARY], count: 1, synthetic: true });
    }
    if (url.endsWith(`/api/v1/incidents/${INCIDENT_ID}`)) {
      return jsonResponse({
        summary: INCIDENT_SUMMARY,
        peak_statistics: { current_attempts: 120 },
        observations: [
          { observation_id: 'obs_ui_001', evaluated_at: NOW, statistics: { current_attempts: 120 }, evidence_event_ids: [EVENT_ID] },
        ],
        evidence_labels: ['verified_observation', 'inferred_hypothesis', 'unknown'],
        synthetic: true,
      });
    }
    if (url.endsWith(`/api/v1/incidents/${INCIDENT_ID}/analyze`) && method === 'POST') {
      return jsonResponse({
        disposition: 'created',
        brief: {
          executive_summary: 'A merchant-local UPI degradation is verified.',
          verified_evidence: [
            { statement: 'Current success is below baseline.', evidence_event_ids: [EVENT_ID] },
            { statement: 'At-risk GMV is observed exposure.', evidence_event_ids: [EVENT_ID] },
          ],
          hypotheses: [{ statement: 'Issuer concentration may explain the drop.', confidence_ppm: 900000 }],
          unknowns: ['Provider-wide health is unknown.'],
          confidence: 990000,
        },
        plan_fallback: {
          incident_id: INCIDENT_ID,
          can_create_plan: true,
          reason_code: 'RULES_FALLBACK_PLAN_AVAILABLE',
          requires_external_approval: true,
          external_notifications_enabled: false,
          plan_endpoint: `/api/v1/incidents/${INCIDENT_ID}/plans`,
          synthetic: true,
        },
        model_status: 'unavailable',
        fallback_used: true,
        fallback_reason_code: 'ANALYST_NOT_CONFIGURED',
      });
    }
    if (url.endsWith(`/api/v1/incidents/${INCIDENT_ID}/recovery-candidates`)) {
      return jsonResponse({
        incident_id: INCIDENT_ID,
        action_eligible: true,
        items: [
          {
            payment_id: PAYMENT_ID,
            amount_subunits: 149900,
            currency: 'INR',
            method: 'upi',
            issuer: 'HDFC',
            status: 'failed',
            authoritative_preview_required: true,
            synthetic: true,
          },
        ],
        count: 1,
        synthetic: true,
      });
    }
    if (url.endsWith(`/api/v1/incidents/${INCIDENT_ID}/plans`) && method === 'POST') {
      if (!scenario.previewBlocked) return jsonResponse(PREVIEW);
      return jsonResponse({
        ...PREVIEW,
        preview: {
          ...PREVIEW.preview,
          execution_target: 'razorpay_test_mode',
          effect: 'razorpay_test_mode_payment_link_creation',
          preview_policy_allowed: false,
          policy_result: {
            ...PREVIEW.preview.policy_result,
            decision: 'deny',
            rule_results: POLICY_RULES.map((rule) => rule.rule === 'kill_switch'
              ? { ...rule, outcome: 'deny', reason_code: 'POLICY_KILL_SWITCH_DENY' }
              : rule),
          },
        },
      });
    }
    if (url.endsWith(`/api/v1/plans/${PLAN_ID}/approve`) && method === 'POST') {
      return jsonResponse({
        disposition: 'created',
        approval: {
          approval_id: 'approval_ui_001',
          decision: 'approve',
          status: 'issued',
          decided_at: NOW,
          expires_at: '2026-08-31T10:25:00Z',
          synthetic: true,
        },
        approval_token: `rr_apv_${'a'.repeat(43)}`,
        token_delivery: 'issued_once',
      });
    }
    if (url.endsWith(`/api/v1/plans/${PLAN_ID}/reject`) && method === 'POST') {
      return jsonResponse({
        disposition: 'created',
        approval: {
          approval_id: 'approval_ui_reject_001',
          decision: 'reject',
          status: 'rejected',
          decided_at: NOW,
          expires_at: null,
          synthetic: true,
        },
        approval_token: null,
        token_delivery: 'not_issued',
      });
    }
    if (url.endsWith(`/api/v1/plans/${PLAN_ID}/execute`) && method === 'POST') {
      if (scenario.ambiguousExecution) {
        return jsonResponse({
          disposition: 'created',
          receipt: {
            ...RECEIPT,
            state: 'reconciliation_required',
            provider_action_id: null,
            transitions: [
              ...TRANSITIONS.slice(0, 4),
              {
                prior_state: 'executing',
                new_state: 'reconciliation_required',
                occurred_at: NOW,
                actor: 'razorpay_test_mode',
                reason_code: 'ACTION_PROVIDER_OUTCOME_AMBIGUOUS',
              },
            ],
            error: {
              category: 'provider_timeout',
              reason_code: 'PROVIDER_OUTCOME_AMBIGUOUS',
              retry_permitted: false,
              reconciliation_required: true,
            },
          },
          provider_receipt: null,
          synthetic: true,
        });
      }
      return jsonResponse({
        disposition: 'created',
        receipt: RECEIPT,
        provider_receipt: {
          provider_action_id: 'plink_ui_001',
          status: 'created',
          short_url: null,
          verified_at: NOW,
          verification_source: 'create_response',
        },
        synthetic: true,
      });
    }
    if (url.endsWith(`/api/v1/actions/${ACTION_ID}/reconcile`) && method === 'POST') {
      return jsonResponse({
        disposition: 'created',
        receipt: RECEIPT,
        provider_receipt: {
          provider_action_id: 'plink_ui_001',
          status: 'created',
          short_url: 'https://rzp.io/i/test-ui',
          verified_at: NOW,
          verification_source: 'reference_lookup',
        },
      });
    }
    if (url.endsWith(`/api/v1/actions/${ACTION_ID}`)) {
      return jsonResponse({
        receipt: RECEIPT,
        audit: {
          complete: true,
          required_facts: Array.from({ length: 13 }, (_, index) => `fact_${index.toString()}`),
          missing_facts: [],
          transition_count: 5,
          terminal_state: 'succeeded',
          synthetic: true,
        },
      });
    }
    if (url.includes('/api/v1/experiments/recovery_experiment_v1')) {
      return jsonResponse(EXPERIMENT);
    }
    if (url.endsWith('/v1/demo/run') && method === 'POST') {
      return jsonResponse({
        synthetic: true,
        replay: {
          selected_deliveries: 120,
          accepted: 110,
          duplicates: 6,
          rejected_signatures: 4,
          expectation_mismatches: 0,
        },
        projected: 110,
        retried: 0,
        dead_lettered: 0,
        detector_run_id: 'run_ui_001',
        detector_reused: false,
        source_events: 110,
        attempts: 100,
        aggregates: 12,
        incidents: 1,
        active_incidents: 1,
        at_risk_gmv_subunits: 149900,
      });
    }
    return jsonResponse({ detail: { reason_code: 'UNEXPECTED_TEST_ROUTE' } }, 404);
  });
}

function renderApp(): QueryClient {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
  render(
    <BladeProvider colorScheme="light" themeTokens={bladeTheme}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </BladeProvider>,
  );
  return queryClient;
}

async function unlock(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(screen.getByRole('button', { name: 'Unlock merchant actions' }));
  const dialog = screen.getByRole('dialog', { name: 'Unlock review actions' });
  await user.type(within(dialog).getByLabelText('Merchant authorization secret'), 'merchant-secret-for-ui-test');
  await user.type(within(dialog).getByLabelText(/Demo replay token/), 'replay-token-for-ui-test');
  await user.click(within(dialog).getByRole('button', { name: 'Unlock session' }));
}

describe('M7 merchant workflow', () => {
  beforeEach(() => {
    globalThis.history.replaceState({}, '', '/');
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('completes evidence, fallback, approval, execution, impact and demo views', async () => {
    const api = installHappyPathApi();
    const user = userEvent.setup();
    renderApp();

    expect((await screen.findAllByText('₹1,499.00')).length).toBeGreaterThanOrEqual(1);
    await user.click(screen.getByRole('link', { name: 'Inspect evidence →' }));
    expect(await screen.findByRole('heading', { name: 'Evidence classification' })).toBeInTheDocument();

    await unlock(user);
    await user.click(screen.getByRole('button', { name: 'Generate grounded brief' }));
    expect(await screen.findByText('Deterministic fallback used')).toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Open recovery preview' }));

    expect(await screen.findByText(PAYMENT_ID)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create authoritative preview' }));
    expect(await screen.findByText('Authoritative policy preview')).toBeInTheDocument();
    expect(
      screen.getByLabelText('Deterministic policy results').querySelectorAll('.policy-rule'),
    ).toHaveLength(13);

    await user.click(screen.getByRole('checkbox', { name: /I reviewed the amount/ }));
    await user.click(screen.getByRole('button', { name: 'Approve once' }));
    expect(await screen.findByRole('heading', { name: 'Approval recorded' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Execute in Deterministic fake provider/ }));
    expect(await screen.findByText('Audit chain complete')).toBeInTheDocument();

    await user.click(screen.getByRole('link', { name: 'Experiment impact' }));
    expect(await screen.findByRole('heading', { name: 'Recovery impact' })).toBeInTheDocument();
    expect(screen.getAllByText('₹1,20,912.00').length).toBeGreaterThanOrEqual(1);

    await user.click(screen.getByRole('link', { name: 'Demo controls' }));
    await user.click(await screen.findByRole('button', { name: 'Run synthetic detection demo' }));
    expect(await screen.findByText('Synthetic pipeline completed')).toBeInTheDocument();
    expect(screen.getByText('Expectations Matched')).toBeInTheDocument();

    const calls = api.mock.calls.map(([input]) => requestUrl(input));
    expect(calls.some((url) => url.endsWith(`/api/v1/plans/${PLAN_ID}/approve`))).toBe(true);
    expect(calls.some((url) => url.endsWith(`/api/v1/plans/${PLAN_ID}/execute`))).toBe(true);
  });

  it('closes and clears a merchant session without persisting secrets', async () => {
    installHappyPathApi();
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole('heading', { name: /Revenue reliability/ });

    await user.click(screen.getByRole('button', { name: 'Unlock merchant actions' }));
    const dialog = screen.getByRole('dialog', { name: 'Unlock review actions' });
    within(dialog).getByRole('button', { name: 'Unlock session' }).focus();
    await user.tab();
    expect(within(dialog).getByRole('button', { name: 'Close session dialog' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await unlock(user);
    await user.click(screen.getByRole('button', { name: /Session unlocked · Lock/ }));
    expect(screen.getByRole('button', { name: 'Unlock merchant actions' })).toBeInTheDocument();
    expect(globalThis.localStorage.length).toBe(0);
    expect(globalThis.sessionStorage.length).toBe(0);
  });

  it('fails closed when authoritative policy denies a Razorpay Test Mode preview', async () => {
    installHappyPathApi({ previewBlocked: true });
    const user = userEvent.setup();
    globalThis.history.replaceState({}, '', `/incidents/${INCIDENT_ID}/recover`);
    renderApp();

    expect(await screen.findByRole('heading', { name: 'Unlock merchant actions' })).toBeInTheDocument();
    await unlock(user);
    expect(await screen.findByText(PAYMENT_ID)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create authoritative preview' }));

    expect(await screen.findByText('Policy blocked this plan')).toBeInTheDocument();
    expect(screen.getByText('Razorpay Test Mode')).toBeInTheDocument();
    expect(screen.getByText('POLICY KILL SWITCH DENY')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve once' })).not.toBeInTheDocument();
  });

  it('supports a keyboard rejection without issuing an execution token', async () => {
    const api = installHappyPathApi();
    const user = userEvent.setup();
    globalThis.history.replaceState({}, '', `/incidents/${INCIDENT_ID}/recover`);
    renderApp();

    await unlock(user);
    await screen.findByText(PAYMENT_ID);
    await user.click(screen.getByRole('button', { name: 'Create authoritative preview' }));
    const reject = await screen.findByRole('button', { name: 'Reject plan' });
    reject.focus();
    await user.keyboard('{Enter}');

    expect(await screen.findByText('Plan rejected')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Execute in/ })).not.toBeInTheDocument();
    expect(
      api.mock.calls.some(([input]) => requestUrl(input).endsWith(`/api/v1/plans/${PLAN_ID}/reject`)),
    ).toBe(true);
  });

  it('invalidates the in-memory approval bearer when the merchant locks the session', async () => {
    installHappyPathApi();
    const user = userEvent.setup();
    globalThis.history.replaceState({}, '', `/incidents/${INCIDENT_ID}/recover`);
    renderApp();

    await unlock(user);
    await screen.findByText(PAYMENT_ID);
    await user.click(screen.getByRole('button', { name: 'Create authoritative preview' }));
    await user.click(screen.getByRole('checkbox', { name: /I reviewed the amount/ }));
    await user.click(screen.getByRole('button', { name: 'Approve once' }));
    expect(await screen.findByRole('heading', { name: 'Approval recorded' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Session unlocked · Lock/ }));
    await unlock(user);
    await screen.findByText(PAYMENT_ID);

    expect(screen.queryByRole('button', { name: /Execute in/ })).not.toBeInTheDocument();
    expect(screen.getByText('Approval bearer cleared')).toBeInTheDocument();
  });

  it('reconciles an ambiguous provider timeout by lookup only', async () => {
    const api = installHappyPathApi({ ambiguousExecution: true });
    const user = userEvent.setup();
    globalThis.history.replaceState({}, '', `/incidents/${INCIDENT_ID}/recover`);
    renderApp();

    await unlock(user);
    await screen.findByText(PAYMENT_ID);
    await user.click(screen.getByRole('button', { name: 'Create authoritative preview' }));
    await user.click(screen.getByRole('checkbox', { name: /I reviewed the amount/ }));
    await user.click(screen.getByRole('button', { name: 'Approve once' }));
    await user.click(await screen.findByRole('button', { name: /Execute in/ }));

    expect(await screen.findByText('Outcome is ambiguous')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Lookup and reconcile' }));
    expect(await screen.findByText('Audit chain complete')).toBeInTheDocument();
    expect(screen.queryByText('Outcome is ambiguous')).not.toBeInTheDocument();
    expect(
      api.mock.calls.some(([input]) => requestUrl(input).endsWith(`/api/v1/actions/${ACTION_ID}/reconcile`)),
    ).toBe(true);
  });
});
