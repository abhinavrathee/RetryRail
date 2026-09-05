import { expect, test, type Page } from '@playwright/test';

const INCIDENT_ID = 'inc_e2e_001';
const PAYMENT_ID = 'pay_e2e_001';
const PLAN_ID = 'plan_e2e_001';
const ACTION_ID = 'action_e2e_001';
const EVENT_ID = 'evt_e2e_001';
const NOW = '2026-08-31T10:15:00Z';

const incidentSummary = {
  incident: {
    incident_id: INCIDENT_ID,
    merchant_id: 'merchant_synthetic_e2e',
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
    verified_attributions: [{
      dimension: 'error_source',
      value: 'issuer',
      rank: 1,
      contribution_ppm: 1000000,
      confidence_ppm: 990000,
      evidence_event_ids: [EVENT_ID],
      evidence_kind: 'verified_observation',
    }],
    hypotheses: [{
      statement: 'Merchant-local failures are concentrated at the issuer.',
      confidence_ppm: 900000,
      evidence_event_ids: [EVENT_ID],
      evidence_kind: 'inferred_hypothesis',
    }],
    unknowns: ['Provider-wide conditions are not independently verified.'],
    likely_causes: ['issuer'],
  },
};

const ruleNames = [
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
];

const preview = {
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
    provider_reference_id: 'rr_e2e_reference_001',
    effect: 'simulated_external_mutation',
    external_notifications_enabled: false,
    preview_policy_allowed: true,
    policy_result: {
      policy_result_id: 'policy_e2e_001',
      decision: 'allow',
      rule_results: ruleNames.map((rule) => ({
        rule,
        outcome: 'pass',
        reason_code: `POLICY_${rule.toUpperCase()}_PASS`,
      })),
    },
    persisted_at: NOW,
    synthetic: true,
  },
};

const transitions = [
  { prior_state: null, new_state: 'previewed', occurred_at: NOW, actor: 'system', reason_code: 'ACTION_PREVIEWED' },
  { prior_state: 'previewed', new_state: 'awaiting_approval', occurred_at: NOW, actor: 'system', reason_code: 'ACTION_AWAITING_APPROVAL' },
  { prior_state: 'awaiting_approval', new_state: 'approved', occurred_at: NOW, actor: 'merchant', reason_code: 'ACTION_APPROVED' },
  { prior_state: 'approved', new_state: 'executing', occurred_at: NOW, actor: 'worker', reason_code: 'ACTION_EXECUTING' },
  { prior_state: 'executing', new_state: 'succeeded', occurred_at: NOW, actor: 'deterministic_fake', reason_code: 'ACTION_PROVIDER_VERIFIED' },
];

const receipt = {
  action_id: ACTION_ID,
  plan_id: PLAN_ID,
  incident_id: INCIDENT_ID,
  payment_id: PAYMENT_ID,
  state: 'succeeded',
  execution_target: 'deterministic_fake',
  execution_side_effect: 'simulated_external_mutation',
  external_notifications_enabled: false,
  provider_action_id: 'plink_e2e_001',
  transitions,
  error: null,
  synthetic: true,
};

const experiment = {
  report_id: 'recovery_experiment_report_v1',
  experiment_id: 'recovery_experiment_v1',
  generated_at: '2026-10-04T00:05:00Z',
  source_rows_scanned: 5760,
  eligible_count: 280,
  treatment: { eligible_count: 224, recovered_count: 116, recovery_rate_ppm: 517857, recovered_gmv_subunits: 20088400, action_count: 224 },
  control: { eligible_count: 56, recovered_count: 7, recovery_rate_ppm: 125000, recovered_gmv_subunits: 1999300 },
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

async function installApi(page: Page, requests: string[]): Promise<void> {
  await page.route('http://127.0.0.1:8000/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    requests.push(`${method} ${pathname}`);

    let json: unknown;
    if (pathname === '/health/ready') {
      json = { status: 'ready', service: 'retryrail-api', version: '0.1.0' };
    } else if (pathname === '/api/v1/overview') {
      json = {
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
      };
    } else if (pathname === '/api/v1/incidents') {
      json = { items: [incidentSummary], count: 1, synthetic: true };
    } else if (pathname === `/api/v1/incidents/${INCIDENT_ID}` && method === 'GET') {
      json = {
        summary: incidentSummary,
        peak_statistics: { current_attempts: 120 },
        observations: [{ observation_id: 'obs_e2e_001', evaluated_at: NOW, statistics: { current_attempts: 120 }, evidence_event_ids: [EVENT_ID] }],
        evidence_labels: ['verified_observation', 'inferred_hypothesis', 'unknown'],
        synthetic: true,
      };
    } else if (pathname.endsWith('/analyze')) {
      json = {
        disposition: 'created',
        brief: {
          executive_summary: 'A merchant-local UPI degradation is verified.',
          verified_evidence: [{ statement: 'Current success is below baseline.', evidence_event_ids: [EVENT_ID] }],
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
      };
    } else if (pathname.endsWith('/recovery-candidates')) {
      json = {
        incident_id: INCIDENT_ID,
        action_eligible: true,
        items: [{
          payment_id: PAYMENT_ID,
          amount_subunits: 149900,
          currency: 'INR',
          method: 'upi',
          issuer: 'HDFC',
          status: 'failed',
          authoritative_preview_required: true,
          synthetic: true,
        }],
        count: 1,
        synthetic: true,
      };
    } else if (pathname.endsWith('/plans')) {
      json = preview;
    } else if (pathname.endsWith('/approve')) {
      json = {
        disposition: 'created',
        approval: { approval_id: 'approval_e2e_001', decision: 'approve', status: 'issued', decided_at: NOW, expires_at: '2026-08-31T10:25:00Z', synthetic: true },
        approval_token: `rr_apv_${'a'.repeat(43)}`,
        token_delivery: 'issued_once',
      };
    } else if (pathname.endsWith('/reject')) {
      json = {
        disposition: 'created',
        approval: { approval_id: 'approval_e2e_reject', decision: 'reject', status: 'rejected', decided_at: NOW, expires_at: null, synthetic: true },
        approval_token: null,
        token_delivery: 'not_issued',
      };
    } else if (pathname.endsWith('/execute')) {
      json = {
        disposition: 'created',
        receipt,
        provider_receipt: { provider_action_id: 'plink_e2e_001', status: 'created', short_url: null, verified_at: NOW, verification_source: 'create_response' },
        synthetic: true,
      };
    } else if (pathname === `/api/v1/actions/${ACTION_ID}`) {
      json = { receipt, audit: { complete: true, required_facts: ruleNames, missing_facts: [], transition_count: 5, terminal_state: 'succeeded', synthetic: true } };
    } else if (pathname === '/api/v1/experiments/recovery_experiment_v1') {
      json = experiment;
    } else if (pathname === '/v1/demo/run') {
      json = {
        synthetic: true,
        replay: { selected_deliveries: 120, accepted: 110, duplicates: 6, rejected_signatures: 4, expectation_mismatches: 0 },
        projected: 110,
        retried: 0,
        dead_lettered: 0,
        detector_run_id: 'run_e2e_001',
        detector_reused: false,
        source_events: 110,
        attempts: 100,
        aggregates: 12,
        incidents: 1,
        active_incidents: 1,
        at_risk_gmv_subunits: 149900,
      };
    } else {
      await route.fulfill({ status: 404, json: { detail: { reason_code: 'E2E_ROUTE_MISSING' } } });
      return;
    }
    await route.fulfill({ status: 200, json });
  });
}

async function unlockWithKeyboard(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Unlock merchant actions' }).click();
  const dialog = page.getByRole('dialog', { name: 'Unlock review actions' });
  await dialog.getByLabel('Merchant authorization secret').fill('merchant-e2e-secret');
  await dialog.getByLabel(/Demo replay token/).fill('demo-e2e-token');
  await dialog.getByRole('button', { name: 'Unlock session' }).focus();
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
}

test('primary M7 evidence-to-impact demo is operable by keyboard at approval', async ({ page }) => {
  const requests: string[] = [];
  await installApi(page, requests);
  await page.goto('/');

  await expect(page.getByRole('heading', { name: /Revenue reliability/ })).toBeVisible();
  await page.getByRole('link', { name: 'Inspect evidence →' }).click();
  await expect(page.getByRole('heading', { name: 'Evidence classification' })).toBeVisible();

  await unlockWithKeyboard(page);
  await page.getByRole('button', { name: 'Generate grounded brief' }).click();
  await expect(page.getByText('Deterministic fallback used')).toBeVisible();
  await page.getByRole('link', { name: 'Open recovery preview' }).click();
  await expect(page.getByText(PAYMENT_ID)).toBeVisible();
  await page.getByRole('button', { name: 'Create authoritative preview' }).click();
  await expect(page.getByLabel('Deterministic policy results').locator('.policy-rule')).toHaveCount(13);

  const review = page.getByRole('checkbox', { name: /I reviewed the amount/ });
  await review.focus();
  await page.keyboard.press('Space');
  const approve = page.getByRole('button', { name: 'Approve once' });
  await approve.focus();
  await page.keyboard.press('Enter');
  const execute = page.getByRole('button', { name: /Execute in Deterministic fake provider/ });
  await execute.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Audit chain complete')).toBeVisible();

  await page.getByRole('link', { name: 'Experiment impact' }).click();
  await expect(page.getByRole('heading', { name: 'Recovery impact' })).toBeVisible();
  await expect(page.getByText('Synthetic benchmark', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Demo controls' }).click();
  const demo = page.getByRole('button', { name: 'Run synthetic detection demo' });
  await demo.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Synthetic pipeline completed' })).toBeVisible();

  expect(requests).toContain(`POST /api/v1/plans/${PLAN_ID}/approve`);
  expect(requests).toContain(`POST /api/v1/plans/${PLAN_ID}/execute`);
  expect(requests).toContain('POST /v1/demo/run');
});

test('merchant can reject a preview with Enter and no execute request is sent', async ({ page }) => {
  const requests: string[] = [];
  await installApi(page, requests);
  await page.goto(`/incidents/${INCIDENT_ID}/recover`);
  await unlockWithKeyboard(page);
  await expect(page.getByText(PAYMENT_ID)).toBeVisible();
  await page.getByRole('button', { name: 'Create authoritative preview' }).click();

  const reject = page.getByRole('button', { name: 'Reject plan' });
  await reject.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Plan rejected')).toBeVisible();
  expect(requests).toContain(`POST /api/v1/plans/${PLAN_ID}/reject`);
  expect(requests.some((request) => request.endsWith('/execute'))).toBe(false);
});
