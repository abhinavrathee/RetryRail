import { z } from 'zod';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(
  /\/$/u,
  '',
) ?? 'http://127.0.0.1:8000';

const cohortSchema = z.object({
  dimension: z.string(),
  value: z.string(),
});

const evidenceSchema = z.object({
  baseline_attempts: z.number().int().nonnegative(),
  baseline_successes: z.number().int().nonnegative(),
  current_attempts: z.number().int().nonnegative(),
  current_successes: z.number().int().nonnegative(),
  minimum_attempts: z.number().int().positive(),
  observed_success_rate_drop_bps: z.number().int().nonnegative(),
  confidence_ppm: z.number().int().nonnegative(),
  excess_failures: z.number().int().nonnegative(),
});

const attributionSchema = z.object({
  dimension: z.string(),
  value: z.string(),
  rank: z.number().int().positive(),
  contribution_ppm: z.number().int().nonnegative(),
  confidence_ppm: z.number().int().nonnegative(),
  evidence_event_ids: z.array(z.string()),
  evidence_kind: z.literal('verified_observation'),
});

const hypothesisSchema = z.object({
  statement: z.string(),
  confidence_ppm: z.number().int().nonnegative(),
  evidence_event_ids: z.array(z.string()),
  evidence_kind: z.literal('inferred_hypothesis'),
});

const incidentSchema = z.object({
  incident_id: z.string(),
  merchant_id: z.string(),
  status: z.enum(['open', 'resolved']),
  detector_version: z.string(),
  opened_at: z.string(),
  last_observed_at: z.string(),
  resolved_at: z.string().nullable(),
  affected_cohort: z.array(cohortSchema),
  evidence_event_ids: z.array(z.string()),
  evidence: evidenceSchema,
  likely_error_sources: z.array(z.string()),
  gmv_at_risk_subunits: z.number().int().nonnegative(),
  currency: z.string().length(3),
  synthetic: z.boolean(),
});

const incidentSummarySchema = z.object({
  incident: incidentSchema,
  action_eligible: z.boolean(),
  detector_config_sha256: z.string(),
  diagnosis: z.object({
    verified_attributions: z.array(attributionSchema),
    hypotheses: z.array(hypothesisSchema),
    unknowns: z.array(z.string()),
    likely_causes: z.array(z.string()),
  }),
});

const overviewSchema = z.object({
  detector_version: z.string(),
  detector_release_status: z.string(),
  detector_release_failed_targets: z.array(z.string()),
  active_incidents: z.number().int().nonnegative(),
  action_eligible_incidents: z.number().int().nonnegative(),
  total_incidents: z.number().int().nonnegative(),
  at_risk_gmv_subunits: z.number().int().nonnegative(),
  currency: z.string().length(3),
  data_as_of: z.string().nullable(),
  synthetic: z.boolean(),
});

const incidentListSchema = z.object({
  items: z.array(incidentSummarySchema),
  count: z.number().int().nonnegative(),
  synthetic: z.boolean(),
});

const incidentDetailSchema = z.object({
  summary: incidentSummarySchema,
  peak_statistics: z.record(z.string(), z.unknown()),
  observations: z.array(
    z.object({
      observation_id: z.string(),
      evaluated_at: z.string(),
      statistics: z.record(z.string(), z.unknown()),
      evidence_event_ids: z.array(z.string()),
    }),
  ),
  evidence_labels: z.array(
    z.enum(['verified_observation', 'inferred_hypothesis', 'unknown']),
  ),
  synthetic: z.boolean(),
});

const candidateListSchema = z.object({
  incident_id: z.string(),
  action_eligible: z.boolean(),
  items: z.array(
    z.object({
      payment_id: z.string(),
      amount_subunits: z.number().int().positive(),
      currency: z.string().length(3),
      method: z.string(),
      issuer: z.string().nullable(),
      status: z.literal('failed'),
      authoritative_preview_required: z.literal(true),
      synthetic: z.boolean(),
    }),
  ),
  count: z.number().int().nonnegative(),
  synthetic: z.boolean(),
});

const analystEvidenceSchema = z.object({
  statement: z.string(),
  evidence_ids: z.array(z.string()).optional(),
  evidence_event_ids: z.array(z.string()).optional(),
});

const analystBriefSchema = z.object({
  executive_summary: z.string(),
  verified_evidence: z.array(analystEvidenceSchema),
  hypotheses: z.array(
    z.object({
      statement: z.string(),
      confidence_ppm: z.number().int().nonnegative(),
    }),
  ),
  unknowns: z.array(z.string()),
  confidence_ppm: z.number().int().nonnegative().optional(),
  confidence: z.number().int().nonnegative().optional(),
});

const planFallbackSchema = z.object({
  incident_id: z.string(),
  can_create_plan: z.boolean(),
  reason_code: z.string(),
  requires_external_approval: z.literal(true),
  external_notifications_enabled: z.literal(false),
  plan_endpoint: z.string(),
  synthetic: z.boolean(),
});

const analysisSchema = z.union([
  z.object({
    disposition: z.enum(['created', 'replayed']),
    analysis: z.object({
      analysis_id: z.string(),
      brief: analystBriefSchema,
      proposal: z.object({
        recommended_template: z.literal('standard_payment_link'),
        rationale: z.string(),
        opportunity_gmv_subunits: z.number().int().nonnegative(),
        currency: z.string().length(3),
        expected_benefit: z.literal('not_estimated_without_outcome_evidence'),
        requires_external_approval: z.literal(true),
        executable: z.literal(false),
        external_notifications_enabled: z.literal(false),
        stop_conditions: z.array(z.string()),
      }),
      provenance: z.object({
        model: z.string(),
        latency_ms: z.number().int().nonnegative(),
        total_tokens: z.number().int().nonnegative(),
        estimated_cost_microusd: z.number().int().nonnegative().nullable(),
      }),
      model_status: z.literal('succeeded'),
      fallback_used: z.literal(false),
      synthetic: z.boolean(),
    }),
    plan_fallback: planFallbackSchema,
  }),
  z.object({
    disposition: z.enum(['created', 'replayed']),
    brief: analystBriefSchema,
    plan_fallback: planFallbackSchema,
    model_status: z.enum([
      'unavailable',
      'timeout',
      'refused',
      'invalid_response',
      'provider_error',
    ]),
    fallback_used: z.literal(true),
    fallback_reason_code: z.string(),
  }),
]);

const ruleResultSchema = z.object({
  rule: z.string(),
  outcome: z.enum(['pass', 'deny']),
  reason_code: z.string(),
});

const previewSchema = z.object({
  disposition: z.enum(['created', 'replayed', 'retrieved']),
  preview: z.object({
    plan: z.object({
      plan_id: z.string(),
      incident_id: z.string(),
      mode: z.string(),
      template: z.literal('standard_payment_link'),
      policy_version: z.string(),
      created_at: z.string(),
      stopping_rules: z.object({
        maximum_actions: z.number().int().positive(),
        maximum_attempts_per_payment: z.number().int().positive(),
        cooldown_seconds: z.number().int().nonnegative(),
        expires_at: z.string(),
        stop_after_recovery: z.literal(true),
        merchant_kill_switch_enforced: z.literal(true),
      }),
      requires_external_approval: z.literal(true),
      synthetic: z.boolean(),
    }),
    payment_id: z.string(),
    amount_subunits: z.number().int().positive(),
    currency: z.string().length(3),
    execution_target: z.enum(['deterministic_fake', 'razorpay_test_mode']),
    provider_reference_id: z.string(),
    effect: z.string(),
    external_notifications_enabled: z.literal(false),
    preview_policy_allowed: z.boolean(),
    policy_result: z.object({
      policy_result_id: z.string(),
      decision: z.enum(['allow', 'deny']),
      rule_results: z.array(ruleResultSchema),
    }),
    persisted_at: z.string(),
    synthetic: z.boolean(),
  }),
});

const approvalSchema = z.object({
  disposition: z.enum(['created', 'replayed']),
  approval: z.object({
    approval_id: z.string(),
    decision: z.enum(['approve', 'reject']),
    status: z.string(),
    decided_at: z.string(),
    expires_at: z.string().nullable(),
    synthetic: z.boolean(),
  }),
  approval_token: z.string().nullable(),
  token_delivery: z.string(),
});

const transitionSchema = z.object({
  prior_state: z.string().nullable(),
  new_state: z.string(),
  occurred_at: z.string(),
  actor: z.string(),
  reason_code: z.string(),
});

const receiptSchema = z.object({
  action_id: z.string(),
  plan_id: z.string(),
  incident_id: z.string(),
  payment_id: z.string(),
  state: z.string(),
  execution_target: z.enum(['deterministic_fake', 'razorpay_test_mode']),
  execution_side_effect: z.string(),
  external_notifications_enabled: z.literal(false),
  provider_action_id: z.string().nullable(),
  transitions: z.array(transitionSchema),
  error: z
    .object({
      category: z.string(),
      reason_code: z.string(),
      retry_permitted: z.boolean(),
      reconciliation_required: z.boolean(),
    })
    .nullable(),
  synthetic: z.boolean(),
});

const providerReceiptSchema = z.object({
  provider_action_id: z.string(),
  status: z.string(),
  short_url: z.url().nullable(),
  verified_at: z.string(),
  verification_source: z.string(),
});

const executionSchema = z.object({
  disposition: z.enum(['created', 'replayed', 'blocked']),
  receipt: receiptSchema.nullable(),
  provider_receipt: providerReceiptSchema.nullable(),
  synthetic: z.boolean(),
});

const reconciliationSchema = z.object({
  disposition: z.enum(['created', 'replayed']),
  receipt: receiptSchema,
  provider_receipt: providerReceiptSchema.nullable(),
});

const auditSchema = z.object({
  receipt: receiptSchema,
  audit: z.object({
    complete: z.boolean(),
    required_facts: z.array(z.string()),
    missing_facts: z.array(z.string()),
    transition_count: z.number().int().positive(),
    terminal_state: z.string(),
    synthetic: z.boolean(),
  }),
});

const experimentSchema = z.object({
  report_id: z.string(),
  experiment_id: z.string(),
  generated_at: z.string(),
  source_rows_scanned: z.number().int().positive(),
  eligible_count: z.number().int().positive(),
  treatment: z.object({
    eligible_count: z.number().int().positive(),
    recovered_count: z.number().int().nonnegative(),
    recovery_rate_ppm: z.number().int().nonnegative(),
    recovered_gmv_subunits: z.number().int().nonnegative(),
    action_count: z.number().int().nonnegative(),
  }),
  control: z.object({
    eligible_count: z.number().int().positive(),
    recovered_count: z.number().int().nonnegative(),
    recovery_rate_ppm: z.number().int().nonnegative(),
    recovered_gmv_subunits: z.number().int().nonnegative(),
  }),
  value: z.object({
    currency: z.string().length(3),
    gross_treatment_recovered_gmv_subunits: z.number().int().nonnegative(),
    observed_control_recovered_gmv_subunits: z.number().int().nonnegative(),
    estimated_natural_recovery_in_treatment_subunits: z.number().int().nonnegative(),
    incremental_recovered_gmv_subunits: z.number().int(),
    action_cost_subunits: z.number().int().nonnegative(),
    false_intervention_cost_subunits: z.number().int().nonnegative(),
    net_recovered_value_subunits: z.number().int(),
    absolute_recovery_rate_uplift_bps: z.number().int(),
  }),
  uncertainty: z.object({
    confidence_level_ppm: z.number().int(),
    incremental_gmv_lower_subunits: z.number().int(),
    incremental_gmv_point_subunits: z.number().int(),
    incremental_gmv_upper_subunits: z.number().int(),
    incremental_gmv_interval_includes_zero: z.boolean(),
    recovery_rate_uplift_lower_bps: z.number().int(),
    recovery_rate_uplift_point_bps: z.number().int(),
    recovery_rate_uplift_upper_bps: z.number().int(),
    recovery_rate_interval_includes_zero: z.boolean(),
    replicates: z.number().int().positive(),
  }),
  conclusion: z.string(),
  gross_recovery_is_not_incremental: z.literal(true),
  metric_scope: z.literal('synthetic_batch_not_live_merchant_performance'),
  synthetic: z.literal(true),
});

const demoRunSchema = z.object({
  synthetic: z.literal(true),
  replay: z.object({
    selected_deliveries: z.number().int().nonnegative(),
    accepted: z.number().int().nonnegative(),
    duplicates: z.number().int().nonnegative(),
    rejected_signatures: z.number().int().nonnegative(),
    expectation_mismatches: z.number().int().nonnegative(),
  }),
  projected: z.number().int().nonnegative(),
  retried: z.number().int().nonnegative(),
  dead_lettered: z.number().int().nonnegative(),
  detector_run_id: z.string().nullable(),
  detector_reused: z.boolean(),
  source_events: z.number().int().nonnegative(),
  attempts: z.number().int().nonnegative(),
  aggregates: z.number().int().nonnegative(),
  incidents: z.number().int().nonnegative(),
  active_incidents: z.number().int().nonnegative(),
  at_risk_gmv_subunits: z.number().int().nonnegative(),
});

export type Overview = z.infer<typeof overviewSchema>;
export type IncidentList = z.infer<typeof incidentListSchema>;
export type IncidentDetail = z.infer<typeof incidentDetailSchema>;
export type RecoveryCandidateList = z.infer<typeof candidateListSchema>;
export type IncidentAnalysis = z.infer<typeof analysisSchema>;
export type RecoveryPreview = z.infer<typeof previewSchema>;
export type ApprovalDecision = z.infer<typeof approvalSchema>;
export type RecoveryExecution = z.infer<typeof executionSchema>;
export type RecoveryAudit = z.infer<typeof auditSchema>;
export type ExperimentReport = z.infer<typeof experimentSchema>;
export type DemoRun = z.infer<typeof demoRunSchema>;

export class RetryRailApiError extends Error {
  readonly status: number;
  readonly reasonCode: string;

  constructor(status: number, reasonCode: string) {
    super(reasonCode);
    this.name = 'RetryRailApiError';
    this.status = status;
    this.reasonCode = reasonCode;
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST';
  authorization?: string;
  approvalToken?: string;
  replayToken?: string;
  body?: unknown;
  signal?: AbortSignal | undefined;
}

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (options.authorization !== undefined) {
    headers['X-RetryRail-Merchant-Authorization'] = options.authorization;
  }
  if (options.approvalToken !== undefined) {
    headers['X-RetryRail-Approval-Token'] = options.approvalToken;
  }
  if (options.replayToken !== undefined) {
    headers['X-RetryRail-Replay-Token'] = options.replayToken;
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? 'GET',
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (!response.ok) {
    let reasonCode = `HTTP_${String(response.status)}`;
    try {
      const error = z
        .object({ detail: z.object({ reason_code: z.string() }) })
        .parse(await response.json());
      reasonCode = error.detail.reason_code;
    } catch {
      // Keep the bounded status-derived reason when the server response is malformed.
    }
    throw new RetryRailApiError(response.status, reasonCode);
  }
  return schema.parse(await response.json());
}

export const retryRailApi = {
  overview: (signal?: AbortSignal) =>
    request('/api/v1/overview', overviewSchema, { signal }),
  incidents: (signal?: AbortSignal) =>
    request('/api/v1/incidents?limit=50', incidentListSchema, { signal }),
  incident: (incidentId: string, signal?: AbortSignal) =>
    request(`/api/v1/incidents/${encodeURIComponent(incidentId)}`, incidentDetailSchema, {
      signal,
    }),
  candidates: (incidentId: string, authorization: string, signal?: AbortSignal) =>
    request(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/recovery-candidates`,
      candidateListSchema,
      { authorization, signal },
    ),
  analyze: (incidentId: string, authorization: string) =>
    request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/analyze`, analysisSchema, {
      method: 'POST',
      authorization,
    }),
  createPreview: (
    incidentId: string,
    paymentId: string,
    authorization: string,
    idempotencyKey: string,
  ) =>
    request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/plans`, previewSchema, {
      method: 'POST',
      authorization,
      body: { payment_id: paymentId, idempotency_key: idempotencyKey },
    }),
  decide: (
    planId: string,
    decision: 'approve' | 'reject',
    authorization: string,
    idempotencyKey: string,
  ) =>
    request(`/api/v1/plans/${encodeURIComponent(planId)}/${decision}`, approvalSchema, {
      method: 'POST',
      authorization,
      body: { idempotency_key: idempotencyKey },
    }),
  execute: (
    planId: string,
    authorization: string,
    approvalToken: string,
    idempotencyKey: string,
  ) =>
    request(`/api/v1/plans/${encodeURIComponent(planId)}/execute`, executionSchema, {
      method: 'POST',
      authorization,
      approvalToken,
      body: { idempotency_key: idempotencyKey },
    }),
  reconcile: (actionId: string, authorization: string, idempotencyKey: string) =>
    request(`/api/v1/actions/${encodeURIComponent(actionId)}/reconcile`, reconciliationSchema, {
      method: 'POST',
      authorization,
      body: { idempotency_key: idempotencyKey },
    }),
  audit: (actionId: string, authorization: string, signal?: AbortSignal) =>
    request(`/api/v1/actions/${encodeURIComponent(actionId)}`, auditSchema, {
      authorization,
      signal,
    }),
  experiment: (authorization: string, signal?: AbortSignal) =>
    request('/api/v1/experiments/recovery_experiment_v1', experimentSchema, {
      authorization,
      signal,
    }),
  runDemo: (replayToken: string) =>
    request('/v1/demo/run', demoRunSchema, {
      method: 'POST',
      replayToken,
      body: { mode: 'tuning' },
    }),
};

export function operationKey(prefix: string): string {
  const random = globalThis.crypto.randomUUID().replaceAll('-', '').slice(0, 16);
  return `${prefix}_${Date.now().toString(36)}_${random}`;
}
