import { useMutation, useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import {
  operationKey,
  retryRailApi,
  RetryRailApiError,
  type RecoveryExecution,
} from '../api/retryrail';
import {
  DefinitionList,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  StatusChip,
} from '../components/UI';
import { formatDateTime, formatMoney, humanize } from '../lib/format';
import { useMerchantSession } from '../session/useMerchantSession';

function errorReason(error: unknown): string {
  return error instanceof RetryRailApiError ? humanize(error.reasonCode) : 'Unexpected local error';
}

export function RecoveryPage(): React.JSX.Element {
  const { incidentId = '' } = useParams();
  const session = useMerchantSession();
  const [selectedPaymentId, setSelectedPaymentId] = useState('');
  const [reviewed, setReviewed] = useState(false);
  const [approvalToken, setApprovalToken] = useState('');
  const [approvalTokenEpoch, setApprovalTokenEpoch] = useState<number | null>(null);
  const [decisionState, setDecisionState] = useState<'none' | 'approved' | 'rejected'>('none');
  const [decisionPending, setDecisionPending] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [execution, setExecution] = useState<RecoveryExecution | null>(null);
  const [executionPending, setExecutionPending] = useState(false);
  const [executionError, setExecutionError] = useState<string | null>(null);

  const approvalTokenIsCurrent = approvalToken.length > 0
    && approvalTokenEpoch === session.authorityEpoch
    && session.isUnlocked;

  const candidates = useQuery({
    queryKey: ['recovery-candidates', incidentId, session.isUnlocked],
    queryFn: ({ signal }) => retryRailApi.candidates(incidentId, session.authorization, signal),
    enabled: session.isUnlocked && incidentId.length > 0,
    retry: false,
  });
  const selectedCandidate = useMemo(
    () => candidates.data?.items.find((item) => item.payment_id === selectedPaymentId)
      ?? candidates.data?.items[0],
    [candidates.data, selectedPaymentId],
  );
  const preview = useMutation({
    mutationFn: () => {
      if (selectedCandidate === undefined) throw new Error('candidate required');
      return retryRailApi.createPreview(
        incidentId,
        selectedCandidate.payment_id,
        session.authorization,
        operationKey('preview'),
      );
    },
    onSuccess: () => {
      setReviewed(false);
      setApprovalToken('');
      setApprovalTokenEpoch(null);
      setDecisionState('none');
      setExecution(null);
      setDecisionError(null);
      setExecutionError(null);
    },
  });

  const receipt = execution?.receipt ?? null;
  const actionId = receipt?.action_id ?? '';
  const audit = useQuery({
    queryKey: ['action-audit', actionId],
    queryFn: ({ signal }) => retryRailApi.audit(actionId, session.authorization, signal),
    enabled: actionId.length > 0 && session.isUnlocked,
    retry: false,
  });

  if (!session.isUnlocked) {
    return (
      <>
        <PageHeader
          eyebrow="Recovery control"
          title="Review before any Test Mode mutation"
          description="The merchant authorization secret is required to reveal candidates, preview policy, approve, or execute."
        />
        <Panel eyebrow="Session locked" title="Unlock merchant actions">
          <div className="locked-state">
            <span aria-hidden="true">⌁</span>
            <div><p>The secret stays only in this page&apos;s memory. Razorpay and OpenAI credentials belong on the server and must never be entered here.</p><button className="button button--primary" onClick={session.openDialog} type="button">Unlock local session</button></div>
          </div>
        </Panel>
      </>
    );
  }
  if (candidates.isPending) return <LoadingState label="Finding cited failed payments" />;
  if (candidates.isError) {
    return <ErrorState title="Recovery candidates are unavailable" message={errorReason(candidates.error)} action={<button className="button button--secondary" onClick={() => void candidates.refetch()} type="button">Retry</button>} />;
  }

  const previewData = preview.data?.preview;
  const providerLabel = previewData?.execution_target === 'razorpay_test_mode'
    ? 'Razorpay Test Mode'
    : 'Deterministic fake provider';

  async function decide(decision: 'approve' | 'reject'): Promise<void> {
    if (previewData === undefined) return;
    setDecisionPending(true);
    setDecisionError(null);
    try {
      const result = await retryRailApi.decide(
        previewData.plan.plan_id,
        decision,
        session.authorization,
        operationKey(decision),
      );
      if (decision === 'approve') {
        if (result.approval_token === null) {
          setDecisionError('Approval replayed without the one-time execution token. Create a fresh preview to continue.');
          return;
        }
        setApprovalToken(result.approval_token);
        setApprovalTokenEpoch(session.authorityEpoch);
        setDecisionState('approved');
      } else {
        setApprovalToken('');
        setApprovalTokenEpoch(null);
        setDecisionState('rejected');
      }
    } catch (error) {
      setDecisionError(errorReason(error));
    } finally {
      setDecisionPending(false);
    }
  }

  async function execute(): Promise<void> {
    if (previewData === undefined || !approvalTokenIsCurrent) return;
    setExecutionPending(true);
    setExecutionError(null);
    try {
      const result = await retryRailApi.execute(
        previewData.plan.plan_id,
        session.authorization,
        approvalToken,
        operationKey('execute'),
      );
      setApprovalToken('');
      setApprovalTokenEpoch(null);
      setExecution(result);
    } catch (error) {
      setApprovalToken('');
      setApprovalTokenEpoch(null);
      setExecutionError(errorReason(error));
    } finally {
      setExecutionPending(false);
    }
  }

  async function reconcile(): Promise<void> {
    if (receipt === null) return;
    setExecutionPending(true);
    setExecutionError(null);
    try {
      const result = await retryRailApi.reconcile(
        receipt.action_id,
        session.authorization,
        operationKey('reconcile'),
      );
      setExecution({
        disposition: result.disposition,
        receipt: result.receipt,
        provider_receipt: result.provider_receipt,
        synthetic: result.receipt.synthetic,
      });
      await audit.refetch();
    } catch (error) {
      setExecutionError(errorReason(error));
    } finally {
      setExecutionPending(false);
    }
  }

  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/">Overview</Link><span aria-hidden="true">/</span>
        <Link to={`/incidents/${encodeURIComponent(incidentId)}`}>Incident</Link><span aria-hidden="true">/</span><span>Recovery</span>
      </nav>
      <PageHeader
        eyebrow="Recovery control"
        title="Preview the exact effect before approval"
        description="The model has no role here. Server-owned evidence and 13 deterministic policy rules decide whether the plan may proceed."
        actions={<StatusChip value={candidates.data.action_eligible ? 'review_first' : 'analysis_only'} tone={candidates.data.action_eligible ? 'info' : 'warn'} />}
      />

      {candidates.data.items.length === 0 ? (
        <EmptyState title="No cited failed payment is available" message="The incident remains visible, but there is no PII-free failed payment candidate bound to its cited evidence." />
      ) : (
        <div className="recovery-layout">
          <Panel eyebrow="Step 1 of 4" title="Select cited payment">
            <div className="candidate-list" role="radiogroup" aria-label="Recovery candidates">
              {candidates.data.items.map((candidate) => {
                const selected = candidate.payment_id === selectedCandidate?.payment_id;
                return (
                  <label className={`candidate-card${selected ? ' candidate-card--selected' : ''}`} key={candidate.payment_id}>
                    <input checked={selected} name="payment-candidate" onChange={() => { setSelectedPaymentId(candidate.payment_id); }} type="radio" />
                    <span><strong>{formatMoney(candidate.amount_subunits, candidate.currency)}</strong><small>{candidate.method} · {candidate.issuer ?? 'issuer unknown'}</small></span>
                    <code>{candidate.payment_id}</code>
                  </label>
                );
              })}
            </div>
            <div className="panel-footer">
              <p>Candidate identity comes from a verified event citation. Eligibility is recomputed at preview.</p>
              <button className="button button--primary" disabled={preview.isPending || selectedCandidate === undefined} onClick={() => { preview.mutate(); }} type="button">{preview.isPending ? 'Evaluating 13 rules…' : 'Create authoritative preview'}</button>
            </div>
            {preview.isError ? <ErrorState title="Preview failed closed" message={errorReason(preview.error)} /> : null}
          </Panel>

          {previewData === undefined ? (
            <Panel className="preview-placeholder" eyebrow="Steps 2–4" title="Policy, approval and execution">
              <div className="empty-preview"><span aria-hidden="true">13</span><p>Select a candidate and create a preview to see every deterministic rule, exact amount, external effect, expiry and stopping control.</p></div>
            </Panel>
          ) : (
            <Panel
              className="preview-panel"
              eyebrow="Step 2 of 4"
              title="Authoritative policy preview"
              actions={<StatusChip value={previewData.preview_policy_allowed ? 'policy_allowed' : 'policy_blocked'} tone={previewData.preview_policy_allowed ? 'good' : 'danger'} />}
            >
              <div className="preview-summary">
                <div><span>Exact amount</span><strong>{formatMoney(previewData.amount_subunits, previewData.currency)}</strong></div>
                <div><span>Effect</span><strong>{humanize(previewData.effect)}</strong></div>
                <div><span>Target</span><strong>{providerLabel}</strong></div>
                <div><span>Customer notifications</span><strong>Disabled</strong></div>
              </div>
              <DefinitionList items={[
                { term: 'Template', value: humanize(previewData.plan.template) },
                { term: 'Provider reference', value: <code>{previewData.provider_reference_id}</code> },
                { term: 'Plan expires', value: formatDateTime(previewData.plan.stopping_rules.expires_at) },
                { term: 'Attempt cap', value: `${previewData.plan.stopping_rules.maximum_attempts_per_payment.toString()} per payment` },
                { term: 'Cooldown', value: `${previewData.plan.stopping_rules.cooldown_seconds.toString()} seconds` },
                { term: 'Stop after recovery', value: 'Required' },
              ]} />

              <div className="policy-grid" aria-label="Deterministic policy results">
                {previewData.policy_result.rule_results.map((rule) => (
                  <div className={`policy-rule policy-rule--${rule.outcome}`} key={rule.rule}>
                    <span aria-hidden="true">{rule.outcome === 'pass' ? '✓' : '×'}</span>
                    <div><strong>{humanize(rule.rule)}</strong><small>{humanize(rule.reason_code)}</small></div>
                  </div>
                ))}
              </div>

              {!previewData.preview_policy_allowed ? (
                <div className="notice notice--danger"><strong>Policy blocked this plan</strong><span>No approval token can be issued and no provider call is possible.</span></div>
              ) : decisionState === 'none' ? (
                <div className="approval-box">
                  <div><p className="eyebrow">Step 3 of 4</p><h3>Merchant decision</h3><p>Approval is outside the model. Confirm the exact amount and effect above before issuing a one-time token.</p></div>
                  <label className="review-check"><input checked={reviewed} onChange={(event) => { setReviewed(event.target.checked); }} type="checkbox" />I reviewed the amount, Test Mode target, expiry and stopping controls.</label>
                  <div className="approval-actions">
                    <button className="button button--danger" disabled={decisionPending} onClick={() => void decide('reject')} type="button">Reject plan</button>
                    <button className="button button--primary" disabled={!reviewed || decisionPending} onClick={() => void decide('approve')} type="button">{decisionPending ? 'Recording decision…' : 'Approve once'}</button>
                  </div>
                </div>
              ) : decisionState === 'rejected' ? (
                <div className="notice notice--neutral"><strong>Plan rejected</strong><span>The decision is terminal. No token or provider action was created.</span></div>
              ) : receipt === null && approvalTokenIsCurrent ? (
                <div className="execute-box">
                  <div><p className="eyebrow">Step 4 of 4</p><h3>Approval recorded</h3><p>The one-time bearer is held only in component memory. Execution will re-run policy before any provider call.</p></div>
                  <button className="button button--primary" disabled={executionPending} onClick={() => void execute()} type="button">{executionPending ? 'Executing safely…' : `Execute in ${providerLabel}`}</button>
                </div>
              ) : receipt === null ? (
                <div className="notice notice--warn"><strong>Approval bearer cleared</strong><span>The memory-only token was cleared or invalidated. This approved plan cannot execute again in this browser session.</span></div>
              ) : null}

              {decisionError === null ? null : <ErrorState title="Decision could not continue" message={decisionError} />}
              {executionError === null ? null : <ErrorState title="Execution stopped safely" message={executionError} />}

              {receipt === null ? null : (
                <section className="action-result" aria-live="polite">
                  <div className="result-heading">
                    <div><p className="eyebrow">Durable action receipt</p><h3>{humanize(receipt.state)}</h3></div>
                    <StatusChip value={receipt.state} tone={receipt.state === 'succeeded' ? 'good' : receipt.state === 'reconciliation_required' ? 'warn' : 'danger'} />
                  </div>
                  {receipt.state === 'reconciliation_required' ? (
                    <div className="notice notice--warn"><strong>Outcome is ambiguous</strong><span>Creation will not be retried. Reconciliation performs lookup only with the stable provider reference.</span><button className="button button--secondary" disabled={executionPending} onClick={() => void reconcile()} type="button">Lookup and reconcile</button></div>
                  ) : null}
                  <ol className="audit-timeline">
                    {receipt.transitions.map((transition, index) => (
                      <li key={`${transition.occurred_at}-${transition.new_state}`}>
                        <span>{(index + 1).toString().padStart(2, '0')}</span>
                        <div><strong>{humanize(transition.new_state)}</strong><p>{humanize(transition.reason_code)} · {humanize(transition.actor)}</p><small>{formatDateTime(transition.occurred_at)}</small></div>
                      </li>
                    ))}
                  </ol>
                  {audit.isSuccess ? (
                    <div className={`audit-proof${audit.data.audit.complete ? ' audit-proof--complete' : ''}`}>
                      <span aria-hidden="true">{audit.data.audit.complete ? '✓' : '!'}</span>
                      <div><strong>{audit.data.audit.complete ? 'Audit chain complete' : 'Audit chain incomplete'}</strong><p>{audit.data.audit.required_facts.length.toString()} required facts · {audit.data.audit.missing_facts.length.toString()} missing</p></div>
                    </div>
                  ) : null}
                  {execution?.provider_receipt?.short_url === null || execution?.provider_receipt?.short_url === undefined ? null : (
                    <a className="button button--secondary" href={execution.provider_receipt.short_url} rel="noreferrer" target="_blank">Open Test Mode payment link ↗</a>
                  )}
                </section>
              )}
            </Panel>
          )}
        </div>
      )}
    </>
  );
}
