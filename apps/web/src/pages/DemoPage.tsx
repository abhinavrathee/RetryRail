import { useMutation, useQueryClient } from '@tanstack/react-query';

import { retryRailApi, RetryRailApiError } from '../api/retryrail';
import { ErrorState, PageHeader, Panel, StatusChip } from '../components/UI';
import { formatMoney, humanize } from '../lib/format';
import { useMerchantSession } from '../session/useMerchantSession';

export function DemoPage(): React.JSX.Element {
  const session = useMerchantSession();
  const queryClient = useQueryClient();
  const run = useMutation({
    mutationFn: () => retryRailApi.runDemo(session.replayToken),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['overview'] });
      await queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });
  const message = run.error instanceof RetryRailApiError
    ? humanize(run.error.reasonCode)
    : 'The bounded local demo did not complete.';

  return (
    <>
      <PageHeader
        eyebrow="Isolated demo controls"
        title="Replay synthetic evidence through the real pipeline"
        description="This local-only control replays a fixed synthetic tuning partition, drains the transactional outbox, and runs the deterministic detector. It is disabled in production."
        actions={<StatusChip value="synthetic_only" tone="warn" />}
      />
      <div className="demo-layout">
        <Panel eyebrow="Bounded operation" title="Detection scenario">
          <ol className="demo-steps">
            <li><span>1</span><div><strong>Replay signed fixtures</strong><p>Duplicate, out-of-order and invalid-signature behavior stays intact.</p></div></li>
            <li><span>2</span><div><strong>Project through outbox</strong><p>Finite lease-based batches update PII-free payment state.</p></div></li>
            <li><span>3</span><div><strong>Run deterministic detector</strong><p>The same activated detector—not an LLM—opens incidents.</p></div></li>
            <li><span>4</span><div><strong>Review in the UI</strong><p>Inspect evidence, then use policy and approval controls separately.</p></div></li>
          </ol>
          <div className="demo-action">
            <div><strong>No real customer or payment data</strong><p>The replay token and merchant secret remain in page memory only.</p></div>
            <button
              className="button button--primary"
              disabled={run.isPending}
              onClick={() => {
                if (session.replayToken.length === 0) {
                  session.openDialog();
                  return;
                }
                run.mutate();
              }}
              type="button"
            >
              {run.isPending ? 'Running replay + detection…' : 'Run synthetic detection demo'}
            </button>
          </div>
          {run.isError ? <ErrorState title="Demo stopped safely" message={message} /> : null}
        </Panel>

        <Panel eyebrow="Operational guardrails" title="What this control cannot do">
          <ul className="guardrail-list">
            <li><span>×</span>It cannot run in production.</li>
            <li><span>×</span>It cannot access Razorpay or OpenAI credentials.</li>
            <li><span>×</span>It cannot approve or execute recovery.</li>
            <li><span>×</span>It cannot alter held-out evaluation truth.</li>
          </ul>
        </Panel>
      </div>

      {run.data === undefined ? null : (
        <Panel className="demo-result" eyebrow="Run receipt" title="Synthetic pipeline completed" actions={<StatusChip value={run.data.replay.expectation_mismatches === 0 ? 'expectations_matched' : 'mismatch_detected'} tone={run.data.replay.expectation_mismatches === 0 ? 'good' : 'danger'} />}>
          <div className="demo-result-grid">
            <div><span>Deliveries selected</span><strong>{run.data.replay.selected_deliveries.toString()}</strong></div>
            <div><span>Accepted</span><strong>{run.data.replay.accepted.toString()}</strong></div>
            <div><span>Duplicates</span><strong>{run.data.replay.duplicates.toString()}</strong></div>
            <div><span>Rejected signatures</span><strong>{run.data.replay.rejected_signatures.toString()}</strong></div>
            <div><span>Projected</span><strong>{run.data.projected.toString()}</strong></div>
            <div><span>Detector attempts</span><strong>{run.data.attempts.toString()}</strong></div>
            <div><span>Active incidents</span><strong>{run.data.active_incidents.toString()}</strong></div>
            <div><span>GMV at risk</span><strong>{formatMoney(run.data.at_risk_gmv_subunits, 'INR')}</strong></div>
          </div>
          <a className="button button--secondary" href="/">Open refreshed overview</a>
        </Panel>
      )}
    </>
  );
}

export function NotFoundPage(): React.JSX.Element {
  return (
    <Panel eyebrow="404" title="This control-room view does not exist">
      <p>Return to the reliability overview to inspect current evidence.</p>
      <a className="button button--primary" href="/">Return to overview</a>
    </Panel>
  );
}
