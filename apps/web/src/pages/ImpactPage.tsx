import { useQuery } from '@tanstack/react-query';

import { retryRailApi, RetryRailApiError } from '../api/retryrail';
import { ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusChip } from '../components/UI';
import { formatBasisPoints, formatDateTime, formatMoney, formatPercentPpm, humanize } from '../lib/format';
import { useMerchantSession } from '../session/useMerchantSession';

export function ImpactPage(): React.JSX.Element {
  const session = useMerchantSession();
  const report = useQuery({
    queryKey: ['experiment-impact', session.isUnlocked],
    queryFn: ({ signal }) => retryRailApi.experiment(session.authorization, signal),
    enabled: session.isUnlocked,
    retry: false,
  });

  if (!session.isUnlocked) {
    return (
      <>
        <PageHeader eyebrow="Measurement" title="Recovery impact" description="Incremental value from a frozen treatment/control study with same-payment attribution." />
        <Panel eyebrow="Session locked" title="Unlock the immutable report">
          <div className="locked-state"><span aria-hidden="true">⌁</span><div><p>The synthetic batch report is merchant-authenticated. Unlocking does not grant provider credentials.</p><button className="button button--primary" onClick={session.openDialog} type="button">Unlock local session</button></div></div>
        </Panel>
      </>
    );
  }
  if (report.isPending) return <LoadingState label="Validating frozen experiment report" />;
  if (report.isError) {
    const message = report.error instanceof RetryRailApiError
      ? humanize(report.error.reasonCode)
      : 'The immutable report could not be validated.';
    return <ErrorState title="Experiment report unavailable" message={message} action={<button className="button button--secondary" onClick={() => void report.refetch()} type="button">Retry</button>} />;
  }

  const data = report.data;
  const value = data.value;
  const uncertainty = data.uncertainty;
  return (
    <>
      <PageHeader
        eyebrow="Measurement"
        title="Recovery impact"
        description={`Frozen treatment/control study · ${data.eligible_count.toString()} eligible payments · ${formatDateTime(data.generated_at)}`}
        actions={<StatusChip value={data.conclusion} tone={uncertainty.incremental_gmv_interval_includes_zero ? 'warn' : 'good'} />}
      />

      <div className="impact-scope-banner">
        <strong>Synthetic benchmark</strong>
        <span>Evaluation evidence, not live merchant performance. Gross recovery is not incremental value.</span>
      </div>

      <div className="metric-grid impact-metrics">
        <MetricCard label="Incremental recovered GMV" value={formatMoney(value.incremental_recovered_gmv_subunits, value.currency)} detail="Treatment gross minus estimated natural recovery" tone="good" />
        <MetricCard label="Net recovered value" value={formatMoney(value.net_recovered_value_subunits, value.currency)} detail="After action + false-intervention costs" tone="info" />
        <MetricCard label="Recovery-rate uplift" value={formatBasisPoints(value.absolute_recovery_rate_uplift_bps)} detail="Absolute treatment minus control" />
        <MetricCard label="Eligible batch" value={data.eligible_count.toString()} detail={`${data.source_rows_scanned.toString()} versioned source rows scanned`} />
      </div>

      <div className="impact-layout">
        <Panel className="value-waterfall-panel" eyebrow="Attribution" title="Value bridge">
          <div className="value-waterfall">
            <div className="waterfall-row waterfall-row--gross"><span>Gross treatment recovered GMV</span><strong>{formatMoney(value.gross_treatment_recovered_gmv_subunits, value.currency)}</strong></div>
            <div className="waterfall-row waterfall-row--subtract"><span>Estimated natural recovery in treatment</span><strong>− {formatMoney(value.estimated_natural_recovery_in_treatment_subunits, value.currency)}</strong></div>
            <div className="waterfall-row waterfall-row--result"><span>Incremental recovered GMV</span><strong>{formatMoney(value.incremental_recovered_gmv_subunits, value.currency)}</strong></div>
            <div className="waterfall-row waterfall-row--subtract"><span>Action cost</span><strong>− {formatMoney(value.action_cost_subunits, value.currency)}</strong></div>
            <div className="waterfall-row waterfall-row--subtract"><span>False-intervention cost</span><strong>− {formatMoney(value.false_intervention_cost_subunits, value.currency)}</strong></div>
            <div className="waterfall-row waterfall-row--net"><span>Net recovered value</span><strong>{formatMoney(value.net_recovered_value_subunits, value.currency)}</strong></div>
          </div>
        </Panel>

        <Panel eyebrow="Uncertainty" title="95% bootstrap interval">
          <div className="interval-card">
            <div className="interval-scale" aria-label="Incremental GMV confidence interval">
              <span className="interval-line" /><span className="interval-point" />
            </div>
            <div className="interval-values"><span>{formatMoney(uncertainty.incremental_gmv_lower_subunits, value.currency)}</span><strong>{formatMoney(uncertainty.incremental_gmv_point_subunits, value.currency)}</strong><span>{formatMoney(uncertainty.incremental_gmv_upper_subunits, value.currency)}</span></div>
            <p>{uncertainty.incremental_gmv_interval_includes_zero ? 'The interval includes zero; the result is inconclusive.' : 'The interval excludes zero in this frozen synthetic batch.'}</p>
            <small>{uncertainty.replicates.toLocaleString('en-IN')} deterministic bootstrap replicates · {formatPercentPpm(uncertainty.confidence_level_ppm)} confidence</small>
          </div>
        </Panel>
      </div>

      <Panel eyebrow="Experiment arms" title="Treatment and holdout">
        <div className="arm-comparison">
          <article><div><StatusChip value="treatment" tone="info" /><strong>{formatPercentPpm(data.treatment.recovery_rate_ppm)}</strong></div><dl><div><dt>Eligible</dt><dd>{data.treatment.eligible_count.toString()}</dd></div><div><dt>Recovered</dt><dd>{data.treatment.recovered_count.toString()}</dd></div><div><dt>Gross GMV</dt><dd>{formatMoney(data.treatment.recovered_gmv_subunits, value.currency)}</dd></div><div><dt>Actions</dt><dd>{data.treatment.action_count.toString()}</dd></div></dl></article>
          <div className="versus">vs</div>
          <article><div><StatusChip value="control_holdout" tone="neutral" /><strong>{formatPercentPpm(data.control.recovery_rate_ppm)}</strong></div><dl><div><dt>Eligible</dt><dd>{data.control.eligible_count.toString()}</dd></div><div><dt>Naturally recovered</dt><dd>{data.control.recovered_count.toString()}</dd></div><div><dt>Observed GMV</dt><dd>{formatMoney(data.control.recovered_gmv_subunits, value.currency)}</dd></div><div><dt>Actions</dt><dd>0</dd></div></dl></article>
        </div>
      </Panel>
    </>
  );
}
