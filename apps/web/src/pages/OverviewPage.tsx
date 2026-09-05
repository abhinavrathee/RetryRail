import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { retryRailApi } from '../api/retryrail';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricCard,
  PageHeader,
  Panel,
  StatusChip,
} from '../components/UI';
import { formatBasisPoints, formatDateTime, formatMoney, formatPercentPpm, humanize } from '../lib/format';

export function OverviewPage(): React.JSX.Element {
  const overview = useQuery({
    queryKey: ['overview'],
    queryFn: ({ signal }) => retryRailApi.overview(signal),
    refetchInterval: 30_000,
  });
  const incidents = useQuery({
    queryKey: ['incidents'],
    queryFn: ({ signal }) => retryRailApi.incidents(signal),
    refetchInterval: 30_000,
  });

  if (overview.isPending || incidents.isPending) {
    return <LoadingState label="Loading payment reliability overview" />;
  }
  if (overview.isError || incidents.isError) {
    return (
      <ErrorState
        title="Overview evidence is unavailable"
        message="Start the local API and database, then retry. No cached metric is presented as current."
        action={<button className="button button--secondary" onClick={() => void Promise.all([overview.refetch(), incidents.refetch()])} type="button">Retry</button>}
      />
    );
  }

  const data = overview.data;
  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Revenue reliability"
        description="Merchant-local payment health, evidence and controlled recovery in one view."
        actions={(
          <div className="as-of">
            <span>Evidence as of</span>
            <strong>{formatDateTime(data.data_as_of)}</strong>
          </div>
        )}
      />

      <div className="metric-grid">
        <MetricCard
          label="GMV at risk"
          value={formatMoney(data.at_risk_gmv_subunits, data.currency)}
          detail={`${data.active_incidents.toString()} open deterministic incident${data.active_incidents === 1 ? '' : 's'}`}
          tone={data.at_risk_gmv_subunits > 0 ? 'danger' : 'good'}
        />
        <MetricCard
          label="Eligible for review"
          value={data.action_eligible_incidents.toString()}
          detail="Still requires authoritative preview + approval"
          tone="info"
        />
        <MetricCard
          label="Detector"
          value={humanize(data.detector_release_status)}
          detail={data.detector_version}
          tone={data.detector_release_failed_targets.length === 0 ? 'good' : 'danger'}
        />
        <MetricCard
          label="Incidents"
          value={data.total_incidents.toString()}
          detail="Open and resolved, merchant scoped"
        />
      </div>

      <div className="overview-layout">
        <Panel
          className="incident-panel"
          eyebrow="Current"
          title="Open incidents"
          actions={<StatusChip value={data.active_incidents > 0 ? 'attention_required' : 'healthy'} tone={data.active_incidents > 0 ? 'danger' : 'good'} />}
        >
          {incidents.data.items.length === 0 ? (
            <EmptyState
              title="No degradation incidents"
              message="The detector has not produced a qualifying merchant-local signal. This is a real empty state, not a simulated success metric."
            />
          ) : (
            <div className="incident-list">
              {incidents.data.items.map((item) => {
                const incident = item.incident;
                return (
                  <article className="incident-row" key={incident.incident_id}>
                    <div className="incident-severity" aria-hidden="true" />
                    <div className="incident-main">
                      <div className="incident-title-row">
                        <Link to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>
                          {incident.affected_cohort.map((part) => `${part.dimension}: ${part.value}`).join(' · ')}
                        </Link>
                        <StatusChip value={incident.status} tone={incident.status === 'open' ? 'danger' : 'good'} />
                      </div>
                      <p>
                        {formatBasisPoints(incident.evidence.observed_success_rate_drop_bps)} success-rate drop · {incident.evidence.current_attempts.toString()} current attempts · {incident.evidence.excess_failures.toString()} excess failures
                      </p>
                      <div className="incident-meta">
                        <span>Confidence {formatPercentPpm(incident.evidence.confidence_ppm)}</span>
                        <span>Opened {formatDateTime(incident.opened_at)}</span>
                        <span>{item.action_eligible ? 'Eligible for policy preview' : 'Analysis only'}</span>
                      </div>
                    </div>
                    <div className="incident-value">
                      <span>At risk</span>
                      <strong>{formatMoney(incident.gmv_at_risk_subunits, incident.currency)}</strong>
                      <Link className="text-link" to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>Inspect evidence →</Link>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </Panel>

        <aside className="confidence-rail">
          <Panel eyebrow="Controls" title="Decision path">
            <ol className="control-steps">
              <li><span>1</span><div><strong>Signal</strong><p>Versioned statistics open the incident.</p></div></li>
              <li><span>2</span><div><strong>Evidence</strong><p>Facts, hypotheses and unknowns stay separate.</p></div></li>
              <li><span>3</span><div><strong>Control</strong><p>Policy and merchant approval gate execution.</p></div></li>
              <li><span>4</span><div><strong>Measurement</strong><p>A holdout isolates incremental value.</p></div></li>
            </ol>
          </Panel>
        </aside>
      </div>
    </>
  );
}
