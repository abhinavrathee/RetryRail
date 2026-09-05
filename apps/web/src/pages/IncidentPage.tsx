import { useMutation, useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';

import { retryRailApi, type IncidentAnalysis } from '../api/retryrail';
import {
  DefinitionList,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  StatusChip,
} from '../components/UI';
import { formatBasisPoints, formatDateTime, formatMoney, formatPercentPpm } from '../lib/format';
import { useMerchantSession } from '../session/useMerchantSession';

function analysisBrief(analysis: IncidentAnalysis) {
  return 'analysis' in analysis ? analysis.analysis.brief : analysis.brief;
}

export function IncidentPage(): React.JSX.Element {
  const { incidentId = '' } = useParams();
  const session = useMerchantSession();
  const incident = useQuery({
    queryKey: ['incident', incidentId],
    queryFn: ({ signal }) => retryRailApi.incident(incidentId, signal),
    enabled: incidentId.length > 0,
  });
  const analysis = useMutation({
    mutationFn: () => retryRailApi.analyze(incidentId, session.authorization),
  });

  if (incident.isPending) return <LoadingState label="Loading incident evidence" />;
  if (incident.isError) {
    return (
      <ErrorState
        title="Incident evidence could not be loaded"
        message="The incident may not exist in this merchant scope, or the API is unavailable."
        action={<Link className="button button--secondary" to="/">Return to overview</Link>}
      />
    );
  }

  const summary = incident.data.summary;
  const detail = summary.incident;
  const brief = analysis.data === undefined ? undefined : analysisBrief(analysis.data);
  const fallbackUsed = analysis.data === undefined ? false : !('analysis' in analysis.data);
  return (
    <>
      <nav className="breadcrumb" aria-label="Breadcrumb">
        <Link to="/">Overview</Link><span aria-hidden="true">/</span><span>Incident</span>
      </nav>
      <PageHeader
        eyebrow="Incident evidence"
        title={detail.affected_cohort.map((part) => `${part.dimension}: ${part.value}`).join(' · ')}
        description={`Opened ${formatDateTime(detail.opened_at)} · Last observed ${formatDateTime(detail.last_observed_at)} · ${detail.detector_version}`}
        actions={(
          <div className="header-action-stack">
            <StatusChip value={detail.status} tone={detail.status === 'open' ? 'danger' : 'good'} />
            <span className="mono-id">{detail.incident_id}</span>
          </div>
        )}
      />

      <div className="evidence-metrics">
        <div><span>Observed success-rate drop</span><strong>{formatBasisPoints(detail.evidence.observed_success_rate_drop_bps)}</strong><small>percentage points</small></div>
        <div><span>Current sample</span><strong>{detail.evidence.current_attempts.toString()}</strong><small>minimum {detail.evidence.minimum_attempts.toString()} attempts</small></div>
        <div><span>Excess failures</span><strong>{detail.evidence.excess_failures.toString()}</strong><small>above baseline expectation</small></div>
        <div><span>GMV at risk</span><strong>{formatMoney(detail.gmv_at_risk_subunits, detail.currency)}</strong><small>observed exposure, not recovery</small></div>
      </div>

      <div className="incident-detail-grid">
        <Panel className="evidence-board" eyebrow="Diagnosis" title="Evidence classification">
          <div className="evidence-columns">
            <section className="evidence-column evidence-column--verified">
              <div className="evidence-column-heading"><StatusChip value="verified_observation" tone="good" /><span>{summary.diagnosis.verified_attributions.length.toString()}</span></div>
              {summary.diagnosis.verified_attributions.map((item) => (
                <article key={`${item.dimension}-${item.value}`}>
                  <strong>{item.dimension}: {item.value}</strong>
                  <p>{formatPercentPpm(item.contribution_ppm)} of measured excess failures, {formatPercentPpm(item.confidence_ppm)} confidence.</p>
                  <small>{item.evidence_event_ids.length.toString()} cited event ID{item.evidence_event_ids.length === 1 ? '' : 's'}</small>
                </article>
              ))}
            </section>
            <section className="evidence-column evidence-column--hypothesis">
              <div className="evidence-column-heading"><StatusChip value="inferred_hypothesis" tone="warn" /><span>{summary.diagnosis.hypotheses.length.toString()}</span></div>
              {summary.diagnosis.hypotheses.map((item) => (
                <article key={item.statement}>
                  <strong>Bounded interpretation</strong>
                  <p>{item.statement}</p>
                  <small>{formatPercentPpm(item.confidence_ppm)} confidence · merchant-local only</small>
                </article>
              ))}
            </section>
            <section className="evidence-column evidence-column--unknown">
              <div className="evidence-column-heading"><StatusChip value="unknown" tone="neutral" /><span>{summary.diagnosis.unknowns.length.toString()}</span></div>
              {summary.diagnosis.unknowns.map((item) => (
                <article key={item}><strong>Not independently verified</strong><p>{item}</p></article>
              ))}
            </section>
          </div>
        </Panel>

        <Panel eyebrow="Source integrity" title="Evidence receipt">
          <DefinitionList items={[
            { term: 'Detector configuration', value: <code>{summary.detector_config_sha256.slice(0, 16)}…</code> },
            { term: 'Baseline sample', value: `${detail.evidence.baseline_successes.toString()} / ${detail.evidence.baseline_attempts.toString()} successful` },
            { term: 'Current sample', value: `${detail.evidence.current_successes.toString()} / ${detail.evidence.current_attempts.toString()} successful` },
            { term: 'Evidence events', value: detail.evidence_event_ids.length.toString() },
            { term: 'Synthetic', value: detail.synthetic ? 'Yes — clearly labeled' : 'No' },
          ]} />
        </Panel>
      </div>

      <Panel
        className="analyst-panel"
        eyebrow="Bounded analyst"
        title="Grounded incident brief"
        actions={brief === undefined ? (
          <button
            className="button button--primary"
            disabled={analysis.isPending}
            onClick={() => {
              if (!session.isUnlocked) {
                session.openDialog();
                return;
              }
              analysis.mutate();
            }}
            type="button"
          >
            {analysis.isPending ? 'Analyzing…' : 'Generate grounded brief'}
          </button>
        ) : <StatusChip value={fallbackUsed ? 'rules_fallback' : 'structured_model'} tone={fallbackUsed ? 'warn' : 'info'} />}
      >
        {analysis.isError ? (
          <ErrorState title="Analysis failed safely" message="No model output was accepted and no recovery action was created. Retry or continue with the deterministic evidence above." />
        ) : brief === undefined ? (
          <div className="analyst-empty">
            <p>The analyst receives only a redacted aggregate snapshot. It can explain evidence and recommend the single allowlisted template, but it cannot approve or execute.</p>
            {!session.isUnlocked ? <button className="text-button" onClick={session.openDialog} type="button">Unlock the local merchant session first →</button> : null}
          </div>
        ) : (
          <div className="brief-layout">
            <div>
              {fallbackUsed ? <div className="notice notice--warn"><strong>Deterministic fallback used</strong><span>Model status: {analysis.data !== undefined && 'model_status' in analysis.data ? analysis.data.model_status : 'unavailable'}. The workflow remains fully operable.</span></div> : null}
              <blockquote>{brief.executive_summary}</blockquote>
              <h3>Hypotheses</h3>
              <ul>{brief.hypotheses.map((item) => <li key={item.statement}>{item.statement}</li>)}</ul>
              <h3>Unknowns retained</h3>
              <ul>{brief.unknowns.map((item) => <li key={item}>{item}</li>)}</ul>
            </div>
            <div className="brief-next-step">
              <span className="eyebrow">Next controlled step</span>
              <strong>Preview standard payment link</strong>
              <p>Server-owned policy will recompute all 13 rules. Merchant approval is required after preview.</p>
              {summary.action_eligible ? (
                <Link className="button button--primary" to={`/incidents/${encodeURIComponent(detail.incident_id)}/recover`}>Open recovery preview</Link>
              ) : (
                <StatusChip value="incident_not_action_eligible" tone="warn" />
              )}
            </div>
          </div>
        )}
      </Panel>

      <Panel eyebrow="Append-only history" title="Detector observations">
        <ol className="observation-timeline">
          {incident.data.observations.map((item, index) => (
            <li key={item.observation_id}>
              <span>{(index + 1).toString().padStart(2, '0')}</span>
              <div><strong>{formatDateTime(item.evaluated_at)}</strong><p>{item.evidence_event_ids.length.toString()} cited evidence event{item.evidence_event_ids.length === 1 ? '' : 's'}</p></div>
            </li>
          ))}
        </ol>
      </Panel>
    </>
  );
}
