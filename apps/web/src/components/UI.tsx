import type { PropsWithChildren, ReactNode } from 'react';

import { humanize } from '../lib/format';

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}): React.JSX.Element {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions === undefined ? null : <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function StatusChip({
  value,
  tone = 'neutral',
}: {
  value: string;
  tone?: 'good' | 'warn' | 'danger' | 'info' | 'neutral';
}): React.JSX.Element {
  return <span className={`status-chip status-chip--${tone}`}>{humanize(value)}</span>;
}

export function MetricCard({
  label,
  value,
  detail,
  tone = 'neutral',
}: {
  label: string;
  value: string;
  detail: string;
  tone?: 'neutral' | 'danger' | 'good' | 'info';
}): React.JSX.Element {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export function Panel({
  title,
  eyebrow,
  actions,
  children,
  className = '',
}: PropsWithChildren<{
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  className?: string;
}>): React.JSX.Element {
  return (
    <section className={`panel ${className}`.trim()}>
      <div className="panel-heading">
        <div>
          {eyebrow === undefined ? null : <p className="eyebrow">{eyebrow}</p>}
          <h2>{title}</h2>
        </div>
        {actions === undefined ? null : <div className="panel-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function LoadingState({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="state-card" aria-live="polite">
      <span className="loader" aria-hidden="true" />
      <div><strong>{label}</strong><p>Reading validated local evidence…</p></div>
    </div>
  );
}

export function ErrorState({
  title,
  message,
  action,
}: {
  title: string;
  message: string;
  action?: ReactNode;
}): React.JSX.Element {
  return (
    <div className="state-card state-card--error" role="alert">
      <span className="state-icon" aria-hidden="true">!</span>
      <div><strong>{title}</strong><p>{message}</p>{action}</div>
    </div>
  );
}

export function EmptyState({
  title,
  message,
}: {
  title: string;
  message: string;
}): React.JSX.Element {
  return (
    <div className="empty-state">
      <span aria-hidden="true">✓</span>
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

export function DefinitionList({
  items,
}: {
  items: readonly { term: string; value: ReactNode }[];
}): React.JSX.Element {
  return (
    <dl className="definition-list">
      {items.map((item) => (
        <div key={item.term}><dt>{item.term}</dt><dd>{item.value}</dd></div>
      ))}
    </dl>
  );
}
