import { Badge } from '@razorpay/blade/components';
import { useQuery } from '@tanstack/react-query';
import { useEffect, useRef, useState, type PropsWithChildren } from 'react';
import { NavLink } from 'react-router-dom';

import { fetchReadiness } from '../api/health';
import { useMerchantSession } from '../session/useMerchantSession';

const NAVIGATION = [
  { to: '/', label: 'Overview', icon: 'pulse', end: true },
  { to: '/impact', label: 'Experiment impact', icon: 'chart', end: false },
  { to: '/demo', label: 'Demo controls', icon: 'play', end: false },
] as const;

function RailIcon({ name }: { name: string }): React.JSX.Element {
  const path = name === 'chart'
    ? 'M4 17V9m6 8V5m6 12v-4m4 7H2'
    : name === 'play'
      ? 'm8 5 10 7-10 7V5Z'
      : 'M3 12h4l2-6 4 12 2-6h6';
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24">
      <path d={path} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
    </svg>
  );
}

function ApiStatus(): React.JSX.Element {
  const readiness = useQuery({
    queryKey: ['health', 'ready'],
    queryFn: ({ signal }) => fetchReadiness(signal),
    retry: 1,
    staleTime: 15_000,
  });
  if (readiness.isPending) {
    return <span className="api-state api-state--pending">Checking API</span>;
  }
  if (readiness.isError) {
    return (
      <span className="api-state api-state--offline" role="status">
        API unavailable
      </span>
    );
  }
  return (
    <span className="api-state api-state--ready" role="status">
      API ready · v{readiness.data.version}
    </span>
  );
}

function SessionDialog(): React.JSX.Element {
  const session = useMerchantSession();
  const [authorization, setAuthorization] = useState(session.authorization);
  const [replayToken, setReplayToken] = useState(session.replayToken);
  const authorizationRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement;
    const timer = globalThis.setTimeout(() => authorizationRef.current?.focus(), 0);
    return () => {
      globalThis.clearTimeout(timer);
      if (previouslyFocused instanceof HTMLElement) previouslyFocused.focus();
    };
  }, []);

  useEffect(() => {
    if (!session.isDialogOpen) return undefined;
    const closeOnEscape = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        session.closeDialog();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      );
      if (focusable === undefined || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    globalThis.addEventListener('keydown', closeOnEscape);
    return () => { globalThis.removeEventListener('keydown', closeOnEscape); };
  }, [session]);

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={session.closeDialog}>
      <section
        aria-labelledby="session-title"
        aria-modal="true"
        className="session-dialog"
        ref={dialogRef}
        role="dialog"
        onMouseDown={(event) => { event.stopPropagation(); }}
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">Local operator session</p>
            <h2 id="session-title">Unlock review actions</h2>
          </div>
          <button aria-label="Close session dialog" className="icon-button" onClick={session.closeDialog} type="button">×</button>
        </div>
        <p className="dialog-copy">
          These values stay only in this page&apos;s memory and disappear on refresh. Never enter
          Razorpay or OpenAI keys here.
        </p>
        <form
          className="session-form"
          onSubmit={(event) => {
            event.preventDefault();
            session.save(authorization.trim(), replayToken.trim());
          }}
        >
          <label htmlFor="merchant-authorization">
            Merchant authorization secret
            <input
              autoComplete="off"
              id="merchant-authorization"
              onChange={(event) => { setAuthorization(event.target.value); }}
              placeholder="RETRYRAIL_MERCHANT_APPROVAL_SECRET"
              ref={authorizationRef}
              required
              type="password"
              value={authorization}
            />
          </label>
          <label htmlFor="replay-token">
            Demo replay token <span>optional</span>
            <input
              autoComplete="off"
              id="replay-token"
              onChange={(event) => { setReplayToken(event.target.value); }}
              placeholder="Only needed on Demo controls"
              type="password"
              value={replayToken}
            />
          </label>
          <div className="dialog-actions">
            <button className="button button--secondary" onClick={session.closeDialog} type="button">Cancel</button>
            <button className="button button--primary" type="submit">Unlock session</button>
          </div>
        </form>
      </section>
    </div>
  );
}

export function AppShell({ children }: PropsWithChildren): React.JSX.Element {
  const session = useMerchantSession();
  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className="side-rail" aria-label="Primary navigation">
        <NavLink className="rail-brand" to="/" aria-label="RetryRail overview">
          <span className="rail-brand-mark" aria-hidden="true">R</span>
          <span><strong>RetryRail</strong><small>Payment control room</small></span>
        </NavLink>
        <nav>
          {NAVIGATION.map((item) => (
            <NavLink
              className={({ isActive }) => `rail-link${isActive ? ' rail-link--active' : ''}`}
              end={item.end}
              key={item.to}
              to={item.to}
            >
              <RailIcon name={item.icon} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="rail-trust">
          <span className="trust-dot" aria-hidden="true" />
          <p><strong>Review first</strong><span>No AI output can mutate provider state.</span></p>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="synthetic-badge">
            <Badge color="notice" size="medium">Synthetic evidence</Badge>
            <span>Test Mode actions only</span>
          </div>
          <div className="topbar-actions">
            <ApiStatus />
            {session.isUnlocked ? (
              <button className="session-control session-control--open" onClick={session.lock} type="button">
                <span aria-hidden="true">●</span> Session unlocked · Lock
              </button>
            ) : (
              <button className="session-control" onClick={session.openDialog} type="button">
                Unlock merchant actions
              </button>
            )}
          </div>
        </header>
        <main id="main-content" className="main-content">{children}</main>
        <footer className="app-footer">
          <span>RetryRail M7 reviewer surface</span>
          <span>UTC timestamps · INR subunits · synthetic batch metrics</span>
        </footer>
      </div>
      {session.isDialogOpen ? <SessionDialog /> : null}
    </div>
  );
}
