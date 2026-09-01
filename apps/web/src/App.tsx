import { Badge, Box, Heading, Text } from '@razorpay/blade/components';
import { useQuery } from '@tanstack/react-query';

import { fetchReadiness } from './api/health';

const PRINCIPLES = [
  {
    eyebrow: 'Detect',
    title: 'Statistical evidence first',
    body: 'A deterministic detector—not a model—decides whether a payment cohort degraded.',
  },
  {
    eyebrow: 'Diagnose',
    title: 'Ground every claim',
    body: 'Observed facts, bounded hypotheses and unknowns remain visibly separate.',
  },
  {
    eyebrow: 'Recover',
    title: 'Review before mutation',
    body: 'Policy, approval, idempotency and verification guard every Test Mode action.',
  },
] as const;

function ServiceStatus(): React.JSX.Element {
  const readiness = useQuery({
    queryKey: ['health', 'ready'],
    queryFn: ({ signal }) => fetchReadiness(signal),
    retry: 1,
    staleTime: 15_000,
  });

  if (readiness.isPending) {
    return <span className="status status--pending">Checking local API…</span>;
  }
  if (readiness.isError) {
    return (
      <span className="status status--offline" role="status">
        API unavailable · run the local stack
      </span>
    );
  }
  return (
    <span className="status status--ready" role="status">
      API ready · v{readiness.data.version}
    </span>
  );
}

export function App(): React.JSX.Element {
  return (
    <Box backgroundColor="surface.background.gray.intense" minHeight="100vh">
      <header className="site-header" aria-label="RetryRail header">
        <a className="brand" href="/" aria-label="RetryRail home">
          <span className="brand-mark" aria-hidden="true">R</span>
          <span>RetryRail</span>
        </a>
        <ServiceStatus />
      </header>

      <main id="main-content">
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-copy">
            <div className="label-row">
              <Badge color="notice" size="medium">Synthetic data only</Badge>
              <span className="milestone">Foundation · M0</span>
            </div>
            <div id="hero-title">
              <Heading as="h1" size="xlarge">
                Detect payment degradation. Recover revenue with proof.
              </Heading>
            </div>
            <Text size="large" color="surface.text.gray.muted">
              RetryRail closes the loop from merchant-specific payment failure evidence to a
              bounded, approved recovery action and honestly measured incremental GMV.
            </Text>
            <p className="scope-note">
              No live payments, recovery actions or performance claims are enabled in this
              foundation build.
            </p>
          </div>
          <div className="rail-visual" aria-label="RetryRail control flow">
            {PRINCIPLES.map((principle, index) => (
              <div className="rail-stop" key={principle.eyebrow}>
                <span className="rail-index" aria-hidden="true">0{index + 1}</span>
                <div>
                  <span className="eyebrow">{principle.eyebrow}</span>
                  <h2>{principle.title}</h2>
                  <p>{principle.body}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="trust-strip" aria-label="Safety guarantees">
          <div><strong>Raw-body HMAC</strong><span>before parsing</span></div>
          <div><strong>Merchant scoped</strong><span>at every boundary</span></div>
          <div><strong>Rules fallback</strong><span>when AI is unavailable</span></div>
          <div><strong>Append-only audit</strong><span>for every decision</span></div>
        </section>
      </main>
    </Box>
  );
}
