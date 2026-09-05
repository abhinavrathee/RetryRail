import { BladeProvider } from '@razorpay/blade/components';
import { bladeTheme } from '@razorpay/blade/tokens';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';

const OVERVIEW = {
  detector_version: 'detector_v4_0_0',
  detector_release_status: 'qualified',
  detector_release_failed_targets: [],
  active_incidents: 0,
  action_eligible_incidents: 0,
  total_incidents: 0,
  at_risk_gmv_subunits: 0,
  currency: 'INR',
  data_as_of: '2026-08-31T10:15:00Z',
  synthetic: true,
};

function renderApp(): void {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <BladeProvider colorScheme="light" themeTokens={bladeTheme}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </BladeProvider>,
  );
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

describe('RetryRail merchant control room', () => {
  beforeEach(() => {
    globalThis.history.replaceState({}, '', '/');
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('shows the honest empty overview and healthy API state', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      await Promise.resolve();
      const url = requestUrl(input);
      if (url.endsWith('/health/ready')) {
        return jsonResponse({ status: 'ready', service: 'retryrail-api', version: '0.1.0' });
      }
      if (url.includes('/api/v1/overview')) return jsonResponse(OVERVIEW);
      if (url.includes('/api/v1/incidents')) {
        return jsonResponse({ items: [], count: 0, synthetic: true });
      }
      return jsonResponse({}, 404);
    });

    renderApp();

    expect(
      await screen.findByRole('heading', { name: /detect payment degradation/i }),
    ).toBeInTheDocument();
    expect(screen.getByText('Synthetic evidence')).toBeInTheDocument();
    expect(screen.getByText('No degradation incidents')).toBeInTheDocument();
    expect(await screen.findByText('API ready · v0.1.0')).toBeInTheDocument();
  });

  it('shows a useful failure state when the local API is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('network unavailable'));

    renderApp();

    expect(
      await screen.findByText(/API unavailable/i, {}, { timeout: 3_000 }),
    ).toBeInTheDocument();
    expect(await screen.findByText('Overview evidence is unavailable')).toBeInTheDocument();
  });
});
