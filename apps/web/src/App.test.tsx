import { BladeProvider } from '@razorpay/blade/components';
import { bladeTheme } from '@razorpay/blade/tokens';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';

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

describe('RetryRail foundation shell', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('shows an honest synthetic-only scope and healthy API state', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ status: 'ready', service: 'retryrail-api', version: '0.1.0' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    renderApp();

    expect(
      screen.getByRole('heading', { name: /detect payment degradation/i }),
    ).toBeInTheDocument();
    expect(screen.getByText('Synthetic data only')).toBeInTheDocument();
    expect(await screen.findByText('API ready · v0.1.0')).toBeInTheDocument();
  });

  it('shows a useful recovery state when the local API is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('network unavailable'));

    renderApp();

    expect(
      await screen.findByText(/API unavailable/i, {}, { timeout: 3_000 }),
    ).toBeInTheDocument();
  });
});
