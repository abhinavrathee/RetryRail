import { afterEach, describe, expect, it, vi } from 'vitest';

import { operationKey, retryRailApi, RetryRailApiError } from './retryrail';

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

describe('RetryRail API boundary', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('preserves a typed server reason without exposing response details', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ detail: { reason_code: 'MERCHANT_AUTHORIZATION_INVALID' } }, 401),
    );

    const error = await retryRailApi.experiment('wrong-secret').catch((value: unknown) => value);

    expect(error).toBeInstanceOf(RetryRailApiError);
    expect(error).toMatchObject({
      status: 401,
      reasonCode: 'MERCHANT_AUTHORIZATION_INVALID',
      name: 'RetryRailApiError',
      message: 'MERCHANT_AUTHORIZATION_INVALID',
    });
  });

  it('falls back to the HTTP status when an error body is untrusted', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html>upstream failure</html>', { status: 503 }),
    );

    await expect(retryRailApi.overview()).rejects.toMatchObject({
      status: 503,
      reasonCode: 'HTTP_503',
    });
  });

  it('performs lookup-only reconciliation with encoded identifiers and no approval token', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({
        disposition: 'created',
        receipt: {
          action_id: 'action/ambiguous',
          plan_id: 'plan_001',
          incident_id: 'incident_001',
          payment_id: 'payment_001',
          state: 'succeeded',
          execution_target: 'razorpay_test_mode',
          execution_side_effect: 'test_mode_payment_link_created',
          external_notifications_enabled: false,
          provider_action_id: 'plink_001',
          transitions: [
            {
              prior_state: 'reconciliation_required',
              new_state: 'succeeded',
              occurred_at: '2026-09-05T08:00:00Z',
              actor: 'razorpay_lookup',
              reason_code: 'ACTION_PROVIDER_VERIFIED',
            },
          ],
          error: null,
          synthetic: true,
        },
        provider_receipt: {
          provider_action_id: 'plink_lookup_001',
          status: 'created',
          short_url: null,
          verified_at: '2026-09-05T08:00:00Z',
          verification_source: 'reference_lookup',
        },
      }),
    );

    const result = await retryRailApi.reconcile(
      'action/ambiguous',
      'merchant-secret',
      'reconcile-key',
    );

    expect(result.receipt.state).toBe('succeeded');
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0] ?? [];
    expect(url === undefined ? false : requestUrl(url).endsWith('/api/v1/actions/action%2Fambiguous/reconcile')).toBe(true);
    expect(options).toMatchObject({
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-RetryRail-Merchant-Authorization': 'merchant-secret',
      },
      body: JSON.stringify({ idempotency_key: 'reconcile-key' }),
    });
    expect((options?.headers as Record<string, string>)['X-RetryRail-Approval-Token']).toBeUndefined();
  });

  it('creates collision-resistant operation keys without retaining secrets', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_725_000_000_000);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue(
      '12345678-1234-4234-8234-123456789abc',
    );

    expect(operationKey('preview')).toBe('preview_m0gcgmio_1234567812344234');
  });
});
