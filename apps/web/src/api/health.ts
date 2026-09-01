import { z } from 'zod';

const healthResponseSchema = z.object({
  status: z.enum(['ok', 'ready']),
  service: z.literal('retryrail-api'),
  version: z.string().min(1),
});

export type HealthResponse = z.infer<typeof healthResponseSchema>;

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(
  /\/$/u,
  '',
) ?? 'http://127.0.0.1:8000';

export async function fetchReadiness(signal?: AbortSignal): Promise<HealthResponse> {
  const request: RequestInit = {
    method: 'GET',
    headers: { Accept: 'application/json' },
    ...(signal === undefined ? {} : { signal }),
  };
  const response = await fetch(`${API_BASE_URL}/health/ready`, request);
  if (!response.ok) {
    throw new Error(`Readiness returned HTTP ${String(response.status)}`);
  }
  return healthResponseSchema.parse(await response.json());
}
