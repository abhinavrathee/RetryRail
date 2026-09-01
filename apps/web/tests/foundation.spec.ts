import { expect, test } from '@playwright/test';

test('foundation shell is accessible when the API is offline', async ({ page }) => {
  await page.route('http://127.0.0.1:8000/**', async (route) => route.abort('connectionfailed'));
  await page.goto('/');

  await expect(
    page.getByRole('heading', { name: /detect payment degradation/i }),
  ).toBeVisible();
  await expect(page.getByText('Synthetic data only')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('API unavailable');
});

