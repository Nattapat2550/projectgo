import { test, expect } from '@playwright/test';

test.describe('Reset Password Page', () => {
  test('Part 1: ขอลิงก์สำเร็จ', async ({ page }) => {
    await page.route('**/api/auth/forgot-password', route => {
      route.fulfill({ status: 200, json: { ok: true } });
    });

    await page.goto('/reset');
    await page.fill('input[type="email"]', 'test@example.com');
    await page.click('button[type="submit"]');

    await expect(page.locator('text=If that email exists, a reset link was sent.')).toBeVisible();
  });

  test('Part 2: เปลี่ยนรหัสผ่านใหม่ (มี Token)', async ({ page }) => {
    await page.route('**/api/auth/reset-password', route => {
      route.fulfill({ status: 200, json: { ok: true } });
    });

    await page.goto('/reset?token=valid-token');
    await page.fill('input[type="password"]', 'NewPass123!');
    await page.click('button[type="submit"]');

    await expect(page.locator('text=Password set. You can login now.')).toBeVisible();
  });
});