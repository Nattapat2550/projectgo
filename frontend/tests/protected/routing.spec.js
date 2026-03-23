import { test, expect } from '@playwright/test';

test.describe('Protected Routing', () => {
  test('เข้า /home โดยไม่ได้ล็อกอิน โดนเตะกลับไปหน้าเข้าสู่ระบบ', async ({ page }) => {
    await page.route('**/api/auth/status', route => {
      route.fulfill({ status: 401, json: { error: 'Unauthorized' } });
    });
    
    await page.goto('/home');
    await expect(page).toHaveURL(/\/login/);
  });

  test('เข้า /settings โดยไม่ได้ล็อกอิน โดนเตะกลับไปหน้าเข้าสู่ระบบ', async ({ page }) => {
    await page.route('**/api/auth/status', route => {
      route.fulfill({ status: 401, json: { error: 'Unauthorized' } });
    });

    await page.goto('/settings');
    await expect(page).toHaveURL(/\/login/);
  });
});