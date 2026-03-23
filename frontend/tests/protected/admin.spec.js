import { test, expect } from '@playwright/test';

test.describe('Admin Page Protection', () => {
  test('User ธรรมดาพยายามเข้า /admin จะโดนเตะกลับไป /', async ({ page }) => {
    await page.route('**/api/auth/status', route => {
      route.fulfill({ status: 200, json: { authenticated: true, role: 'user' } });
    });

    await page.goto('/admin');
    await expect(page).toHaveURL('http://localhost:3000/'); // Redirects to home/root
  });

  test('Admin เข้า /admin และโหลดตารางผู้ใช้ได้สำเร็จ', async ({ page }) => {
    await page.route('**/api/auth/status', route => {
      route.fulfill({ status: 200, json: { authenticated: true, role: 'admin' } });
    });
    
    await page.route('**/api/admin/users', route => {
      route.fulfill({ 
        status: 200, 
        json: [{ id: 1, email: 'admin@system.com', role: 'admin', username: 'SuperAdmin' }] 
      });
    });
    
    await page.route('**/api/admin/carousel', route => route.fulfill({ status: 200, json: [] }));

    await page.goto('/admin');
    await expect(page.locator('h2', { hasText: 'Admin Dashboard' })).toBeVisible();
    
    // เช็คว่าตาราง Users มีข้อมูลที่เรา Mock ไว้มาแสดง
    await expect(page.locator('input[value="admin@system.com"]')).toBeVisible();
  });
});