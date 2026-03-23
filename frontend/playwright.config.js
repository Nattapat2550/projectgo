import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  /* รันเทสแบบขนานให้เสร็จไวขึ้น */
  fullyParallel: true,
  /* ถ้ารันใน CI (GitHub Actions) ให้ลองเทสซ้ำ 2 รอบถ้าพัง */
  retries: process.env.CI ? 2 : 0,
  /* จำนวน Worker */
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  
  use: {
    /* ✨ ส่วนสำคัญ: กำหนด Base URL ให้ Playwright รู้จัก */
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    // สามารถเปิด Firefox หรือ WebKit เพิ่มได้ถ้าต้องการ
  ],

  /* ✨ ส่วนสำคัญ: สั่งให้ Playwright เปิด Vite Server อัตโนมัติก่อนเทส */
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});