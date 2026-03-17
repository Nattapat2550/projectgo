// src/App.jsx
import React, { Suspense, lazy, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';

import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';

// ✅ ทำ Landing เป็น static import เพื่อตัด critical request chain
import LandingPage from './pages/LandingPage';

// ✅ lazy-load หน้าที่ไม่ใช่หน้าแรก เพื่อลด JS ตอนเริ่มโหลด
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const CheckCodePage = lazy(() => import('./pages/CheckCodePage'));
const CompleteProfilePage = lazy(() => import('./pages/CompleteProfilePage'));
const HomePage = lazy(() => import('./pages/HomePage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const ResetPasswordPage = lazy(() => import('./pages/ResetPasswordPage'));
const AdminPage = lazy(() => import('./pages/AdminPage'));
const AboutPage = lazy(() => import('./pages/AboutPage'));
const ContactPage = lazy(() => import('./pages/ContactPage'));
const DownloadPage = lazy(() => import('./pages/DownloadPage'));

const App = () => {
  // ✅ เพิ่ม useEffect สำหรับดักจับ Token เวลา Login ผ่าน Google
  useEffect(() => {
    const hash = window.location.hash;
    if (hash && hash.includes('token=')) {
      const params = new URLSearchParams(hash.substring(1));
      const token = params.get('token');
      const role = params.get('role');

      if (token) {
        // เซฟ Token ลง LocalStorage เพื่อให้ Redux/Axios ดึงไปใช้ต่อได้
        localStorage.setItem('token', token);
        if (role) localStorage.setItem('role', role);

        // เคลียร์ URL เพื่อซ่อน Token ไม่ให้รกหน้าจอและป้องกันความปลอดภัย
        window.history.replaceState(null, '', window.location.pathname);

        // โหลดหน้าใหม่ 1 ครั้ง เพื่อให้ระบบ State ยืนยันการเข้าสู่ระบบ
        window.location.href = '/home';
      }
    }
  }, []);

  return (
    <Layout>
      <Suspense fallback={<div className="page-loading" aria-busy="true">กำลังโหลด...</div>}>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/check" element={<CheckCodePage />} />
          <Route path="/form" element={<CompleteProfilePage />} />
          <Route path="/reset" element={<ResetPasswordPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/contact" element={<ContactPage />} />

          {/* Protected routes – ต้องล็อกอินก่อน */}
          <Route
            path="/home"
            element={
              <ProtectedRoute>
                <HomePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <SettingsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/download"
            element={
              <ProtectedRoute>
                <DownloadPage />
              </ProtectedRoute>
            }
          />

          {/* เฉพาะ role admin */}
          <Route
            path="/admin"
            element={
              <ProtectedRoute roles={['admin']}>
                <AdminPage />
              </ProtectedRoute>
            }
          />

          {/* route ไม่เจอ → กลับหน้าแรก */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  );
};

export default App;