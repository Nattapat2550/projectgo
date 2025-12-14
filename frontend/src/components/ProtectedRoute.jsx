// src/components/ProtectedRoute.jsx
import React, { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { Navigate, useLocation } from 'react-router-dom';

import { checkAuthStatus } from '../slices/authSlice';

const ProtectedRoute = ({ children, roles }) => {
  const dispatch = useDispatch();
  const location = useLocation();

  const { isAuthenticated, role, status } = useSelector((state) => state.auth);

  // เรียก checkAuthStatus เฉพาะตอน state เป็น idle (ยังไม่เช็ค)
  useEffect(() => {
    if (status === 'idle') {
      dispatch(checkAuthStatus());
    }
  }, [status, dispatch]);

  // กำลังเช็คสถานะ login – ให้แสดง loading เฉพาะหน้า protected
  if (status === 'loading' || status === 'idle') {
    return (
      <div className="page-loading">
        กำลังตรวจสอบสิทธิ์การเข้าถึง...
      </div>
    );
  }

  // ถ้าเช็คแล้วพบว่าไม่ล็อกอิน → เด้งไปหน้า login และจำ path เดิม
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // ถ้ามีการกำหนด roles และ role ปัจจุบันไม่อยู่ในนั้น → เด้งกลับหน้าหลัก
  if (roles && roles.length > 0 && !roles.includes(role)) {
    return <Navigate to="/" replace />;
  }

  // ผ่านทุกเงื่อนไข → แสดงหน้า child
  return children;
};

export default ProtectedRoute;