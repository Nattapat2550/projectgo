import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { login, clearAuthError, checkAuthStatus } from '../slices/authSlice';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import api from '../api';

const LoginPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, role, status, error } = useSelector((s) => s.auth);
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [localError, setLocalError] = useState(null);

  // ✅ 1. ตรวจสอบ Error จาก Google OAuth Redirect
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    if (params.get('error') === 'oauth_failed') {
      setLocalError('การเข้าสู่ระบบด้วย Google ล้มเหลว กรุณาลองใหม่อีกครั้ง');
    }
    
    // ✅ 2. ตรวจสอบ Google Login Success (ผ่าน URL Fragment #token=...)
    if (window.location.hash.includes('token=')) {
      dispatch(checkAuthStatus());
    }
  }, [location, dispatch]);

  useEffect(() => {
    if (isAuthenticated) {
      const dest = role === 'admin' ? '/admin' : '/home';
      navigate(dest, { replace: true });
    }
  }, [isAuthenticated, role, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError(null);
    dispatch(clearAuthError());
    try {
      await dispatch(login({ email, password, remember })).unwrap();
    } catch (errMsg) {
      // ไม่ต้องทำอะไร Redux จะเก็บ Error ไว้ให้แล้ว
    }
  };

  const handleGoogleLogin = () => {
    // ยิงตรงไปที่ Backend Google Start Route
    window.location.href = `${api.defaults.baseURL}/api/auth/google`;
  };

  return (
    <div className="login-container">
      <h2>เข้าสู่ระบบ</h2>
      <form onSubmit={handleSubmit}>
        <label>อีเมล</label>
        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />

        <label>รหัสผ่าน</label>
        <input type={showPassword ? 'text' : 'password'} required value={password} onChange={(e) => setPassword(e.target.value)} />

        <div className="options">
          <label><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> จำฉันไว้</label>
          <label><input type="checkbox" checked={showPassword} onChange={(e) => setShowPassword(e.target.checked)} /> แสดงรหัสผ่าน</label>
        </div>

        <button className="btn" type="submit" disabled={status === 'loading'}>
          {status === 'loading' ? 'กำลังตรวจสอบ...' : 'เข้าสู่ระบบ'}
        </button>
      </form>

      <div className="divider">หรือ</div>
      <button className="btn outline" onClick={handleGoogleLogin}>Login with Google</button>

      {(localError || error) && <p style={{ color: 'red', marginTop: '1rem' }}>{localError || error}</p>}
    </div>
  );
};

export default LoginPage;