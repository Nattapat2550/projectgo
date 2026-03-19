import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { login, clearAuthError, setCredentials, checkAuthStatus } from '../slices/authSlice'; // ✅ เพิ่ม import
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

  // ✅ 1. ตรวจสอบ Google Login จาก URL Fragment (#token=...&role=...)
  useEffect(() => {
    const hash = window.location.hash;
    if (hash) {
      const params = new URLSearchParams(hash.substring(1));
      const token = params.get('token');
      const role = params.get('role');

      if (token) {
        // เมื่อได้ token มาแล้ว ให้เช็คสถานะจริงจาก API
        dispatch(checkAuthStatus()).then(() => {
            navigate('/home', { replace: true });
        });
      }
    }
  }, [dispatch, navigate]);

  useEffect(() => {
    dispatch(clearAuthError());
  }, [dispatch]);

  useEffect(() => {
    if (isAuthenticated) {
      const dest = role === 'admin' ? '/admin' : (location.state && location.state.from?.pathname) || '/home';
      navigate(dest, { replace: true });
    }
  }, [isAuthenticated, role, navigate, location]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError(null);
    try {
      await dispatch(login({ email, password, remember })).unwrap();
    } catch (errMsg) {
      setLocalError(errMsg || 'Login failed');
    }
  };

  const handleGoogleLogin = () => {
    // ส่งไปที่ Backend เพื่อเริ่ม OAuth
    window.location.href = `${api.defaults.baseURL}/api/auth/google`;
  };

  return (
    <>
      <h2>Login</h2>
      <form id="loginForm" onSubmit={handleSubmit}>
        <label>Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value.trim())}
        />

        <label>Password</label>
        <input
          type={showPassword ? 'text' : 'password'}
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem' }}>
          <label><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> Remember me</label>
          <label><input type="checkbox" checked={showPassword} onChange={(e) => setShowPassword(e.target.checked)} /> แสดงรหัสผ่าน</label>
        </div>

        <button className="btn" type="submit" disabled={status === 'loading'}>
          {status === 'loading' ? 'Logging in...' : 'Login'}
        </button>
        <Link className="muted" to="/reset">Forgot Password?</Link>
      </form>

      <div className="divider">or</div>
      <button className="btn outline" type="button" onClick={handleGoogleLogin}>
        Login with Google
      </button>

      {(localError || error) && <p style={{ color: 'red' }}>{localError || error}</p>}
    </>
  );
};

export default LoginPage;