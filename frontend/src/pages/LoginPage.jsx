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

  // ✅ ตรวจสอบ URL Fragment สำหรับ Google Login
  useEffect(() => {
    const hash = window.location.hash;
    if (hash && hash.includes('token=')) {
      // เมื่อพบ token ใน URL ให้ทำการยืนยันสิทธิ์กับ Backend อีกครั้ง
      dispatch(checkAuthStatus());
    }
  }, [dispatch]);

  useEffect(() => {
    dispatch(clearAuthError());
  }, [dispatch]);

  useEffect(() => {
    if (isAuthenticated) {
      const dest = role === 'admin' 
        ? '/admin' 
        : (location.state && location.state.from?.pathname) || '/home';
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
    // เรียกไปที่ API Start ของ Go
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
          <label>
            <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            {" "}Remember me
          </label>
          <label>
            <input type="checkbox" checked={showPassword} onChange={(e) => setShowPassword(e.target.checked)} />
            {" "}แสดงรหัสผ่าน
          </label>
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

      {(localError || error) && (
        <p className="muted" style={{ color: 'var(--acc-1)' }}>
          {localError || error}
        </p>
      )}
    </>
  );
};

export default LoginPage;