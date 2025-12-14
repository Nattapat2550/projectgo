// frontend/src/pages/LoginPage.jsx
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { login, clearAuthError } from '../slices/authSlice';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import api from '../api';

const LoginPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, role, status, error } = useSelector(
    (s) => s.auth
  );

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false); // <-- state ใหม่
  const [localError, setLocalError] = useState(null);

  useEffect(() => {
    dispatch(clearAuthError());
  }, [dispatch]);

  useEffect(() => {
    if (isAuthenticated) {
      const dest =
        role === 'admin'
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
          type={showPassword ? 'text' : 'password'}  // <-- เปลี่ยนตาม checkbox
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <div
          className="row"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: '1rem',
            marginTop: '0.5rem'
          }}
        >
          <label>
            <input
              type="checkbox"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
            />{' '}
            Remember me
          </label>

          <label>
            <input
              type="checkbox"
              checked={showPassword}
              onChange={(e) => setShowPassword(e.target.checked)}
            />{' '}
            แสดงรหัสผ่าน
          </label>
        </div>

        <button className="btn" type="submit" disabled={status === 'loading'}>
          {status === 'loading' ? 'Logging in...' : 'Login'}
        </button>

        <Link className="muted" to="/reset">
          Forgot Password?
        </Link>
      </form>

      <div className="divider">or</div>

      <button
        className="btn outline"
        type="button"
        onClick={handleGoogleLogin}
      >
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
