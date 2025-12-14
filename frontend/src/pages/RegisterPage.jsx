import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';

const RegisterPage = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post('/api/auth/register', { email: email.trim() });
      sessionStorage.setItem('pendingEmail', email.trim());
      navigate('/check');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Register failed');
    }
  };

  const handleGoogle = () => {
    window.location.href = `${api.defaults.baseURL}/api/auth/google`;
  };

  return (
    <>
      <h2>Register</h2>

      <form id="registerForm" onSubmit={handleSubmit}>
        <label>Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value.trim())}
        />

        <button className="btn" type="submit">
          Send verification code
        </button>
      </form>

      <div className="divider">or</div>

      <button
        className="btn outline"
        type="button"
        onClick={handleGoogle}
      >
        Continue with Google
      </button>

      {msg && (
        <p className="muted" style={{ color: 'var(--acc-1)' }}>
          {msg}
        </p>
      )}
    </>
  );
};

export default RegisterPage;
