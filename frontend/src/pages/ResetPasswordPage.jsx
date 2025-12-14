import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api';

const ResetPasswordPage = () => {
  const [search] = useSearchParams();
  const token = search.get('token');

  const [email, setEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [msg, setMsg] = useState(null);

  const requestReset = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post('/api/auth/forgot-password', {
        email: email.trim()
      });
      setMsg('If that email exists, a reset link was sent.');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Request failed');
    }
  };

  const doReset = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post('/api/auth/reset-password', {
        token,
        newPassword
      });
      setMsg('Password set. You can login now.');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Reset failed');
    }
  };

  if (!token) {
    return (
      <section>
        <h2>Forgot password</h2>
        <form onSubmit={requestReset}>
          <div>
            <label>
              Email
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value.trim())}
              />
            </label>
          </div>
          <button type="submit">Send reset link</button>
        </form>
        {msg && <p style={{ color: 'red' }}>{msg}</p>}
      </section>
    );
  }

  return (
    <section>
      <h2>Reset password</h2>
      <form onSubmit={doReset}>
        <div>
          <label>
            New password
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </label>
        </div>
        <button type="submit">Set new password</button>
      </form>
      {msg && <p style={{ color: 'red' }}>{msg}</p>}
    </section>
  );
};

export default ResetPasswordPage;
