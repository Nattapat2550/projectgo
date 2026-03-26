import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../api';
import { useDispatch } from 'react-redux';
import { checkAuthStatus } from '../slices/authSlice';

const CompleteProfilePage = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [search] = useSearchParams();
  const emailFromQuery = search.get('email') || '';

  const [email, setEmail] = useState(emailFromQuery);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    if (!emailFromQuery) {
      const pending = sessionStorage.getItem('pendingEmail');
      if (pending) setEmail(pending);
    }
  }, [emailFromQuery]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      // ✅ ส่งไปแค่ email, username, password เพราะโค้ดถูกตรวจสอบผ่านไปแล้ว
      await api.post('/api/auth/complete-profile', {
        email: email.trim(),
        username: username.trim(),
        password
      });
      await dispatch(checkAuthStatus());
      navigate('/home', { replace: true });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Failed to complete profile');
    }
  };

  return (
    <section>
      <h2>Complete Profile</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>
            Email
            <input
              type="email"
              required
              readOnly
              style={{ opacity: 0.7 }}
              value={email}
              onChange={(e) => setEmail(e.target.value.trim())}
            />
          </label>
        </div>
        <div>
          <label>
            Username
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value.trim())}
            />
          </label>
        </div>
        <div>
          <label>
            Password (min 8 chars)
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
        </div>
        <button type="submit" className="btn mt-3">Save</button>
      </form>
      {msg && <p style={{ color: 'red', marginTop: '1rem' }}>{msg}</p>}
    </section>
  );
};

export default CompleteProfilePage;