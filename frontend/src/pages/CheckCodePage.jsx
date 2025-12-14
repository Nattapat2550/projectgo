import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';

const CheckCodePage = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    const pending = sessionStorage.getItem('pendingEmail');
    if (!pending) {
      navigate('/register', { replace: true });
      return;
    }
    setEmail(pending);
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post('/api/auth/verify-code', {
        email,
        code: code.trim()
      });
      navigate(`/form?email=${encodeURIComponent(email)}`);
    } catch (err) {
      setMsg(err.response?.data?.error || 'Invalid code');
    }
  };

  return (
    <section>
      <h2>Verify Code</h2>
      <p>We sent a verification code to {email}</p>
      <form onSubmit={handleSubmit}>
        <div>
          <label>
            Code
            <input
              type="text"
              required
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
            />
          </label>
        </div>
        <button type="submit">Verify</button>
      </form>
      {msg && <p style={{ color: 'red' }}>{msg}</p>}
    </section>
  );
};

export default CheckCodePage;
