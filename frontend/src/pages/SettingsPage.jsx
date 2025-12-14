import React, { useEffect, useState, useRef } from 'react';
import api from '../api';
import { useNavigate } from 'react-router-dom';

const SettingsPage = () => {
  const [username, setUsername] = useState('');
  const [avatarUrl, setAvatarUrl] = useState('');
  const [msg, setMsg] = useState(null);
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  useEffect(() => {
    const loadMe = async () => {
      try {
        const res = await api.get('/api/users/me');
        setUsername(res.data.username || '');
        if (res.data.profile_picture_url) {
          setAvatarUrl(res.data.profile_picture_url);
        }
      } catch {
        navigate('/', { replace: true });
      }
    };
    loadMe();
  }, [navigate]);

  const handleProfileSave = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.put('/api/users/me', {
        username: username.trim()
      });
      setMsg('Profile updated.');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Update failed');
    }
  };

  const handleAvatarChange = async (e) => {
    setMsg(null);
    const file = e.target.files?.[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('avatar', file);
    try {
      const res = await api.post('/api/users/avatar', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      if (res.data.profile_picture_url) {
        setAvatarUrl(res.data.profile_picture_url);
      }
      setMsg('Avatar uploaded.');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Upload failed');
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Delete your account? This cannot be undone.')) {
      return;
    }
    try {
      await api.delete('/api/users/me');
      navigate('/', { replace: true });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Delete failed');
    }
  };

  const triggerFileSelect = () => {
    fileInputRef.current?.click();
  };

  return (
    <>
      <h2>Settings</h2>

      {avatarUrl && (
        <div className="avatar-wrapper" style={{ marginBottom: '1rem' }}>
          <img
            src={avatarUrl}
            alt="avatar"
            style={{ width: 80, height: 80, borderRadius: '50%' }}
          />
        </div>
      )}

      <form id="settingsForm" onSubmit={handleProfileSave}>
        <label>Username</label>
        <input
          type="text"
          required
          value={username}
          onChange={(e) => setUsername(e.target.value.trimStart())}
        />

        <button className="btn" type="submit">
          Save profile
        </button>
      </form>

      <div style={{ marginTop: '1rem' }}>
        <button
          type="button"
          className="btn outline"
          onClick={triggerFileSelect}
        >
          Change avatar
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleAvatarChange}
          style={{ display: 'none' }}
        />
      </div>

      <div style={{ marginTop: '2rem' }}>
        <button
          type="button"
          className="btn danger"
          onClick={handleDelete}
        >
          Delete my account
        </button>
      </div>

      {msg && (
        <p className="muted" style={{ color: 'var(--acc-1)', marginTop: '1rem' }}>
          {msg}
        </p>
      )}
    </>
  );
};

export default SettingsPage;
