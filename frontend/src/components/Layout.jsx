import React, { useEffect, useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { logout } from '../slices/authSlice';
import api from '../api';

const Layout = ({ children }) => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();

  const { isAuthenticated, role } = useSelector((s) => s.auth);

  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [dark, setDark] = useState(false);
  const [me, setMe] = useState(null);

  // โหลดข้อมูล user สำหรับแสดงชื่อ + avatar (เฉพาะตอน login)
  useEffect(() => {
    let cancelled = false;
    const loadMe = async () => {
      if (!isAuthenticated) {
        setMe(null);
        return;
      }
      try {
        const res = await api.get('/api/users/me');
        if (!cancelled) setMe(res.data);
      } catch {
        if (!cancelled) setMe(null);
      }
    };
    loadMe();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  // theme toggle
  useEffect(() => {
    const saved = localStorage.getItem('theme') === 'dark';
    setDark(saved);
  }, []);

  useEffect(() => {
    document.body.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  }, [dark]);

  const handleThemeToggle = () => {
    setDark((prev) => !prev);
  };

  const handleLogout = async () => {
    try {
      await dispatch(logout()).unwrap();
    } finally {
      setDropdownOpen(false);
      navigate('/');
    }
  };

  const atPublicLanding =
    location.pathname === '/' && !isAuthenticated;

  const showDownloadLink = true; // ให้เหมือนของเก่า มี Download ตลอด

  const userDisplayName =
    me?.username || me?.email || 'User';

  return (
    <div>
      {/* Top Nav */}
      <nav className="nav">
        <div className="brand">
          <Link to="/" className="brand-text">
            MySite
          </Link>
        </div>


        <div className="links">
          {/* ลิงก์เมนูหลักเหมือนเวอร์ชันเก่า */}
          <NavLink to="/about">About</NavLink>
          <NavLink to="/contact">Contact</NavLink>
          {showDownloadLink && (
            <NavLink to="/download">Download</NavLink>
          )}

          {/* ปุ่มสลับธีม */}
          <button
            id="themeToggle"
            type="button"
            onClick={handleThemeToggle}
          >
            🌓
          </button>

          {/* ถ้า login แล้ว -> แสดง user menu แบบ home.html เดิม */}
          {isAuthenticated && (
            <div
              className={
                'user-menu' + (dropdownOpen ? ' open' : '')
              }
            >
              <img
                src={me?.profile_picture_url || '../../images/user.png'}
                alt="avatar"
                onClick={() => setDropdownOpen((o) => !o)}
              />
              <span onClick={() => setDropdownOpen((o) => !o)}>
                {userDisplayName}
              </span>
              <div className="dropdown">
                <Link to="/settings">Settings</Link>
                {role === 'admin' && (
                  <Link to="/admin">Admin</Link>
                )}
                <button
                  type="button"
                  className="linklike"
                  onClick={handleLogout}
                >
                  Logout
                </button>
              </div>
            </div>
          )}

          {/* ถ้ายังไม่ login: ไม่แสดง user-menu (เหมือน index.html เดิม) */}
        </div>
      </nav>

      {/* Main content + container เหมือนหน้าเก่า */}
      <main className="container">
        {children}
      </main>
    </div>
  );
};

export default Layout;
