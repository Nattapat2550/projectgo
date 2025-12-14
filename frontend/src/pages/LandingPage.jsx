import React from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useSelector } from 'react-redux';

const LandingPage = () => {
  const { isAuthenticated, role } = useSelector((s) => s.auth);

  if (isAuthenticated) {
    return (
      <Navigate to={role === 'admin' ? '/admin' : '/home'} replace />
    );
  }

  return (
    <>
      <h1>Welcome</h1>
      <p>
        This is a public landing page. Please register or login to
        continue.
      </p>
      <div className="actions">
        <Link className="btn" to="/register">
          Register
        </Link>
        <Link className="btn" to="/login">
          Login
        </Link>
      </div>
    </>
  );
};

export default LandingPage;
