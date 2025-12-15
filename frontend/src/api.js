import axios from 'axios';

// Vite env (จะถูกฝังตอน build)
const ENV_BASE = import.meta?.env?.VITE_API_BASE_URL;

const normalize = (u) => (u ? u.replace(/\/+$/, '') : u);

const API_BASE_URL = normalize(
  ENV_BASE ||
    (window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1'
      ? 'http://localhost:5000'
      : 'https://projectgob.onrender.com')
);

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: { Accept: 'application/json' }
});

export default api;
export { API_BASE_URL };
