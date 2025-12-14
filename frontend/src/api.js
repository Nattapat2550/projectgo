import axios from 'axios';

const API_BASE_URL =
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000'
    : 'https://react1-k4e2.onrender.com';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true
});

export default api;
