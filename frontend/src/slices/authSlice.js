import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../api';

const initialState = {
  isAuthenticated: false,
  role: null,
  userId: null,
  status: 'idle',
  error: null
};

export const checkAuthStatus = createAsyncThunk(
  'auth/checkStatus',
  async (_, { rejectWithValue }) => {
    try {
      const res = await api.get('/api/auth/status');
      return res.data; // { authenticated: true, id: 1, role: 'user' }
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || 'Session expired');
    }
  }
);

export const login = createAsyncThunk(
  'auth/login',
  async ({ email, password, remember }, { rejectWithValue }) => {
    try {
      const res = await api.post('/api/auth/login', { email, password, remember });
      return res.data; // { ok: true, user: { id: 1, role: 'admin' }, token: '...' }
    } catch (err) {
      // ดักจับ Error 401 และแสดงข้อความจาก Backend
      return rejectWithValue(err.response?.data?.error || 'อีเมลหรือรหัสผ่านไม่ถูกต้อง');
    }
  }
);

export const logout = createAsyncThunk(
  'auth/logout',
  async (_, { rejectWithValue }) => {
    try {
      await api.post('/api/auth/logout');
      return {};
    } catch (err) {
      return rejectWithValue('Logout failed');
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    clearAuthError(state) {
      state.error = null;
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(checkAuthStatus.fulfilled, (state, action) => {
        state.status = 'succeeded';
        const { authenticated, role, id } = action.payload || {};
        state.isAuthenticated = !!authenticated;
        state.role = authenticated ? role : null;
        state.userId = authenticated ? id : null;
      })
      .addCase(login.pending, (state) => {
        state.status = 'loading';
        state.error = null;
      })
      .addCase(login.fulfilled, (state, action) => {
        // ✅ แก้ไข: ดึงค่าจาก action.payload.user ตามที่ Go Backend ส่งมา
        if (action.payload.ok && action.payload.user) {
          state.status = 'succeeded';
          state.isAuthenticated = true;
          state.role = action.payload.user.role;
          state.userId = action.payload.user.id;
        }
      })
      .addCase(login.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload;
      })
      .addCase(logout.fulfilled, (state) => {
        state.isAuthenticated = false;
        state.role = null;
        state.userId = null;
      });
  }
});

export const { clearAuthError } = authSlice.actions;
export default authSlice.reducer;