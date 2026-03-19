import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../api';

const initialState = {
  isAuthenticated: false,
  role: null,
  userId: null,
  status: 'idle',
  error: null
};

// เช็คสถานะจาก Cookie (ที่ Backend set ให้)
export const checkAuthStatus = createAsyncThunk(
  'auth/checkStatus',
  async (_, { rejectWithValue }) => {
    try {
      const res = await api.get('/api/auth/status');
      return res.data; // คาดหวัง { authenticated: true, id: ..., role: ... }
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || 'Failed to check auth status');
    }
  }
);

export const login = createAsyncThunk(
  'auth/login',
  async ({ email, password, remember }, { rejectWithValue }) => {
    try {
      const res = await api.post('/api/auth/login', { email, password, remember });
      // Backend คืน { ok: true, user: { id, role, ... } }
      return res.data;
    } catch (err) {
      return rejectWithValue(err.response?.data?.error || 'Login failed');
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
      return rejectWithValue(err.response?.data?.error || 'Logout failed');
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    clearAuthError(state) {
      state.error = null;
    },
    // ✅ เพิ่ม Reducer สำหรับรับข้อมูลจาก Google Login
    setCredentials(state, action) {
      const { id, role } = action.payload;
      state.isAuthenticated = true;
      state.role = role;
      state.userId = id;
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
      .addCase(login.fulfilled, (state, action) => {
        state.status = 'succeeded';
        // ปรับให้ตรงกับ Payload ของ AuthLogin ใน Go
        if (action.payload.ok) {
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

export const { clearAuthError, setCredentials } = authSlice.actions;
export default authSlice.reducer;