// backend/models/user.js
// IMPORTANT: backend must NOT query Postgres directly.
// All DB operations must go through pure-api (/api/internal/*)

const { get, post } = require('../utils/pureApiClient');

// helper: unwrap { ok:true, data } -> data
function unwrapData(resp) {
  return resp && resp.ok === true ? resp.data : null;
}

// ---------- USERS ----------
async function createUserByEmail(email) {
  const resp = await post('/api/internal/create-user-email', { email });
  return unwrapData(resp);
}

async function findUserByEmail(email) {
  const resp = await post('/api/internal/find-user', { email });
  return unwrapData(resp);
}

async function findUserById(id) {
  const resp = await post('/api/internal/find-user', { id });
  return unwrapData(resp);
}

async function findUserByOAuth(provider, oauthId) {
  const resp = await post('/api/internal/find-user', { provider, oauthId });
  return unwrapData(resp);
}

// เดิมเคยมี markEmailVerified(userId) แต่ pure-api ทำใน verify-code อยู่แล้ว
async function markEmailVerified(_userId) {
  return true;
}

// ---------- AUTH / VERIFY ----------
async function storeVerificationCode(userId, code, expiresAt) {
  // expiresAt จะส่งเป็น Date ก็ได้ (JSON serialize เป็น string) หรือส่งเป็น ISO string
  await post('/api/internal/store-verification-code', { userId, code, expiresAt });
  return true;
}

async function validateAndConsumeCode(email, code) {
  // pure-api route นี้ return result ตรง ๆ: { ok:true,userId } หรือ { ok:false, reason }
  return post('/api/internal/verify-code', { email, code });
}

async function setUsernameAndPassword(email, username, password) {
  const resp = await post('/api/internal/set-username-password', {
    email,
    username,
    password, // ส่ง raw ได้เลย เพราะ pure-api hash ให้
  });
  return unwrapData(resp);
}

async function setOAuthUser({ email, provider, oauthId, pictureUrl, name }) {
  const resp = await post('/api/internal/set-oauth-user', {
    email,
    provider,
    oauthId,
    pictureUrl,
    name,
  });
  return unwrapData(resp);
}

// ---------- PROFILE ----------
async function updateProfile(userId, { username, profilePictureUrl }) {
  // ใช้ internal admin update เป็น “ทางเดียว” ที่ pure-api เปิดให้แก้ profile ผ่าน apiKey
  const resp = await post('/api/internal/admin/users/update', {
    id: userId,
    username: username ?? null,
    profile_picture_url: profilePictureUrl ?? null,
  });
  return unwrapData(resp);
}

async function deleteUser(userId) {
  await post('/api/internal/delete-user', { id: userId });
  return true;
}

async function getAllUsers() {
  const resp = await get('/api/internal/admin/users');
  return unwrapData(resp) || [];
}

// ---------- RESET PASSWORD ----------
async function createPasswordResetToken(email, token, expiresAt) {
  const resp = await post('/api/internal/create-reset-token', { email, token, expiresAt });
  return unwrapData(resp);
}

async function consumePasswordResetToken(rawToken) {
  const resp = await post('/api/internal/consume-reset-token', { token: rawToken });
  return unwrapData(resp);
}

async function setPassword(userId, newPassword) {
  const resp = await post('/api/internal/set-password', { userId, newPassword });
  return unwrapData(resp);
}

module.exports = {
  createUserByEmail,
  findUserByEmail,
  findUserById,
  findUserByOAuth,

  markEmailVerified,
  setUsernameAndPassword,
  updateProfile,
  deleteUser,
  getAllUsers,

  storeVerificationCode,
  validateAndConsumeCode,
  setOAuthUser,

  createPasswordResetToken,
  consumePasswordResetToken,
  setPassword,
};
