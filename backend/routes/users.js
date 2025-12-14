// backend/routes/users.js
const express = require('express');
const { authenticateJWT, clearAuthCookie } = require('../middleware/auth');
const { updateProfile, deleteUser, findUserById } = require('../models/user');
const multer = require('multer');
const upload = multer({ limits: { fileSize: 2 * 1024 * 1024 } }); // 2MB

const router = express.Router();

router.get('/me', authenticateJWT, async (req, res) => {
  const u = await findUserById(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { id, username, email, role, profile_picture_url } = u;
  res.json({ id, username, email, role, profile_picture_url });
});

router.put('/me', authenticateJWT, async (req, res) => {
  try {
    const { username, profilePictureUrl } = req.body || {};
    const updated = await updateProfile(req.user.id, { username, profilePictureUrl });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    const { id, email, role, profile_picture_url } = updated;
    res.json({ id, username: updated.username, email, role, profile_picture_url });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.error('update profile error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

router.delete('/me', authenticateJWT, async (req, res) => {
  try {
    await deleteUser(req.user.id);
    // ลบบัญชีเสร็จแล้ว ให้ลบ cookie token ทิ้งด้วย เพื่อกัน loop index/home
    clearAuthCookie(res);
    res.status(204).end();
  } catch (e) {
    console.error('delete me error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// Avatar upload
router.post('/me/avatar', authenticateJWT, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const mime = req.file.mimetype;
    if (!/^image\/(png|jpe?g|gif|webp)$/.test(mime)) {
      return res.status(400).json({ error: 'Unsupported file type' });
    }
    const b64 = req.file.buffer.toString('base64');
    const dataUrl = `data:${mime};base64,${b64}`;
    const updated = await updateProfile(req.user.id, { profilePictureUrl: dataUrl });
    return res.json({ ok: true, profile_picture_url: updated.profile_picture_url });
  } catch (e) {
    console.error('upload avatar error', e);
    return res.status(500).json({ error: 'Upload failed' });
  }
});

module.exports = router;