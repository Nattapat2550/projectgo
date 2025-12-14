const express = require('express');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const {
  createUserByEmail,
  findUserByEmail,
  setUsernameAndPassword,
  storeVerificationCode,
  validateAndConsumeCode,
  setOAuthUser,
  createPasswordResetToken,
  consumePasswordResetToken,
  setPassword,
} = require('../models/user');

const { sendEmail } = require('../utils/gmail');
const generateCode = require('../utils/generateCode');
const { setAuthCookie, clearAuthCookie } = require('../middleware/auth');

const router = express.Router();

function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '30d' },
  );
}

// ------ REGISTER ------
router.post('/register', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    const existing = await findUserByEmail(email);
    if (existing && existing.is_email_verified) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const user = existing || (await createUserByEmail(email));
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await storeVerificationCode(user.id, code, expiresAt);

    await sendEmail({
      to: email,
      subject: 'Your verification code',
      text: `Your code is ${code}. It expires in 10 minutes.`,
      html: `<p>Your code is <b>${code}</b>. It expires in 10 minutes.</p>`,
    });

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ------ VERIFY CODE ------
router.post('/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) {
      return res.status(400).json({ error: 'Missing email or code' });
    }

    const result = await validateAndConsumeCode(email, code);
    if (!result.ok) {
      if (result.reason === 'no_user') {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('verify-code error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ------ COMPLETE PROFILE ------
router.post('/complete-profile', async (req, res) => {
  try {
    const { email, username, password } = req.body || {};
    if (!email || !username || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (username.length < 3) {
      return res.status(400).json({ error: 'Username too short' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password too short' });
    }

    const updated = await setUsernameAndPassword(email, username, password);
    if (!updated) {
      return res.status(401).json({ error: 'Email not verified' });
    }

    const token = signToken(updated);
    setAuthCookie(res, token, true);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.error('complete-profile error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ------ LOGIN (EMAIL / PASSWORD) ------
router.post('/login', async (req, res) => {
  try {
    const { email, password, remember } = req.body || {};
    const user = await findUserByEmail(email || '');
    if (!user || !user.password_hash) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password || '', user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signToken(user);
    setAuthCookie(res, token, !!remember);
    res.json({ role: user.role });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/logout', async (_req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

// ------ GOOGLE OAUTH (WEB FLOW) ------

const GOOGLE_WEB_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID_WEB || process.env.GOOGLE_CLIENT_ID;
const GOOGLE_ANDROID_CLIENT_ID = process.env.GOOGLE_CLIENT_ID_ANDROID;

const oauth2ClientWeb = new google.auth.OAuth2(
  GOOGLE_WEB_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URI,
);

// เริ่ม OAuth บนเว็บ
router.get('/google', (req, res) => {
  const url = oauth2ClientWeb.generateAuthUrl({
    redirect_uri: process.env.GOOGLE_CALLBACK_URI,
    access_type: 'offline',
    prompt: 'consent',
    scope: ['openid', 'email', 'profile'],
  });
  res.redirect(url);
});

// callback จาก Google (เว็บ)
router.get('/google/callback', async (req, res) => {
  try {
    const { code } = req.query;

    const { tokens } = await oauth2ClientWeb.getToken({
      code,
      redirect_uri: process.env.GOOGLE_CALLBACK_URI,
    });
    oauth2ClientWeb.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2ClientWeb });
    const { data: info } = await oauth2.userinfo.get();

    const email = info.email;
    const oauthId = info.id;
    const picture = info.picture;
    const name = info.name;

    const user = await setOAuthUser({
      email,
      provider: 'google',
      oauthId,
      pictureUrl: picture,
      name,
    });

    const token = signToken(user);
    setAuthCookie(res, token, true);

    if (!user.username) {
      return res.redirect(
        `${process.env.FRONTEND_URL}/form?email=${encodeURIComponent(
          email,
        )}`,
      );
    }

    if (user.role === 'admin') {
      return res.redirect(`${process.env.FRONTEND_URL}/admin`);
    }
    return res.redirect(`${process.env.FRONTEND_URL}/home`);
  } catch (e) {
    console.error(
      'google callback error',
      e?.response?.data || e?.message || e,
    );
    return res.redirect(
      `${process.env.FRONTEND_URL}/login?error=oauth_failed`,
    );
  }
});

// ------ FORGOT / RESET PASSWORD ------

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: 'Missing email' });
    }

    const rawToken =
      uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    const user = await createPasswordResetToken(email, rawToken, expiresAt);

    if (user) {
      const link = `${process.env.FRONTEND_URL}/reset.html?token=${rawToken}`;
      await sendEmail({
        to: email,
        subject: 'Password reset',
        text: `Reset your password using this link (valid 30 minutes): ${link}`,
        html: `<p>Reset your password (valid 30 minutes): <a href="${link}">${link}</a></p>`,
      });
    }

    // ไม่บอกว่า email นี้มี user หรือไม่ (ป้องกัน enumeration)
    res.json({ ok: true });
  } catch (e) {
    console.error('forgot-password error', e);
    res.json({ ok: true });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password too short' });
    }

    const user = await consumePasswordResetToken(token);
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    await setPassword(user.id, newPassword);
    res.json({ ok: true });
  } catch (e) {
    console.error('reset-password error', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ------ GOOGLE LOGIN (MOBILE / FLUTTER) ------

router.post('/google-mobile', async (req, res) => {
  try {
    const { authCode } = req.body || {};
    if (!authCode) {
      return res.status(400).json({ error: 'Missing authCode' });
    }

    const webClientId =
      process.env.GOOGLE_CLIENT_ID_WEB || process.env.GOOGLE_CLIENT_ID;
    if (!webClientId || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error('Google web client or secret is not configured');
      return res
        .status(500)
        .json({ error: 'Google auth is not configured on server' });
    }

    // ใช้ Web client ID + secret ในการแลก authCode เป็น token
    const oauth2ClientMobile = new google.auth.OAuth2(
      webClientId,
      process.env.GOOGLE_CLIENT_SECRET,
      // ไม่ต้องใช้ callback URI แบบเว็บ
    );

    // สำหรับ authCode ที่มาจาก mobile ใช้ redirect_uri = 'postmessage'
    const { tokens } = await oauth2ClientMobile.getToken(authCode);


    oauth2ClientMobile.setCredentials(tokens);

    // ดึงข้อมูล profile ผู้ใช้จาก Google
    const oauth2 = google.oauth2({
      version: 'v2',
      auth: oauth2ClientMobile,
    });

    const { data: info } = await oauth2.userinfo.get();

    const email = info.email;
    const oauthId = info.id;
    const picture = info.picture;
    const name = info.name;

    if (!email) {
      return res.status(400).json({ error: 'No email from Google' });
    }

    // ใช้รูปแบบเดียวกับเว็บ
    const user = await setOAuthUser({
      email,
      provider: 'google',
      oauthId,
      pictureUrl: picture,
      name,
    });

    const token = signToken(user);
    setAuthCookie(res, token, true); // remember=true

    // mobile จะใช้ role ในการตัดสินจะไปหน้า admin หรือ home
    res.json({ role: user.role });
  } catch (e) {
    console.error('google-mobile error', e?.response?.data || e?.message || e);
    res.status(401).json({ error: 'Invalid Google auth' });
  }
});

router.get('/status', (req, res) => {
  const token = req.cookies?.token;
  if (!token) {
    // ยังไม่ล็อกอิน
    return res.json({ authenticated: false });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return res.json({
      authenticated: true,
      id: payload.id,
      role: payload.role || 'user'
    });
  } catch (e) {
    // token เสีย / หมดอายุ ให้ถือว่าไม่ล็อกอิน แต่ไม่ต้อง 401
    return res.json({ authenticated: false });
  }
});

module.exports = router;
