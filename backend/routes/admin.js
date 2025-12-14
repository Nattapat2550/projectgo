const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// IMPORTANT: no direct DB. Use pure-api through model.
const { adminUpdateUser } = require('../models/user');

// Simple JWT check (kept same style)
// If you already have middleware, keep using it—this file doesn’t change structure.
function requireAdmin(req, res, next) {
  try {
    const token =
      req.cookies?.token ||
      (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

    if (!token) {
      return res.status(401).json({ error: true, message: 'No token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded || !decoded.is_admin) {
      return res.status(403).json({ error: true, message: 'Admin only' });
    }

    req.user = decoded;
    return next();
  } catch (err) {
    err.status = 401;
    return next(err);
  }
}

// Admin update user
router.post('/users/update', requireAdmin, async (req, res, next) => {
  try {
    const { id, ...payload } = req.body || {};
    if (!id) {
      return res.status(400).json({ error: true, message: 'Missing user id' });
    }

    const updated = await adminUpdateUser(id, payload);
    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// Example: (optional) you can add more admin endpoints that call pure-api internal admin endpoints.

module.exports = router;
