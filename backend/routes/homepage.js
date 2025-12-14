const express = require('express');
const router = express.Router();

// IMPORTANT: Use pure-api only (no direct DB)
const { get, post } = require('../utils/pureApiClient');

// GET homepage content
router.get('/', async (req, res, next) => {
  try {
    const data = await get('/api/internal/homepage');
    res.json(data);
  } catch (err) {
    next(err);
  }
});

// UPDATE homepage content (admin or authorized)
router.post('/update', async (req, res, next) => {
  try {
    const payload = req.body || {};
    const data = await post('/api/internal/homepage/update', payload);
    res.json(data);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
