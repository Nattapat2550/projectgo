const express = require('express');
const { listCarouselItems } = require('../models/carousel');
const router = express.Router();

// Public list for homepage
router.get('/', async (_req, res) => {
  const items = await listCarouselItems();
  res.json(items);
});

module.exports = router;
