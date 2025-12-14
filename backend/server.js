const path = require('path');

// Load env:
// - Prefer backend/.env when present
// - Otherwise load project root .env (../.env) to match the "docker" style setup
require('dotenv').config();
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const homepageRoutes = require('./routes/homepage');
const carouselRoutes = require('./routes/carousel');
const downloadRoutes = require('./routes/download');

const app = express();

// ถ้าอยู่หลัง proxy (เช่น Render, Nginx) ต้องเปิด trust proxy เพื่อให้ secure cookie / rate-limit ใช้ IP จริง
app.set('trust proxy', 1);

// 1) ใส่ security headers พื้นฐาน
app.use(helmet());

// 2) ใส่ security headers เพิ่มเติม
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      // ปรับตามที่โปรเจกต์ต้องใช้ ถ้าฟรอนต์มี CDN ค่อยเพิ่ม
      'script-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'", 'https:'],
    },
  })
);

// 3) gzip ลดขนาด response
app.use(compression());

// 4) CORS
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// 5) body parser + cookies
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 6) rate limit ป้องกันยิงถี่
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// 7) routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/homepage', homepageRoutes);
app.use('/api/carousel', carouselRoutes);
app.use('/api/download', downloadRoutes);

// 8) health check
app.get('/health', (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || 'unknown' });
});

// 9) error handler
app.use((err, req, res, next) => {
  const status = err.status || 500;

  // ปลอดภัย: ไม่ log secrets
  console.error('[SERVER ERROR]', {
    status,
    message: err.message,
    path: req.path,
  });

  res.status(status).json({
    error: true,
    message: err.message || 'Internal Server Error',
    status,
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
