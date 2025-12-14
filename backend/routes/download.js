// backend/routes/download.js
// Proxy downloads from PURE API (so we can delete backend/app folder safely)

const express = require('express');
const { Readable } = require('stream');

const router = express.Router();

function normalizeBaseUrl(u) {
  return String(u || '').replace(/\/+$/, '');
}

function getPureApiConfig() {
  const baseUrl = normalizeBaseUrl(process.env.PURE_API_BASE_URL);
  const apiKey = String(process.env.PURE_API_KEY || '');
  if (!baseUrl) {
    const err = new Error('PURE_API_BASE_URL is not set');
    err.status = 500;
    throw err;
  }
  if (!apiKey) {
    const err = new Error('PURE_API_KEY is not set');
    err.status = 500;
    throw err;
  }
  if (typeof fetch !== 'function') {
    const err = new Error('Global fetch() is not available. Please use Node.js 18+.');
    err.status = 500;
    throw err;
  }
  return { baseUrl, apiKey };
}

async function proxyDownload(res, purePath, fallbackFilename) {
  const { baseUrl, apiKey } = getPureApiConfig();
  const url = `${baseUrl}${purePath.startsWith('/') ? '' : '/'}${purePath}`;

  const upstream = await fetch(url, {
    method: 'GET',
    headers: {
      'x-api-key': apiKey,
    },
  });

  if (!upstream.ok) {
    // try read text for better error message
    let detail = '';
    try {
      detail = await upstream.text();
    } catch {}
    const err = new Error(
      `Pure API download failed (${upstream.status})${detail ? `: ${detail}` : ''}`
    );
    err.status = upstream.status;
    throw err;
  }

  // Forward useful headers
  const contentType = upstream.headers.get('content-type');
  const contentLength = upstream.headers.get('content-length');
  const contentDisposition = upstream.headers.get('content-disposition');

  if (contentType) res.setHeader('Content-Type', contentType);
  if (contentLength) res.setHeader('Content-Length', contentLength);

  // Ensure browser downloads as attachment
  if (contentDisposition) {
    res.setHeader('Content-Disposition', contentDisposition);
  } else {
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${fallbackFilename}"`
    );
  }

  // Stream body to client
  res.status(200);

  // Node 18+: convert web stream -> node stream
  if (upstream.body && typeof Readable.fromWeb === 'function') {
    Readable.fromWeb(upstream.body).pipe(res);
    return;
  }

  // Fallback: buffer
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.end(buf);
}

// GET /api/download/windows -> download from pure-api
router.get('/windows', async (_req, res, next) => {
  try {
    await proxyDownload(res, '/api/download/windows', 'MyAppSetup.exe');
  } catch (e) {
    next(e);
  }
});

// GET /api/download/android -> download from pure-api
router.get('/android', async (_req, res, next) => {
  try {
    await proxyDownload(res, '/api/download/android', 'app-release.apk');
  } catch (e) {
    next(e);
  }
});

module.exports = router;
