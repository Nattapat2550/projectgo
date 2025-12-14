// backend/utils/pureApiClient.js

function normalizeBaseUrl(u) {
  return String(u || '').replace(/\/+$/, '');
}

function getCfg() {
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
    const err = new Error('Global fetch() is not available. Use Node 18+ on Render.');
    err.status = 500;
    throw err;
  }
  return { baseUrl, apiKey };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isTransientStatus(code) {
  return code === 502 || code === 503 || code === 504;
}

async function request(path, { method = 'GET', body, headers } = {}) {
  const { baseUrl, apiKey } = getCfg();
  const url = `${baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;

  const maxAttempts = 3;
  let lastErr = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeoutMs = 25000;
    const t = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        method,
        headers: {
          'x-api-key': apiKey,
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(headers || {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });

      // ถ้า pure-api กำลังตื่น มักเจอ 502/503/504 ให้ retry
      if (!res.ok && isTransientStatus(res.status) && attempt < maxAttempts) {
        await sleep(1200 * Math.pow(2, attempt - 1));
        continue;
      }

      const text = await res.text();
      let json = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = null;
      }

      if (!res.ok) {
        const msg =
          json?.error?.message ||
          json?.message ||
          json?.error ||
          `Pure API error (${res.status})`;

        const err = new Error(msg);
        err.status = res.status;
        err.payload = json || text;
        throw err;
      }

      return json;
    } catch (err) {
      lastErr = err;

      // network fail / timeout / aborted => ถือว่า transient
      const transient =
        err?.name === 'AbortError' ||
        /fetch failed/i.test(err?.message || '') ||
        /ECONNRESET|ENOTFOUND|ECONNREFUSED/i.test(err?.message || '');

      if (transient && attempt < maxAttempts) {
        await sleep(1200 * Math.pow(2, attempt - 1));
        continue;
      }

      // ถ้าเป็น transient แต่สุดท้ายยังไม่มา ให้ตอบ 503 (แทน 500)
      if (transient) {
        const e = new Error('Pure API is waking up. Please try again in a moment.');
        e.status = 503;
        throw e;
      }

      throw err;
    } finally {
      clearTimeout(t);
    }
  }

  throw lastErr || new Error('Unknown error');
}

module.exports = {
  request,
  get: (path) => request(path, { method: 'GET' }),
  post: (path, body) => request(path, { method: 'POST', body }),
};