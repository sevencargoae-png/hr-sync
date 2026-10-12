/* خادم مزامنة منصة شؤون الموظفين — يخزّن قاعدة بيانات الشركة مشفّرة طرف-لطرف.
   السيرفر لا يرى البيانات إطلاقاً: يخزّن نصاً مشفّراً (blob) + غلاف المفاتيح (meta) فقط.
   المصادقة: توكن الشركة (COMPANY_TOKEN) مضمّن في التطبيق. تشفير البيانات بكلمة مرور الشركة عند العميل.

   Refactored: modular structure with security fixes (SSL, body limits, code splitting) */
'use strict';
const http = require('http');
const { init } = require('./lib/db');
const h = require('./lib/helpers');
const publicRoutes = require('./routes/public');
const adminRoutes = require('./routes/admin');
const syncRoutes = require('./routes/sync');

const PORT = process.env.PORT || 10000;
const VERSION = '1.4.0';

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return h.send(res, 204, {});

    const u = new URL(req.url, 'http://x');

    // Health check
    if (u.pathname === '/healthz' || u.pathname === '/') {
      return h.send(res, 200, { ok: true, service: 'hr-sync', ts: Date.now() });
    }

    const ip = h.ipOf(req);
    if (h.blocked(ip)) return h.send(res, 429, { ok: false, error: 'too-many-attempts' });

    // Public routes (signup, device ping, licensing) — no auth required
    const publicResult = await publicRoutes.handle(u, req, res, ip);
    if (publicResult !== false) return;

    // Everything below requires company token
    if (!h.authed(req)) { h.noteFail(ip); return h.send(res, 401, { ok: false, error: 'unauthorized' }); }

    // Admin routes (owner-signed: codes, signups, devices)
    const adminResult = await adminRoutes.handle(u, req, res, ip);
    if (adminResult !== false) return;

    // Sync & recovery routes
    const syncResult = await syncRoutes.handle(u, req, res, ip);
    if (syncResult !== false) return;

    return h.send(res, 404, { ok: false, error: 'not-found' });
  } catch (e) {
    console.error(e.message);
    return h.send(res, 500, { ok: false, error: 'server' });
  }
});

init()
  .then(() => server.listen(PORT, () => console.log('hr-sync on', PORT)))
  .catch(e => { console.error('init failed', e); process.exit(1); });

// ---------- graceful shutdown ----------
function shutdown(signal) {
  console.log(`${signal} received — shutting down`);
  server.close(async () => {
    try { const { pool } = require('./lib/db'); await pool.end(); } catch (_) { /* ignore */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 8000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
