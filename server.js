/* خادم مزامنة منصة شؤون الموظفين — يخزّن قاعدة بيانات الشركة مشفّرة طرف-لطرف.
   السيرفر لا يرى البيانات إطلاقاً: يخزّن نصاً مشفّراً (blob) + غلاف المفاتيح (meta) فقط.
   المصادقة: توكن الشركة (COMPANY_TOKEN) مضمّن في التطبيق. تشفير البيانات بكلمة مرور الشركة عند العميل. */
const http = require('http');
const { Pool } = require('pg');
const PORT = process.env.PORT || 10000;
const TOKEN = process.env.COMPANY_TOKEN || '';
const crypto = require('crypto');
const SERVER_SECRET = process.env.SERVER_SECRET || TOKEN; // لتشفير مفتاح الاسترداد أثناء التخزين
const SMTP = { host: process.env.SMTP_HOST || '', port: +(process.env.SMTP_PORT || 465), user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '', from: process.env.SMTP_FROM || process.env.SMTP_USER || '' };
const TEST_MODE = process.env.RECOVERY_TEST_MODE === '1'; // للاختبار فقط: يعيد الكود في الاستجابة بدل الإرسال
/* حدّ للمحاولات: 20 محاولة مصادقة فاشلة/10 دقائق لكل IP → حظر 15 دقيقة */
const fails = new Map();
function ipOf(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }
function blocked(ip) { const f = fails.get(ip); return f && f.until > Date.now(); }
function noteFail(ip) { const f = fails.get(ip) || { n: 0, first: Date.now(), until: 0 }; if (Date.now() - f.first > 600000) { f.n = 0; f.first = Date.now(); } f.n++; if (f.n >= 20) { f.until = Date.now() + 900000; f.n = 0; } fails.set(ip, f); }
function encSecret(b64) { const iv = crypto.randomBytes(12); const k = crypto.createHash('sha256').update(SERVER_SECRET).digest(); const c = crypto.createCipheriv('aes-256-gcm', k, iv); const enc = Buffer.concat([c.update(Buffer.from(b64, 'base64')), c.final()]); return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64'); }
function decSecret(s) { const buf = Buffer.from(s, 'base64'); const k = crypto.createHash('sha256').update(SERVER_SECRET).digest(); const d = crypto.createDecipheriv('aes-256-gcm', k, buf.subarray(0, 12)); d.setAuthTag(buf.subarray(12, 28)); return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('base64'); }
async function sendMail(to, subject, text) {
  if (TEST_MODE) return true;
  if (!SMTP.host || !SMTP.user) throw new Error('smtp-not-configured');
  const nodemailer = require('nodemailer');
  const t = nodemailer.createTransport({ host: SMTP.host, port: SMTP.port, secure: SMTP.port === 465, auth: { user: SMTP.user, pass: SMTP.pass } });
  await t.sendMail({ from: SMTP.from, to, subject, text }); return true;
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === '1' ? { rejectUnauthorized: false } : false, max: 4 });

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_store (
    id text PRIMARY KEY,
    meta jsonb,
    blob text,
    version integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text
  )`);
  await pool.query(`INSERT INTO hr_store (id, version) VALUES ('company', 0) ON CONFLICT (id) DO NOTHING`);
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_recovery (id text PRIMARY KEY, email text, escrow text, code_hash text, code_exp timestamptz, tries integer DEFAULT 0, updated_at timestamptz DEFAULT now())`);
  console.log('hr_store ready');
}

const send = (res, code, obj) => { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization,content-type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Cache-Control': 'no-store' }); res.end(b); };
const readBody = req => new Promise((resolve, reject) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 80 * 1024 * 1024) { reject(new Error('too-big')); req.destroy(); } else c.push(d); }); req.on('end', () => resolve(Buffer.concat(c))); req.on('error', reject); });
const authed = req => TOKEN && (req.headers.authorization || '') === 'Bearer ' + TOKEN;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/healthz' || u.pathname === '/') return send(res, 200, { ok: true, service: 'hr-sync', ts: Date.now() });
    const ip = ipOf(req); if (blocked(ip)) return send(res, 429, { ok: false, error: 'too-many-attempts' });
    if (!authed(req)) { noteFail(ip); return send(res, 401, { ok: false, error: 'unauthorized' }); }
    /* ---- استرداد كلمة مرور المدير بالإيميل ---- */
    if (u.pathname === '/recovery/enroll' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const email = String(b.email || '').trim().toLowerCase(); if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || typeof b.escrow !== 'string' || b.escrow.length < 20) return send(res, 400, { ok: false, error: 'bad-payload' });
      await pool.query(`INSERT INTO hr_recovery (id, email, escrow, updated_at) VALUES ('admin',$1,$2,now()) ON CONFLICT (id) DO UPDATE SET email=$1, escrow=$2, code_hash=NULL, code_exp=NULL, tries=0, updated_at=now()`, [email, encSecret(b.escrow)]);
      return send(res, 200, { ok: true, email });
    }
    if (u.pathname === '/recovery/status' && req.method === 'GET') { const { rows } = await pool.query(`SELECT email FROM hr_recovery WHERE id='admin'`); const em = rows[0] && rows[0].email; return send(res, 200, { ok: true, enrolled: !!em, emailMasked: em ? em.replace(/^(.).+(@.+)$/, '$1***$2') : null }); }
    if (u.pathname === '/recovery/request' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const email = String(b.email || '').trim().toLowerCase();
      const { rows } = await pool.query(`SELECT email FROM hr_recovery WHERE id='admin'`); if (!rows[0] || rows[0].email !== email) { noteFail(ip); return send(res, 200, { ok: true, sent: true }); } // لا نكشف هل الإيميل مسجّل
      const code = String(crypto.randomInt(100000, 999999)); const hash = crypto.createHash('sha256').update(code + SERVER_SECRET).digest('hex');
      await pool.query(`UPDATE hr_recovery SET code_hash=$1, code_exp=now() + interval '10 minutes', tries=0 WHERE id='admin'`, [hash]);
      try { await sendMail(email, 'رمز استرداد كلمة مرور منصة شؤون الموظفين', `رمز الاسترداد: ${code}\nصالح لمدة 10 دقائق. إن لم تطلب هذا، تجاهل الرسالة.`); } catch (e) { return send(res, 500, { ok: false, error: 'mail-failed' }); }
      return send(res, 200, { ok: true, sent: true, ...(TEST_MODE ? { code } : {}) });
    }
    if (u.pathname === '/recovery/verify' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const email = String(b.email || '').trim().toLowerCase(); const code = String(b.code || '').trim();
      const { rows } = await pool.query(`SELECT * FROM hr_recovery WHERE id='admin'`); const r = rows[0];
      if (!r || r.email !== email || !r.code_hash || !r.code_exp || new Date(r.code_exp) < new Date() || r.tries >= 5) { noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
      const hash = crypto.createHash('sha256').update(code + SERVER_SECRET).digest('hex');
      if (hash !== r.code_hash) { await pool.query(`UPDATE hr_recovery SET tries=tries+1 WHERE id='admin'`); noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
      await pool.query(`UPDATE hr_recovery SET code_hash=NULL, code_exp=NULL, tries=0 WHERE id='admin'`);
      return send(res, 200, { ok: true, escrow: decSecret(r.escrow) });
    }

    if (u.pathname === '/sync/pull' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT meta, blob, version, updated_at, updated_by FROM hr_store WHERE id=$1', ['company']);
      const r = rows[0] || { version: 0 };
      return send(res, 200, { ok: true, version: r.version || 0, meta: r.meta || null, blob: r.blob || null, updatedAt: r.updated_at || null, updatedBy: r.updated_by || null, empty: !r.blob });
    }
    if (u.pathname === '/sync/push' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString() || '{}');
      const { expectedVersion, meta, blob, by } = body;
      if (typeof blob !== 'string' || !meta) return send(res, 400, { ok: false, error: 'bad-payload' });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const cur = (await client.query('SELECT version FROM hr_store WHERE id=$1 FOR UPDATE', ['company'])).rows[0];
        const curV = cur ? cur.version : 0;
        if (typeof expectedVersion === 'number' && expectedVersion !== curV) { await client.query('ROLLBACK'); return send(res, 409, { ok: false, conflict: true, version: curV }); }
        const nv = curV + 1;
        await client.query('UPDATE hr_store SET meta=$1, blob=$2, version=$3, updated_at=now(), updated_by=$4 WHERE id=$5', [meta, blob, nv, String(by || '').slice(0, 80), 'company']);
        await client.query('COMMIT');
        return send(res, 200, { ok: true, version: nv });
      } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    }
    // تغيير غلاف كلمة المرور فقط (بدون رفع بيانات) — لتغيير كلمة مرور الشركة
    if (u.pathname === '/sync/meta' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)).toString() || '{}');
      if (!body.meta) return send(res, 400, { ok: false, error: 'bad-payload' });
      const { rows } = await pool.query('UPDATE hr_store SET meta=$1, version=version+1, updated_at=now(), updated_by=$2 WHERE id=$3 RETURNING version', [body.meta, String(body.by || '').slice(0, 80), 'company']);
      return send(res, 200, { ok: true, version: rows[0].version });
    }
    return send(res, 404, { ok: false, error: 'not-found' });
  } catch (e) { console.error(e.message); return send(res, 500, { ok: false, error: 'server' }); }
});
init().then(() => server.listen(PORT, () => console.log('hr-sync on', PORT))).catch(e => { console.error('init failed', e); process.exit(1); });
