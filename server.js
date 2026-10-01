/* خادم مزامنة منصة شؤون الموظفين — يخزّن قاعدة بيانات الشركة مشفّرة طرف-لطرف.
   السيرفر لا يرى البيانات إطلاقاً: يخزّن نصاً مشفّراً (blob) + غلاف المفاتيح (meta) فقط.
   المصادقة: توكن الشركة (COMPANY_TOKEN) مضمّن في التطبيق. تشفير البيانات بكلمة مرور الشركة عند العميل. */
const http = require('http');
const { Pool } = require('pg');
const PORT = process.env.PORT || 10000;
const TOKEN = process.env.COMPANY_TOKEN || '';
const crypto = require('crypto');
const { MODULES, PLANS, resolveModules } = require('./plans');
const VERSION = '1.3.0';
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

/* ---------- الترخيص: التوقيع والتحقق من المالك ---------- */
const b64u = { enc: b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), dec: s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64') };
let SIGN_KEY = null, SIGN_PUB = null;
try { if (process.env.SIGN_PRIVATE_KEY) { SIGN_KEY = crypto.createPrivateKey({ key: Buffer.from(process.env.SIGN_PRIVATE_KEY.trim(), 'base64'), type: 'pkcs8', format: 'der' }); SIGN_PUB = crypto.createPublicKey(SIGN_KEY); } } catch (e) { console.error('SIGN_PRIVATE_KEY invalid'); }
function signLicense(payload) { const p = Buffer.from(JSON.stringify(payload)); return b64u.enc(p) + '.' + b64u.enc(crypto.sign(null, p, SIGN_KEY)); }
/* المالك يوقّع كل طلب إداري بمفتاحه الخاص (Ed25519) — لأن رمز الشركة موجود في كل نسخة مثبّتة ولا يصلح وحده للصلاحيات الإدارية */
const seenSigs = new Map();
function ownerOk(req, path, bodyText) {
  if (!SIGN_PUB) return false;
  const ts = +req.headers['x-owner-ts'], sig = String(req.headers['x-owner-sig'] || '');
  if (!ts || Math.abs(Date.now() - ts) > 300000 || !sig || seenSigs.has(sig)) return false;
  const msg = Buffer.from(req.method + ' ' + path + '\n' + ts + '\n' + bodyText);
  let ok = false; try { ok = crypto.verify(null, msg, SIGN_PUB, b64u.dec(sig)); } catch { }
  if (ok) { seenSigs.set(sig, ts); for (const [k, v] of seenSigs) if (Date.now() - v > 600000) seenSigs.delete(k); }
  return ok;
}
const signupRate = new Map();
const MACHINE_RE = /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/;
const CODE_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genCode() { const b = crypto.randomBytes(12); let o = ''; for (let i = 0; i < 12; i++) { o += CODE_ALPHA[b[i] % CODE_ALPHA.length]; if (i === 3 || i === 7) o += '-'; } return o; }
const todayStr = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => new Date(new Date(d).getTime() + n * 86400000).toISOString().slice(0, 10);
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
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_codes (code text PRIMARY KEY, name text, plan text, modules jsonb, max_uses integer NOT NULL DEFAULT 1, valid_days integer, expires date, revoked boolean NOT NULL DEFAULT false, created_at timestamptz DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_activations (code text NOT NULL, machine text NOT NULL, name text, serial text, lic_id text, lic_expires date, at timestamptz DEFAULT now(), last_check timestamptz, PRIMARY KEY (code, machine))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_signups (id text PRIMARY KEY, kind text NOT NULL DEFAULT 'trial', machine text NOT NULL, company text, person text, activity text, phone text, username text, email text, status text NOT NULL DEFAULT 'pending', approve_code text, tries integer DEFAULT 0, terms text, terms_at timestamptz, note text, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())`);
  console.log('hr_store ready');
}

const send = (res, code, obj) => { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization,content-type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Cache-Control': 'no-store' }); res.end(b); };
const readBody = req => new Promise((resolve, reject) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 80 * 1024 * 1024) { reject(new Error('too-big')); req.destroy(); } else c.push(d); }); req.on('end', () => resolve(Buffer.concat(c))); req.on('error', reject); });
const authed = req => TOKEN && (req.headers.authorization || '') === 'Bearer ' + TOKEN;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/healthz' || u.pathname === '/') return send(res, 200, { ok: true, service: 'hr-sync', version: VERSION, license: !!SIGN_KEY, recovery: 'email', mail: !!(SMTP.host && SMTP.user), ts: Date.now() });
    const ip = ipOf(req); if (blocked(ip)) return send(res, 429, { ok: false, error: 'too-many-attempts' });
    /* ---- طلبات التسجيل/الشراء من العملاء الجدد (عامة، محدودة المعدّل) ---- */
    if (u.pathname === '/signup/request' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const machine = String(b.machine || '').trim().toUpperCase();
      const kind = b.kind === 'purchase' ? 'purchase' : 'trial'; const clip = (v, n) => String(v || '').trim().slice(0, n);
      if (!MACHINE_RE.test(machine) || clip(b.company, 120).length < 2 || clip(b.person, 120).length < 2 || clip(b.phone, 40).length < 5) { noteFail(ip); return send(res, 400, { ok: false, why: 'bad-payload' }); }
      const rl = signupRate.get(ip) || { n: 0, first: Date.now() }; if (Date.now() - rl.first > 3600000) { rl.n = 0; rl.first = Date.now(); } if (++rl.n > 8) return send(res, 429, { ok: false, why: 'busy' }); signupRate.set(ip, rl);
      const old = (await pool.query(`SELECT id, status FROM hr_signups WHERE machine=$1 AND kind=$2 AND status IN ('pending','approved') ORDER BY created_at DESC LIMIT 1`, [machine, kind])).rows[0];
      if (old && kind === 'purchase') { await pool.query(`UPDATE hr_signups SET company=$2, person=$3, activity=$4, phone=$5, username=$6, email=$7, updated_at=now() WHERE id=$1`, [old.id, clip(b.company, 120), clip(b.person, 120), clip(b.activity, 300), clip(b.phone, 40), clip(b.username, 60), clip(b.email, 120)]); return send(res, 200, { ok: true, id: old.id, status: old.status }); }
      const id = crypto.randomBytes(8).toString('hex');
      await pool.query(`INSERT INTO hr_signups (id, kind, machine, company, person, activity, phone, username, email) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [id, kind, machine, clip(b.company, 120), clip(b.person, 120), clip(b.activity, 300), clip(b.phone, 40), clip(b.username, 60), clip(b.email, 120)]);
      return send(res, 200, { ok: true, id, status: 'pending' });
    }
    if (u.pathname === '/signup/status' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const r = (await pool.query('SELECT status FROM hr_signups WHERE id=$1 AND machine=$2', [String(b.id || ''), String(b.machine || '').toUpperCase()])).rows[0];
      if (!r) { noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); } return send(res, 200, { ok: true, status: r.status });
    }
    if (u.pathname === '/signup/verify' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const code = String(b.code || '').trim().toUpperCase().replace(/\s/g, '');
      const r = (await pool.query('SELECT * FROM hr_signups WHERE id=$1 AND machine=$2', [String(b.id || ''), String(b.machine || '').toUpperCase()])).rows[0];
      if (!r || r.status === 'rejected') { noteFail(ip); return send(res, 200, { ok: false, why: r ? 'rejected' : 'invalid' }); }
      if (r.status === 'pending') return send(res, 200, { ok: false, why: 'pending' });
      if (r.tries >= 8) return send(res, 200, { ok: false, why: 'locked' });
      if (!r.approve_code || code !== r.approve_code) { await pool.query('UPDATE hr_signups SET tries=tries+1 WHERE id=$1', [r.id]); noteFail(ip); return send(res, 200, { ok: false, why: 'code' }); }
      await pool.query(`UPDATE hr_signups SET status='active', updated_at=now() WHERE id=$1 AND status='approved'`, [r.id]);
      return send(res, 200, { ok: true });
    }
    if (u.pathname === '/signup/terms' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const t = b.accepted ? 'accepted' : 'rejected';
      const r = await pool.query(`UPDATE hr_signups SET terms=$3, terms_at=now(), updated_at=now() WHERE id=$1 AND machine=$2 RETURNING id`, [String(b.id || ''), String(b.machine || '').toUpperCase(), t]);
      return send(res, 200, { ok: !!r.rows[0] });
    }
    /* ---- نقاط الترخيص العامة (بدون رمز الشركة؛ محمية بالكود نفسه + حدّ المحاولات) ---- */
    if (u.pathname === '/license/plans' && req.method === 'GET') return send(res, 200, { ok: true, modules: MODULES, plans: PLANS });
    if (u.pathname === '/license/activate' && req.method === 'POST') {
      if (!SIGN_KEY) return send(res, 503, { ok: false, why: 'not-configured' });
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const code = String(b.code || '').trim().toUpperCase(); const machine = String(b.machine || '').trim().toUpperCase();
      if (!/^[A-Z2-9]{4}(-[A-Z2-9]{4}){2}$/.test(code) || !MACHINE_RE.test(machine)) { noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const row = (await client.query('SELECT * FROM hr_codes WHERE code=$1 FOR UPDATE', [code])).rows[0];
        if (!row) { await client.query('ROLLBACK'); noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
        if (row.revoked) { await client.query('ROLLBACK'); return send(res, 200, { ok: false, why: 'revoked' }); }
        const prev = (await client.query('SELECT serial, lic_expires FROM hr_activations WHERE code=$1 AND machine=$2', [code, machine])).rows[0];
        if (prev) { await client.query('UPDATE hr_activations SET last_check=now() WHERE code=$1 AND machine=$2', [code, machine]); await client.query('COMMIT'); return send(res, 200, { ok: true, serial: prev.serial, again: true }); }
        if (row.expires && String(row.expires.toISOString ? row.expires.toISOString().slice(0, 10) : row.expires) < todayStr()) { await client.query('ROLLBACK'); return send(res, 200, { ok: false, why: 'expired' }); }
        const used = +(await client.query('SELECT count(*)::int AS n FROM hr_activations WHERE code=$1', [code])).rows[0].n;
        if (used >= row.max_uses) { await client.query('ROLLBACK'); return send(res, 200, { ok: false, why: 'used-up' }); }
        const licExp = row.valid_days ? addDays(todayStr(), row.valid_days) : null;
        const id = crypto.randomBytes(4).toString('hex').toUpperCase();
        const mods = resolveModules(row.plan, row.modules) || Object.keys(MODULES);
        const serial = signLicense({ name: String(b.name || row.name || '').slice(0, 120), machine, expires: licExp, seats: 1, plan: row.plan || 'custom', modules: mods, issued: todayStr(), id, code });
        await client.query('INSERT INTO hr_activations (code, machine, name, serial, lic_id, lic_expires, last_check) VALUES ($1,$2,$3,$4,$5,$6,now())', [code, machine, String(b.name || '').slice(0, 120), serial, id, licExp]);
        await client.query('COMMIT');
        return send(res, 200, { ok: true, serial, plan: row.plan, modules: mods, expires: licExp });
      } catch (e) { await client.query('ROLLBACK').catch(() => { }); throw e; } finally { client.release(); }
    }
    /* فحص الإلغاء (يستدعيه التطبيق بصمت عند وجود إنترنت) */
    if (u.pathname === '/license/check' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}'); const code = String(b.code || '').trim().toUpperCase(); const machine = String(b.machine || '').trim().toUpperCase();
      if (!/^[A-Z2-9]{4}(-[A-Z2-9]{4}){2}$/.test(code) || !MACHINE_RE.test(machine)) { noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
      const { rows } = await pool.query('SELECT c.revoked FROM hr_codes c JOIN hr_activations a ON a.code=c.code WHERE c.code=$1 AND a.machine=$2', [code, machine]);
      if (!rows[0]) { noteFail(ip); return send(res, 200, { ok: false, why: 'invalid' }); }
      await pool.query('UPDATE hr_activations SET last_check=now() WHERE code=$1 AND machine=$2', [code, machine]);
      return send(res, 200, { ok: true, revoked: !!rows[0].revoked });
    }
    if (!authed(req)) { noteFail(ip); return send(res, 401, { ok: false, error: 'unauthorized' }); }
    /* ---- إدارة الأكواد (المالك فقط: رمز الشركة + توقيع المالك) ---- */
    if (['/license/newcode', '/license/codes', '/license/revoke', '/signup/list', '/signup/approve', '/signup/reject', '/signup/done'].includes(u.pathname)) {
      const bodyText = req.method === 'POST' ? (await readBody(req)).toString() : '';
      if (!ownerOk(req, u.pathname, bodyText)) { noteFail(ip); return send(res, 403, { ok: false, why: 'owner-only' }); }
      const b = bodyText ? JSON.parse(bodyText) : {};
      if (u.pathname === '/signup/list') { const { rows } = await pool.query('SELECT id, kind, machine, company, person, activity, phone, username, email, status, terms, terms_at, note, created_at, updated_at FROM hr_signups ORDER BY created_at DESC LIMIT 300'); return send(res, 200, { ok: true, items: rows, pending: rows.filter(x => x.status === 'pending').length }); }
      if (u.pathname === '/signup/approve') {
        const id = String(b.id || ''); const code = genCode().replace(/-/g, '').slice(0, 6);
        const r = await pool.query(`UPDATE hr_signups SET status='approved', approve_code=COALESCE(approve_code,$2), updated_at=now() WHERE id=$1 AND status IN ('pending','approved') RETURNING approve_code`, [id, code]);
        return send(res, 200, r.rows[0] ? { ok: true, code: r.rows[0].approve_code } : { ok: false, why: 'not-found' });
      }
      if (u.pathname === '/signup/reject') { const r = await pool.query(`UPDATE hr_signups SET status='rejected', note=$2, updated_at=now() WHERE id=$1 RETURNING id`, [String(b.id || ''), String(b.note || '').slice(0, 300)]); return send(res, 200, { ok: !!r.rows[0] }); }
      if (u.pathname === '/signup/done') { const r = await pool.query(`UPDATE hr_signups SET status='done', note=$2, updated_at=now() WHERE id=$1 RETURNING id`, [String(b.id || ''), String(b.note || '').slice(0, 300)]); return send(res, 200, { ok: !!r.rows[0] }); }
      if (u.pathname === '/license/newcode') {
        const plan = PLANS[b.plan] ? b.plan : (Array.isArray(b.modules) && b.modules.length ? 'custom' : null);
        if (!plan) return send(res, 200, { ok: false, why: 'bad-plan' });
        const mods = resolveModules(plan, b.modules); if (!mods) return send(res, 200, { ok: false, why: 'bad-plan' });
        const maxUses = Math.min(500, Math.max(1, Math.floor(+b.max_uses || 1)));
        const validDays = b.valid_days ? Math.min(3650, Math.max(1, Math.floor(+b.valid_days))) : null;
        const exp = b.expires && /^\d{4}-\d{2}-\d{2}$/.test(b.expires) ? b.expires : null;
        const name = String(b.name || '').slice(0, 120);
        for (let i = 0; i < 5; i++) {
          const code = genCode();
          const r = await pool.query('INSERT INTO hr_codes (code, name, plan, modules, max_uses, valid_days, expires) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING code', [code, name, plan, JSON.stringify(mods), maxUses, validDays, exp]);
          if (r.rows[0]) return send(res, 200, { ok: true, code, name, plan, modules: mods, max_uses: maxUses, valid_days: validDays, expires: exp });
        }
        return send(res, 500, { ok: false, error: 'server' });
      }
      if (u.pathname === '/license/codes') {
        const { rows } = await pool.query(`SELECT c.code, c.name, c.plan, c.modules, c.max_uses, c.valid_days, c.expires, c.revoked, c.created_at,
          COALESCE((SELECT json_agg(json_build_object('machine', a.machine, 'name', a.name, 'at', a.at, 'last_check', a.last_check, 'lic_expires', a.lic_expires) ORDER BY a.at) FROM hr_activations a WHERE a.code=c.code), '[]'::json) AS devices
          FROM hr_codes c ORDER BY c.created_at DESC LIMIT 500`);
        return send(res, 200, { ok: true, codes: rows.map(r => ({ code: r.code, name: r.name, plan: r.plan, modules: r.modules, max_uses: r.max_uses, valid_days: r.valid_days, expires: r.expires ? new Date(r.expires).toISOString().slice(0, 10) : null, revoked: r.revoked, created_at: r.created_at, used: r.devices.length, devices: r.devices })) });
      }
      if (u.pathname === '/license/revoke') {
        const code = String(b.code || '').trim().toUpperCase(); const revoked = b.revoked !== false;
        const r = await pool.query('UPDATE hr_codes SET revoked=$2 WHERE code=$1 RETURNING code', [code, revoked]);
        return send(res, 200, { ok: !!r.rows[0], revoked });
      }
    }
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
