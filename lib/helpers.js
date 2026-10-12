/* أدوات مساعدة — تشفير، بريد، حدّ محاولات، أدوات عامة */
'use strict';
const crypto = require('crypto');

const SERVER_SECRET = process.env.SERVER_SECRET || process.env.COMPANY_TOKEN || '';
const TOKEN = process.env.COMPANY_TOKEN || '';
const TEST_MODE = process.env.RECOVERY_TEST_MODE === '1';
const SMTP = {
  host: process.env.SMTP_HOST || '',
  port: +(process.env.SMTP_PORT || 465),
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  from: process.env.SMTP_FROM || process.env.SMTP_USER || '',
};

const MACHINE_RE = /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/;
const CODE_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/* ---------- حدّ المحاولات: 20 فاشلة/10 دقائق → حظر 15 دقيقة ---------- */
const fails = new Map();
function ipOf(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }
function blocked(ip) { const f = fails.get(ip); return f && f.until > Date.now(); }
function noteFail(ip) {
  const f = fails.get(ip) || { n: 0, first: Date.now(), until: 0 };
  if (Date.now() - f.first > 600000) { f.n = 0; f.first = Date.now(); }
  f.n++;
  if (f.n >= 20) { f.until = Date.now() + 900000; f.n = 0; }
  fails.set(ip, f);
}

/* ---------- تشفير مفتاح الاسترداد ---------- */
function encSecret(b64) {
  const iv = crypto.randomBytes(12);
  const k = crypto.createHash('sha256').update(SERVER_SECRET).digest();
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  const enc = Buffer.concat([c.update(Buffer.from(b64, 'base64')), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decSecret(s) {
  const buf = Buffer.from(s, 'base64');
  const k = crypto.createHash('sha256').update(SERVER_SECRET).digest();
  const d = crypto.createDecipheriv('aes-256-gcm', k, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('base64');
}

/* ---------- بريد إلكتروني ---------- */
async function sendMail(to, subject, text) {
  if (TEST_MODE) return true;
  if (!SMTP.host || !SMTP.user) throw new Error('smtp-not-configured');
  const nodemailer = require('nodemailer');
  const t = nodemailer.createTransport({ host: SMTP.host, port: SMTP.port, secure: SMTP.port === 465, auth: { user: SMTP.user, pass: SMTP.pass } });
  await t.sendMail({ from: SMTP.from, to, subject, text });
  return true;
}

/* ---------- الترخيص: التوقيع والتحقق من المالك ---------- */
const b64u = {
  enc: b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
};
let SIGN_KEY = null, SIGN_PUB = null;
try {
  if (process.env.SIGN_PRIVATE_KEY) {
    SIGN_KEY = crypto.createPrivateKey({ key: Buffer.from(process.env.SIGN_PRIVATE_KEY.trim(), 'base64'), type: 'pkcs8', format: 'der' });
    SIGN_PUB = crypto.createPublicKey(SIGN_KEY);
  }
} catch (e) { console.error('SIGN_PRIVATE_KEY invalid'); }

function signLicense(payload) {
  const p = Buffer.from(JSON.stringify(payload));
  return b64u.enc(p) + '.' + b64u.enc(crypto.sign(null, p, SIGN_KEY));
}

const seenSigs = new Map();
function ownerOk(req, path, bodyText) {
  if (!SIGN_PUB) return false;
  const ts = +req.headers['x-owner-ts'], sig = String(req.headers['x-owner-sig'] || '');
  if (!ts || Math.abs(Date.now() - ts) > 300000 || !sig || seenSigs.has(sig)) return false;
  const msg = Buffer.from(req.method + ' ' + path + '\n' + ts + '\n' + bodyText);
  let ok = false;
  try { ok = crypto.verify(null, msg, SIGN_PUB, b64u.dec(sig)); } catch { }
  if (ok) { seenSigs.set(sig, ts); for (const [k, v] of seenSigs) if (Date.now() - v > 600000) seenSigs.delete(k); }
  return ok;
}

/* ---------- أدوات عامة ---------- */
const signupRate = new Map();
function genCode() { const b = crypto.randomBytes(12); let o = ''; for (let i = 0; i < 12; i++) { o += CODE_ALPHA[b[i] % CODE_ALPHA.length]; if (i === 3 || i === 7) o += '-'; } return o; }
const todayStr = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => new Date(new Date(d).getTime() + n * 86400000).toISOString().slice(0, 10);
const clip = (v, n) => String(v || '').trim().slice(0, n);
const clipNull = (v, n) => (v === undefined || v === null) ? null : String(v).slice(0, n);
const authed = req => TOKEN && (req.headers.authorization || '') === 'Bearer ' + TOKEN;

/* ---------- HTTP helpers ---------- */
const send = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': b.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization,content-type,x-owner-ts,x-owner-sig',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Cache-Control': 'no-store',
  });
  res.end(b);
};

// Per-route body limits (FIX: was 80MB global!)
// sync/push needs large bodies (encrypted company data), others are small JSON
const BODY_LIMITS = {
  '/sync/push': 10 * 1024 * 1024,  // 10MB — encrypted company database
  '/sync/meta': 256 * 1024,         // 256KB — key wrapper only
  default: 64 * 1024,               // 64KB — all other endpoints
};

function readBody(req, path) {
  const limit = BODY_LIMITS[path] || BODY_LIMITS.default;
  return new Promise((resolve, reject) => {
    let n = 0;
    const c = [];
    req.on('data', d => {
      n += d.length;
      if (n > limit) { reject(new Error('too-big')); req.destroy(); }
      else c.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(c)));
    req.on('error', reject);
  });
}

module.exports = {
  TOKEN, TEST_MODE, SERVER_SECRET, SIGN_KEY, SIGN_PUB, MACHINE_RE,
  ipOf, blocked, noteFail, encSecret, decSecret, sendMail,
  b64u, signLicense, ownerOk, signupRate, genCode,
  todayStr, addDays, clip, clipNull, authed,
  send, readBody, BODY_LIMITS,
};
