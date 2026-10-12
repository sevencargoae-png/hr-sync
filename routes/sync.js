/* مزامنة البيانات واسترداد كلمة المرور — تحتاج رمز الشركة */
'use strict';
const crypto = require('crypto');
const { pool } = require('../lib/db');
const h = require('../lib/helpers');

async function handle(u, req, res, ip) {
  /* ---- استرداد كلمة مرور المدير بالإيميل ---- */
  if (u.pathname === '/recovery/enroll' && req.method === 'POST') {
    const b = JSON.parse((await h.readBody(req, '/recovery/enroll')).toString() || '{}');
    const email = String(b.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || typeof b.escrow !== 'string' || b.escrow.length < 20)
      return h.send(res, 400, { ok: false, error: 'bad-payload' });
    await pool.query(`INSERT INTO hr_recovery (id, email, escrow, updated_at) VALUES ('admin',$1,$2,now()) ON CONFLICT (id) DO UPDATE SET email=$1, escrow=$2, code_hash=NULL, code_exp=NULL, tries=0, updated_at=now()`,
      [email, h.encSecret(b.escrow)]);
    return h.send(res, 200, { ok: true, email });
  }

  if (u.pathname === '/recovery/status' && req.method === 'GET') {
    const { rows } = await pool.query(`SELECT email FROM hr_recovery WHERE id='admin'`);
    const em = rows[0] && rows[0].email;
    return h.send(res, 200, { ok: true, enrolled: !!em, emailMasked: em ? em.replace(/^(.).+(@.+)$/, '$1***$2') : null });
  }

  if (u.pathname === '/recovery/request' && req.method === 'POST') {
    const b = JSON.parse((await h.readBody(req, '/recovery/request')).toString() || '{}');
    const email = String(b.email || '').trim().toLowerCase();
    const { rows } = await pool.query(`SELECT email FROM hr_recovery WHERE id='admin'`);
    if (!rows[0] || rows[0].email !== email) { h.noteFail(ip); return h.send(res, 200, { ok: true, sent: true }); }
    const code = String(crypto.randomInt(100000, 999999));
    const hash = crypto.createHash('sha256').update(code + h.SERVER_SECRET).digest('hex');
    await pool.query(`UPDATE hr_recovery SET code_hash=$1, code_exp=now() + interval '10 minutes', tries=0 WHERE id='admin'`, [hash]);
    try {
      await h.sendMail(email, 'رمز استرداد كلمة مرور منصة شؤون الموظفين', `رمز الاسترداد: ${code}\nصالح لمدة 10 دقائق. إن لم تطلب هذا، تجاهل الرسالة.`);
    } catch (e) { return h.send(res, 500, { ok: false, error: 'mail-failed' }); }
    return h.send(res, 200, { ok: true, sent: true, ...(h.TEST_MODE ? { code } : {}) });
  }

  if (u.pathname === '/recovery/verify' && req.method === 'POST') {
    const b = JSON.parse((await h.readBody(req, '/recovery/verify')).toString() || '{}');
    const email = String(b.email || '').trim().toLowerCase();
    const code = String(b.code || '').trim();
    const { rows } = await pool.query(`SELECT * FROM hr_recovery WHERE id='admin'`);
    const r = rows[0];
    if (!r || r.email !== email || !r.code_hash || !r.code_exp || new Date(r.code_exp) < new Date() || r.tries >= 5) {
      h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' });
    }
    const hash = crypto.createHash('sha256').update(code + h.SERVER_SECRET).digest('hex');
    if (hash !== r.code_hash) {
      await pool.query(`UPDATE hr_recovery SET tries=tries+1 WHERE id='admin'`);
      h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' });
    }
    await pool.query(`UPDATE hr_recovery SET code_hash=NULL, code_exp=NULL, tries=0 WHERE id='admin'`);
    return h.send(res, 200, { ok: true, escrow: h.decSecret(r.escrow) });
  }

  /* ---- مزامنة البيانات المشفّرة ---- */
  if (u.pathname === '/sync/pull' && req.method === 'GET') {
    const { rows } = await pool.query('SELECT meta, blob, version, updated_at, updated_by FROM hr_store WHERE id=$1', ['company']);
    const r = rows[0] || { version: 0 };
    return h.send(res, 200, { ok: true, version: r.version || 0, meta: r.meta || null, blob: r.blob || null, updatedAt: r.updated_at || null, updatedBy: r.updated_by || null, empty: !r.blob });
  }

  if (u.pathname === '/sync/push' && req.method === 'POST') {
    const body = JSON.parse((await h.readBody(req, '/sync/push')).toString() || '{}');
    const { expectedVersion, meta, blob, by } = body;
    if (typeof blob !== 'string' || !meta) return h.send(res, 400, { ok: false, error: 'bad-payload' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cur = (await client.query('SELECT version FROM hr_store WHERE id=$1 FOR UPDATE', ['company'])).rows[0];
      const curV = cur ? cur.version : 0;
      if (typeof expectedVersion === 'number' && expectedVersion !== curV) {
        await client.query('ROLLBACK');
        return h.send(res, 409, { ok: false, conflict: true, version: curV });
      }
      const nv = curV + 1;
      await client.query('UPDATE hr_store SET meta=$1, blob=$2, version=$3, updated_at=now(), updated_by=$4 WHERE id=$5',
        [meta, blob, nv, String(by || '').slice(0, 80), 'company']);
      await client.query('COMMIT');
      return h.send(res, 200, { ok: true, version: nv });
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
  }

  if (u.pathname === '/sync/meta' && req.method === 'POST') {
    const body = JSON.parse((await h.readBody(req, '/sync/meta')).toString() || '{}');
    if (!body.meta) return h.send(res, 400, { ok: false, error: 'bad-payload' });
    const { rows } = await pool.query('UPDATE hr_store SET meta=$1, version=version+1, updated_at=now(), updated_by=$2 WHERE id=$3 RETURNING version',
      [body.meta, String(body.by || '').slice(0, 80), 'company']);
    return h.send(res, 200, { ok: true, version: rows[0].version });
  }

  return false;
}

module.exports = { handle };
