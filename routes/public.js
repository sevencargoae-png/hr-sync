/* الطلبات العامة — تسجيل، ترخيص، نبضة الجهاز (بدون رمز الشركة) */
'use strict';
const crypto = require('crypto');
const { pool } = require('../lib/db');
const { MODULES, PLANS, resolveModules } = require('../plans');
const h = require('../lib/helpers');

function handle(u, req, res, ip) {
  /* ---- طلبات التسجيل/الشراء ---- */
  if (u.pathname === '/signup/request' && req.method === 'POST') return signupRequest(req, res, ip);
  if (u.pathname === '/signup/status' && req.method === 'POST') return signupStatus(req, res, ip);
  if (u.pathname === '/signup/verify' && req.method === 'POST') return signupVerify(req, res, ip);
  if (u.pathname === '/signup/terms' && req.method === 'POST') return signupTerms(req, res);
  /* ---- نبضة الجهاز ---- */
  if (u.pathname === '/device/ping' && req.method === 'POST') return devicePing(req, res, ip);
  /* ---- ترخيص ---- */
  if (u.pathname === '/license/plans' && req.method === 'GET') return h.send(res, 200, { ok: true, modules: MODULES, plans: PLANS });
  if (u.pathname === '/license/activate' && req.method === 'POST') return licenseActivate(req, res, ip);
  if (u.pathname === '/license/check' && req.method === 'POST') return licenseCheck(req, res, ip);
  return false; // not handled
}

async function signupRequest(req, res, ip) {
  const b = h.parseJSON(await h.readBody(req, '/signup/request'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const machine = String(b.machine || '').trim().toUpperCase();
  const kind = b.kind === 'purchase' ? 'purchase' : 'trial';
  if (!h.MACHINE_RE.test(machine) || h.clip(b.company, 120).length < 2 || h.clip(b.person, 120).length < 2 || h.clip(b.phone, 40).length < 5) {
    h.noteFail(ip); return h.send(res, 400, { ok: false, why: 'bad-payload' });
  }
  const rl = h.signupRate.get(ip) || { n: 0, first: Date.now() };
  if (Date.now() - rl.first > 3600000) { rl.n = 0; rl.first = Date.now(); }
  if (++rl.n > 8) return h.send(res, 429, { ok: false, why: 'busy' });
  h.signupRate.set(ip, rl);

  const old = (await pool.query(`SELECT id, status FROM hr_signups WHERE machine=$1 AND kind=$2 AND status IN ('pending','approved') ORDER BY created_at DESC LIMIT 1`, [machine, kind])).rows[0];
  if (old && kind === 'purchase') {
    await pool.query(`UPDATE hr_signups SET company=$2, person=$3, activity=$4, phone=$5, username=$6, email=$7, updated_at=now() WHERE id=$1`,
      [old.id, h.clip(b.company, 120), h.clip(b.person, 120), h.clip(b.activity, 300), h.clip(b.phone, 40), h.clip(b.username, 60), h.clip(b.email, 120)]);
    return h.send(res, 200, { ok: true, id: old.id, status: old.status });
  }
  const id = crypto.randomBytes(8).toString('hex');
  await pool.query(`INSERT INTO hr_signups (id, kind, machine, company, person, activity, phone, username, email) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [id, kind, machine, h.clip(b.company, 120), h.clip(b.person, 120), h.clip(b.activity, 300), h.clip(b.phone, 40), h.clip(b.username, 60), h.clip(b.email, 120)]);
  return h.send(res, 200, { ok: true, id, status: 'pending' });
}

async function signupStatus(req, res, ip) {
  const b = h.parseJSON(await h.readBody(req, '/signup/status'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const r = (await pool.query('SELECT status FROM hr_signups WHERE id=$1 AND machine=$2', [String(b.id || ''), String(b.machine || '').toUpperCase()])).rows[0];
  if (!r) { h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' }); }
  return h.send(res, 200, { ok: true, status: r.status });
}

async function signupVerify(req, res, ip) {
  const b = h.parseJSON(await h.readBody(req, '/signup/verify'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const code = String(b.code || '').trim().toUpperCase().replace(/\s/g, '');
  const r = (await pool.query('SELECT * FROM hr_signups WHERE id=$1 AND machine=$2', [String(b.id || ''), String(b.machine || '').toUpperCase()])).rows[0];
  if (!r || r.status === 'rejected') { h.noteFail(ip); return h.send(res, 200, { ok: false, why: r ? 'rejected' : 'invalid' }); }
  if (r.status === 'pending') return h.send(res, 200, { ok: false, why: 'pending' });
  if (r.tries >= 8) return h.send(res, 200, { ok: false, why: 'locked' });
  const codeMatch = r.approve_code && code.length === r.approve_code.length && crypto.timingSafeEqual(Buffer.from(code), Buffer.from(r.approve_code));
  if (!r.approve_code || !codeMatch) {
    await pool.query('UPDATE hr_signups SET tries=tries+1 WHERE id=$1', [r.id]);
    h.noteFail(ip);
    return h.send(res, 200, { ok: false, why: 'code' });
  }
  await pool.query(`UPDATE hr_signups SET status='active', updated_at=now() WHERE id=$1 AND status='approved'`, [r.id]);
  return h.send(res, 200, { ok: true });
}

async function signupTerms(req, res) {
  const b = h.parseJSON(await h.readBody(req, '/signup/terms'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const t = b.accepted ? 'accepted' : 'rejected';
  const r = await pool.query(`UPDATE hr_signups SET terms=$3, terms_at=now(), updated_at=now() WHERE id=$1 AND machine=$2 RETURNING id`,
    [String(b.id || ''), String(b.machine || '').toUpperCase(), t]);
  return h.send(res, 200, { ok: !!r.rows[0] });
}

async function devicePing(req, res, ip) {
  const b = h.parseJSON(await h.readBody(req, '/device/ping'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const machine = String(b.machine || '').trim().toUpperCase();
  if (!h.MACHINE_RE.test(machine)) { h.noteFail(ip); return h.send(res, 400, { ok: false, why: 'bad-machine' }); }
  const rl = h.signupRate.get('ping:' + machine) || { n: 0, first: Date.now() };
  if (Date.now() - rl.first > 3600000) { rl.n = 0; rl.first = Date.now(); }
  if (++rl.n > 60) return h.send(res, 429, { ok: false, why: 'busy' });
  h.signupRate.set('ping:' + machine, rl);

  const lic = b.lic && typeof b.lic === 'object' ? b.lic : {};
  const { rows } = await pool.query(
    `INSERT INTO hr_devices (machine, host, app_version, os, lic_state, lic_name, lic_plan, lic_expires, lic_code, company, trial_start, ip, seen_count, first_seen, last_seen)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,now(),now())
     ON CONFLICT (machine) DO UPDATE SET host=COALESCE($2,hr_devices.host), app_version=$3, os=COALESCE($4,hr_devices.os), lic_state=$5, lic_name=$6, lic_plan=$7, lic_expires=$8, lic_code=COALESCE($9,hr_devices.lic_code), company=COALESCE($10,hr_devices.company), trial_start=COALESCE($11,hr_devices.trial_start), ip=$12, seen_count=hr_devices.seen_count+1, last_seen=now()
     RETURNING status, note`,
    [machine, h.clipNull(b.host, 80), h.clipNull(b.version, 20), h.clipNull(b.os, 60), h.clipNull(lic.state, 20), h.clipNull(lic.name, 120), h.clipNull(lic.plan, 30), h.clipNull(lic.expires, 10), h.clipNull(lic.code, 20), h.clipNull(b.company, 120), h.clipNull(b.trialStart, 10), ip.slice(0, 60)]);
  return h.send(res, 200, { ok: true, status: rows[0].status || 'active', message: rows[0].note || null, ts: Date.now() });
}

async function licenseActivate(req, res, ip) {
  if (!h.SIGN_KEY) return h.send(res, 503, { ok: false, why: 'not-configured' });
  const b = h.parseJSON(await h.readBody(req, '/license/activate'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const code = String(b.code || '').trim().toUpperCase();
  const machine = String(b.machine || '').trim().toUpperCase();
  if (!/^[A-Z2-9]{4}(-[A-Z2-9]{4}){2}$/.test(code) || !h.MACHINE_RE.test(machine)) { h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' }); }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const row = (await client.query('SELECT * FROM hr_codes WHERE code=$1 FOR UPDATE', [code])).rows[0];
    if (!row) { await client.query('ROLLBACK'); h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' }); }
    if (row.revoked) { await client.query('ROLLBACK'); return h.send(res, 200, { ok: false, why: 'revoked' }); }

    const prev = (await client.query('SELECT serial, lic_expires FROM hr_activations WHERE code=$1 AND machine=$2', [code, machine])).rows[0];
    if (prev) {
      await client.query('UPDATE hr_activations SET last_check=now() WHERE code=$1 AND machine=$2', [code, machine]);
      await client.query('COMMIT');
      return h.send(res, 200, { ok: true, serial: prev.serial, again: true });
    }

    if (row.expires && String(row.expires.toISOString ? row.expires.toISOString().slice(0, 10) : row.expires) < h.todayStr()) {
      await client.query('ROLLBACK'); return h.send(res, 200, { ok: false, why: 'expired' });
    }
    const used = +(await client.query('SELECT count(*)::int AS n FROM hr_activations WHERE code=$1', [code])).rows[0].n;
    if (used >= row.max_uses) { await client.query('ROLLBACK'); return h.send(res, 200, { ok: false, why: 'used-up' }); }

    const licExp = row.valid_days ? h.addDays(h.todayStr(), row.valid_days) : null;
    const id = crypto.randomBytes(4).toString('hex').toUpperCase();
    const mods = resolveModules(row.plan, row.modules) || Object.keys(MODULES);
    const serial = h.signLicense({ name: String(b.name || row.name || '').slice(0, 120), machine, expires: licExp, seats: 1, plan: row.plan || 'custom', modules: mods, issued: h.todayStr(), id, code });
    await client.query('INSERT INTO hr_activations (code, machine, name, serial, lic_id, lic_expires, last_check) VALUES ($1,$2,$3,$4,$5,$6,now())', [code, machine, String(b.name || '').slice(0, 120), serial, id, licExp]);
    await client.query('COMMIT');
    return h.send(res, 200, { ok: true, serial, plan: row.plan, modules: mods, expires: licExp });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}

async function licenseCheck(req, res, ip) {
  const b = h.parseJSON(await h.readBody(req, '/license/check'));
  if (!b) return h.send(res, 400, { ok: false, why: 'bad-json' });
  const code = String(b.code || '').trim().toUpperCase();
  const machine = String(b.machine || '').trim().toUpperCase();
  if (!/^[A-Z2-9]{4}(-[A-Z2-9]{4}){2}$/.test(code) || !h.MACHINE_RE.test(machine)) { h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' }); }
  const { rows } = await pool.query('SELECT c.revoked FROM hr_codes c JOIN hr_activations a ON a.code=c.code WHERE c.code=$1 AND a.machine=$2', [code, machine]);
  if (!rows[0]) { h.noteFail(ip); return h.send(res, 200, { ok: false, why: 'invalid' }); }
  await pool.query('UPDATE hr_activations SET last_check=now() WHERE code=$1 AND machine=$2', [code, machine]);
  return h.send(res, 200, { ok: true, revoked: !!rows[0].revoked });
}

module.exports = { handle };
