/* الطلبات الإدارية — أكواد الترخيص، الاشتراكات، الأجهزة (المالك فقط) */
'use strict';
const { pool } = require('../lib/db');
const { MODULES, PLANS, resolveModules } = require('../plans');
const h = require('../lib/helpers');

const ADMIN_PATHS = ['/license/newcode', '/license/codes', '/license/revoke',
  '/signup/list', '/signup/approve', '/signup/reject', '/signup/done',
  '/admin/devices', '/admin/device/status'];

async function handle(u, req, res, ip) {
  if (!ADMIN_PATHS.includes(u.pathname) || req.method !== 'POST') return false;

  const bodyText = (await h.readBody(req, u.pathname)).toString();
  if (!h.ownerOk(req, u.pathname, bodyText)) { h.noteFail(ip); return h.send(res, 403, { ok: false, why: 'owner-only' }); }
  const b = bodyText ? JSON.parse(bodyText) : {};

  if (u.pathname === '/admin/devices') {
    const { rows } = await pool.query(`SELECT d.*,
      COALESCE((SELECT json_agg(json_build_object('code', a.code, 'name', a.name, 'at', a.at, 'last_check', a.last_check, 'lic_expires', a.lic_expires, 'plan', c.plan, 'code_name', c.name, 'revoked', c.revoked) ORDER BY a.at) FROM hr_activations a LEFT JOIN hr_codes c ON c.code=a.code WHERE a.machine=d.machine), '[]'::json) AS activations,
      COALESCE((SELECT json_agg(json_build_object('id', s.id, 'kind', s.kind, 'company', s.company, 'person', s.person, 'phone', s.phone, 'email', s.email, 'status', s.status, 'note', s.note, 'created_at', s.created_at, 'updated_at', s.updated_at) ORDER BY s.created_at DESC) FROM hr_signups s WHERE s.machine=d.machine), '[]'::json) AS signups
      FROM hr_devices d ORDER BY d.last_seen DESC LIMIT 1000`);
    const orphans = (await pool.query(`SELECT a.machine, a.name, a.code, a.at, a.lic_expires FROM hr_activations a WHERE NOT EXISTS (SELECT 1 FROM hr_devices d WHERE d.machine=a.machine) ORDER BY a.at DESC LIMIT 300`)).rows;
    return h.send(res, 200, { ok: true, devices: rows, orphans, ts: Date.now() });
  }

  if (u.pathname === '/admin/device/status') {
    const machine = String(b.machine || '').trim().toUpperCase();
    const status = ['active', 'disabled', 'killed'].includes(b.status) ? b.status : null;
    if (!h.MACHINE_RE.test(machine) || !status) return h.send(res, 200, { ok: false, why: 'bad-payload' });
    const r = await pool.query(`UPDATE hr_devices SET status=$2, note=$3, status_at=now(), status_by='owner' WHERE machine=$1 RETURNING machine`,
      [machine, status, String(b.note || '').slice(0, 300) || null]);
    return h.send(res, 200, r.rows[0] ? { ok: true, machine, status } : { ok: false, why: 'not-found' });
  }

  if (u.pathname === '/signup/list') {
    const { rows } = await pool.query('SELECT id, kind, machine, company, person, activity, phone, username, email, status, terms, terms_at, note, created_at, updated_at FROM hr_signups ORDER BY created_at DESC LIMIT 300');
    return h.send(res, 200, { ok: true, items: rows, pending: rows.filter(x => x.status === 'pending').length });
  }

  if (u.pathname === '/signup/approve') {
    const id = String(b.id || '');
    const code = h.genCode().replace(/-/g, '').slice(0, 6);
    const r = await pool.query(`UPDATE hr_signups SET status='approved', approve_code=COALESCE(approve_code,$2), updated_at=now() WHERE id=$1 AND status IN ('pending','approved') RETURNING approve_code`, [id, code]);
    return h.send(res, 200, r.rows[0] ? { ok: true, code: r.rows[0].approve_code } : { ok: false, why: 'not-found' });
  }

  if (u.pathname === '/signup/reject') {
    const r = await pool.query(`UPDATE hr_signups SET status='rejected', note=$2, updated_at=now() WHERE id=$1 RETURNING id`, [String(b.id || ''), String(b.note || '').slice(0, 300)]);
    return h.send(res, 200, { ok: !!r.rows[0] });
  }

  if (u.pathname === '/signup/done') {
    const r = await pool.query(`UPDATE hr_signups SET status='done', note=$2, updated_at=now() WHERE id=$1 RETURNING id`, [String(b.id || ''), String(b.note || '').slice(0, 300)]);
    return h.send(res, 200, { ok: !!r.rows[0] });
  }

  if (u.pathname === '/license/newcode') {
    const plan = PLANS[b.plan] ? b.plan : (Array.isArray(b.modules) && b.modules.length ? 'custom' : null);
    if (!plan) return h.send(res, 200, { ok: false, why: 'bad-plan' });
    const mods = resolveModules(plan, b.modules);
    if (!mods) return h.send(res, 200, { ok: false, why: 'bad-plan' });
    const maxUses = Math.min(500, Math.max(1, Math.floor(+b.max_uses || 1)));
    const validDays = b.valid_days ? Math.min(3650, Math.max(1, Math.floor(+b.valid_days))) : null;
    const exp = b.expires && /^\d{4}-\d{2}-\d{2}$/.test(b.expires) ? b.expires : null;
    const name = String(b.name || '').slice(0, 120);
    for (let i = 0; i < 5; i++) {
      const code = h.genCode();
      const r = await pool.query('INSERT INTO hr_codes (code, name, plan, modules, max_uses, valid_days, expires) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING code',
        [code, name, plan, JSON.stringify(mods), maxUses, validDays, exp]);
      if (r.rows[0]) return h.send(res, 200, { ok: true, code, name, plan, modules: mods, max_uses: maxUses, valid_days: validDays, expires: exp });
    }
    return h.send(res, 500, { ok: false, error: 'server' });
  }

  if (u.pathname === '/license/codes') {
    const { rows } = await pool.query(`SELECT c.code, c.name, c.plan, c.modules, c.max_uses, c.valid_days, c.expires, c.revoked, c.created_at,
      COALESCE((SELECT json_agg(json_build_object('machine', a.machine, 'name', a.name, 'at', a.at, 'last_check', a.last_check, 'lic_expires', a.lic_expires) ORDER BY a.at) FROM hr_activations a WHERE a.code=c.code), '[]'::json) AS devices
      FROM hr_codes c ORDER BY c.created_at DESC LIMIT 500`);
    return h.send(res, 200, { ok: true, codes: rows.map(r => ({
      code: r.code, name: r.name, plan: r.plan, modules: r.modules,
      max_uses: r.max_uses, valid_days: r.valid_days,
      expires: r.expires ? new Date(r.expires).toISOString().slice(0, 10) : null,
      revoked: r.revoked, created_at: r.created_at, used: r.devices.length, devices: r.devices,
    })) });
  }

  if (u.pathname === '/license/revoke') {
    const code = String(b.code || '').trim().toUpperCase();
    const revoked = b.revoked !== false;
    const r = await pool.query('UPDATE hr_codes SET revoked=$2 WHERE code=$1 RETURNING code', [code, revoked]);
    return h.send(res, 200, { ok: !!r.rows[0], revoked });
  }

  return false;
}

module.exports = { handle };
