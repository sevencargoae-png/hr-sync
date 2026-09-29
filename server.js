/* خادم مزامنة منصة شؤون الموظفين — يخزّن قاعدة بيانات الشركة مشفّرة طرف-لطرف.
   السيرفر لا يرى البيانات إطلاقاً: يخزّن نصاً مشفّراً (blob) + غلاف المفاتيح (meta) فقط.
   المصادقة: توكن الشركة (COMPANY_TOKEN) مضمّن في التطبيق. تشفير البيانات بكلمة مرور الشركة عند العميل. */
const http = require('http');
const { Pool } = require('pg');
const PORT = process.env.PORT || 10000;
const TOKEN = process.env.COMPANY_TOKEN || '';
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 4 });

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
    if (!authed(req)) return send(res, 401, { ok: false, error: 'unauthorized' });

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
