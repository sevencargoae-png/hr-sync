/* اختبار نقاط الترخيص: node test-license.js (يحتاج Postgres على DATABASE_URL) */
const { spawn } = require('child_process');
const crypto = require('crypto');
const { resolveModules, PLANS } = require('./plans');
const b64u = { enc: b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), dec: s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64') };
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const TOKEN = 'testtoken123', PORT = 4599, BASE = 'http://127.0.0.1:' + PORT;
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log('FAIL:', m); } };
async function call(method, path, body, { owner = false, token = true, ts, tamper } = {}) {
  const text = body ? JSON.stringify(body) : '';
  const h = { 'Content-Type': 'application/json' }; if (token) h.Authorization = 'Bearer ' + TOKEN;
  if (owner) { const t = ts || Date.now(); const sig = b64u.enc(crypto.sign(null, Buffer.from(method + ' ' + path + '\n' + t + '\n' + (tamper || text)), privateKey)); h['X-Owner-Ts'] = String(t); h['X-Owner-Sig'] = sig; }
  const r = await fetch(BASE + path, { method, headers: h, body: method === 'POST' ? text : undefined }); return { status: r.status, j: await r.json() };
}
function verify(serial) { const [p, sig] = serial.split('.'); return crypto.verify(null, b64u.dec(p), publicKey, b64u.dec(sig)) ? JSON.parse(b64u.dec(p).toString()) : null; }
(async () => {
  const srv = spawn('node', ['server.js'], { env: { ...process.env, PORT, COMPANY_TOKEN: TOKEN, SIGN_PRIVATE_KEY: privB64, DATABASE_URL: process.env.DATABASE_URL }, stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise(r => srv.stdout.on('data', d => String(d).includes('hr-sync on') && r()));
  try {
    const h = await call('GET', '/healthz', null, { token: false }); ok(h.j.version === '1.3.0' && h.j.license === true, 'healthz');
    const pl = await call('GET', '/license/plans', null, { token: false }); ok(pl.j.ok && pl.j.plans.pro && pl.j.modules.payroll, 'plans public');
    // resolveModules
    ok(resolveModules('starter').includes('employees') && !resolveModules('starter').includes('payroll'), 'starter modules');
    ok(resolveModules('custom', ['payroll']).includes('employees'), 'core forced');
    ok(resolveModules('nope') === null, 'bad plan null');
    // newcode: owner-only
    let r = await call('POST', '/license/newcode', { name: 'X', plan: 'pro' }); ok(r.status === 403, 'newcode without owner sig -> 403');
    r = await call('POST', '/license/newcode', { name: 'X', plan: 'pro' }, { owner: true, token: false }); ok(r.status === 401, 'newcode without token -> 401');
    r = await call('POST', '/license/newcode', { name: 'X', plan: 'pro' }, { owner: true, tamper: '{"name":"Y"}' }); ok(r.status === 403, 'tampered body -> 403');
    r = await call('POST', '/license/newcode', { name: 'X', plan: 'pro' }, { owner: true, ts: Date.now() - 3600000 }); ok(r.status === 403, 'old ts -> 403');
    const bad = await call('POST', '/license/newcode', { name: 'X', plan: 'zzz' }, { owner: true }); ok(bad.j.why === 'bad-plan', 'bad plan rejected');
    const c1 = await call('POST', '/license/newcode', { name: 'شركة أ', plan: 'pro', max_uses: 2, valid_days: 365 }, { owner: true }); ok(c1.j.ok && /^[A-Z2-9]{4}(-[A-Z2-9]{4}){2}$/.test(c1.j.code), 'newcode ok ' + JSON.stringify(c1.j));
    const cust = await call('POST', '/license/newcode', { name: 'مخصص', modules: ['payroll', 'taxes'], max_uses: 1 }, { owner: true }); ok(cust.j.ok && cust.j.modules.includes('employees') && cust.j.modules.includes('taxes') && !cust.j.modules.includes('finance'), 'custom modules');
    const M1 = 'AAAA-BBBB-CCCC-DDDD', M2 = '1111-2222-3333-4444', M3 = 'ABCD-EF01-2345-6789';
    // activation (no token needed)
    let a = await call('POST', '/license/activate', { code: c1.j.code, machine: M1, name: 'جهاز 1' }, { token: false }); ok(a.j.ok && a.j.serial, 'activate m1');
    const lic = verify(a.j.serial); ok(lic && lic.machine === M1 && lic.plan === 'pro' && lic.modules.includes('payroll') && !lic.modules.includes('finance') && lic.expires && lic.code === c1.j.code, 'serial signed & content');
    const exp = new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10); ok(lic.expires === exp, 'expires = +365d ' + lic.expires + ' vs ' + exp);
    const a1b = await call('POST', '/license/activate', { code: c1.j.code.toLowerCase(), machine: M1 }, { token: false }); ok(a1b.j.ok && a1b.j.serial === a.j.serial && a1b.j.again, 'same machine re-activation idempotent (lowercase code ok)');
    a = await call('POST', '/license/activate', { code: c1.j.code, machine: M2 }, { token: false }); ok(a.j.ok, 'activate m2');
    a = await call('POST', '/license/activate', { code: c1.j.code, machine: M3 }, { token: false }); ok(a.j.why === 'used-up', 'used-up on 3rd');
    a = await call('POST', '/license/activate', { code: 'AAAA-BBBB-CCCC', machine: M1 }, { token: false }); ok(a.j.why === 'invalid', 'unknown code invalid');
    a = await call('POST', '/license/activate', { code: c1.j.code, machine: 'bad' }, { token: false }); ok(a.j.why === 'invalid', 'bad machine invalid');
    // lifetime custom
    a = await call('POST', '/license/activate', { code: cust.j.code, machine: M3, name: 'x' }, { token: false }); const l3 = verify(a.j.serial); ok(l3.expires === null && l3.plan === 'custom' && l3.modules.length === 3, 'lifetime custom: ' + JSON.stringify(l3));
    // expired code
    const ex = await call('POST', '/license/newcode', { name: 'old', plan: 'starter', expires: '2020-01-01' }, { owner: true });
    a = await call('POST', '/license/activate', { code: ex.j.code, machine: M1 }, { token: false }); ok(a.j.why === 'expired', 'expired code');
    // codes list
    let ls = await call('GET', '/license/codes', null, { owner: true }); ok(ls.j.ok && ls.j.codes.find(c => c.code === c1.j.code).used === 2 && ls.j.codes.find(c => c.code === c1.j.code).devices.length === 2, 'list shows devices');
    r = await call('GET', '/license/codes', null); ok(r.status === 403, 'list needs owner');
    // check + revoke
    let ck = await call('POST', '/license/check', { code: c1.j.code, machine: M1 }, { token: false }); ok(ck.j.ok && ck.j.revoked === false, 'check not revoked');
    ck = await call('POST', '/license/check', { code: c1.j.code, machine: M3 }, { token: false }); ok(ck.j.ok === false, 'check unknown machine');
    const rv = await call('POST', '/license/revoke', { code: c1.j.code }, { owner: true }); ok(rv.j.ok && rv.j.revoked, 'revoke');
    ck = await call('POST', '/license/check', { code: c1.j.code, machine: M1 }, { token: false }); ok(ck.j.revoked === true, 'check revoked');
    a = await call('POST', '/license/activate', { code: c1.j.code, machine: M1 }, { token: false }); ok(a.j.why === 'revoked', 'activate revoked');
    const un = await call('POST', '/license/revoke', { code: c1.j.code, revoked: false }, { owner: true }); ok(un.j.ok && !un.j.revoked, 'unrevoke');
    // replay of same signature rejected
    const t = Date.now(); const body = { name: 'R', plan: 'starter' };
    const r1 = await call('POST', '/license/newcode', body, { owner: true, ts: t }); const r2 = await call('POST', '/license/newcode', body, { owner: true, ts: t }); ok(r1.j.ok && r2.status === 403, 'replay blocked');
    // sync endpoints still protected & working
    r = await call('GET', '/sync/pull', null, { token: false }); ok(r.status === 401, 'sync/pull needs token');
    r = await call('GET', '/sync/pull'); ok(r.j.ok, 'sync/pull works');
    // rate limit on bad codes (20 fails -> 429)
    let got429 = false; for (let i = 0; i < 25; i++) { const x = await call('POST', '/license/activate', { code: 'ZZZZ-ZZZZ-ZZZZ', machine: M1 }, { token: false }); if (x.status === 429) { got429 = true; break; } } ok(got429, 'brute-force limited (429)');
    // concurrency: 6 parallel activations on max_uses=2 code => exactly 2 succeed
    // (IP now blocked, so test in a fresh server below)
  } catch (e) { fail++; console.log('EXC', e); }
  srv.kill();
  console.log(`license tests: ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
