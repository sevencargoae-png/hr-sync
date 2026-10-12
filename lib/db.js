/* قاعدة البيانات — PostgreSQL مع دعم شهادة SSL */
'use strict';
const { Pool } = require('pg');

// SSL configuration with proper certificate verification.
// Set DB_CA_CERT to your database provider's CA certificate (inline PEM or file path).
// Set PGSSL=1 to enable SSL. DB_CA_CERT adds proper verification on top.
function buildSslConfig() {
  if (process.env.PGSSL !== '1') return false;
  if (process.env.DB_CA_CERT) {
    const fs = require('fs');
    const ca = process.env.DB_CA_CERT.startsWith('-----BEGIN')
      ? process.env.DB_CA_CERT
      : (fs.existsSync(process.env.DB_CA_CERT) ? fs.readFileSync(process.env.DB_CA_CERT, 'utf8') : undefined);
    return { rejectUnauthorized: true, ...(ca ? { ca } : {}) };
  }
  if (process.env.NODE_ENV === 'production') {
    console.warn('WARNING: DB SSL rejectUnauthorized=false — set DB_CA_CERT for proper certificate verification.');
  }
  return { rejectUnauthorized: false };
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: buildSslConfig(),
  max: 4,
});

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
  await pool.query(`CREATE TABLE IF NOT EXISTS hr_devices (machine text PRIMARY KEY, host text, app_version text, os text, lic_state text, lic_name text, lic_plan text, lic_expires text, lic_code text, company text, trial_start text, status text NOT NULL DEFAULT 'active', note text, ip text, seen_count integer NOT NULL DEFAULT 0, first_seen timestamptz DEFAULT now(), last_seen timestamptz DEFAULT now(), status_at timestamptz, status_by text)`);
  console.log('hr_store ready');
}

module.exports = { pool, init };
