/**
 * Database Client - Direct PostgreSQL + Supabase Auth
 */
import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// =============================================================================
// Supabase Auth Client (for OAuth)
// =============================================================================
const supabaseUrl = process.env.SUPABASE_URL || 'https://kong-production-6d54.up.railway.app';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseAnonKey) {
  console.warn('⚠️  SUPABASE_ANON_KEY not set');
}

// For auth operations only
export const supabase = createClient(supabaseUrl, supabaseAnonKey || 'dummy', {
  auth: {
    autoRefreshToken: true,
    persistSession: false,
  },
});

export const supabaseAdmin = supabaseServiceKey 
  ? createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    })
  : supabase;

export { supabaseUrl, supabaseAnonKey };

// =============================================================================
// Direct PostgreSQL Client (for database queries)
// =============================================================================
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.warn('⚠️  DATABASE_URL not set - database queries will fail');
}

// Railway internal connections don't need SSL
// For external connections (maglev.proxy.rlwy.net), SSL may be needed
const pool = databaseUrl ? new pg.Pool({
  connectionString: databaseUrl,
  // Try without SSL first, Railway handles security at network level
  ssl: false,
  max: 10,
}) : null;

if (pool) {
  pool.on('connect', () => console.log('✅ PostgreSQL connected'));
  pool.on('error', (err) => console.error('❌ PostgreSQL error:', err.message));
}

// =============================================================================
// Database Query Helper
// =============================================================================
export const db = {
  async query(text, params) {
    if (!pool) throw new Error('Database not configured');
    console.log('[DB] Query:', text.slice(0, 80) + '...');
    const start = Date.now();
    const result = await pool.query(text, params);
    console.log('[DB] Result:', result.rowCount, 'rows in', Date.now() - start, 'ms');
    return result;
  },

  // Installation queries
  async findInstallationByInstallId(installId) {
    const result = await this.query(
      'SELECT * FROM installations WHERE install_id = $1',
      [installId]
    );
    return result.rows[0];
  },

  async findInstallationByClaimCode(claimCode) {
    const result = await this.query(
      'SELECT * FROM installations WHERE claim_code = $1',
      [claimCode]
    );
    return result.rows[0];
  },

  async findInstallationsByUserId(userId) {
    const result = await this.query(
      'SELECT * FROM installations WHERE claimed_by = $1 ORDER BY created_at DESC',
      [userId]
    );
    return result.rows;
  },

  async createInstallation({ installId, hostname, architecture, nixosVersion, claimCode }) {
    const result = await this.query(
      `INSERT INTO installations (install_id, hostname, architecture, nixos_version, claim_code)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [installId, hostname || 'kaliunbox', architecture, nixosVersion, claimCode]
    );
    return result.rows[0];
  },

  async updateInstallation(installId, updates) {
    const setClauses = [];
    const values = [];
    let i = 1;

    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        setClauses.push(`${key} = $${i}`);
        values.push(value);
        i++;
      }
    }

    if (setClauses.length === 0) return null;

    setClauses.push('updated_at = NOW()');
    values.push(installId);

    const result = await this.query(
      `UPDATE installations SET ${setClauses.join(', ')} WHERE install_id = $${i} RETURNING *`,
      values
    );
    return result.rows[0];
  },

  async claimInstallation(claimCode, userId, customerName, customerEmail, customerAddress) {
    const result = await this.query(
      `UPDATE installations 
       SET claimed_by = $2, claimed_at = NOW(), customer_name = $3, customer_email = $4, customer_address = $5
       WHERE claim_code = $1 AND claimed_at IS NULL
       RETURNING *`,
      [claimCode, userId, customerName, customerEmail, customerAddress || '']
    );
    return result.rows[0];
  },

  // Health reports
  async createHealthReport(installationId, data) {
    await this.query(
      'INSERT INTO health_reports (installation_id, data) VALUES ($1, $2)',
      [installationId, JSON.stringify(data)]
    );
  },

  // Logs
  async createLogs(installationId, logs) {
    for (const log of logs) {
      await this.query(
        'INSERT INTO logs (installation_id, timestamp, service, level, message) VALUES ($1, $2, $3, $4, $5)',
        [
          installationId,
          log.timestamp || new Date().toISOString(),
          log.service || 'unknown',
          log.level || 'info',
          typeof log === 'string' ? log : log.message
        ]
      );
    }
  },

  async getInstallationLogs(installationId, limit = 50) {
    const result = await this.query(
      'SELECT * FROM logs WHERE installation_id = $1 ORDER BY timestamp DESC LIMIT $2',
      [installationId, limit]
    );
    return result.rows;
  },
};

export default db;
