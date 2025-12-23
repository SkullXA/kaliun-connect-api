/**
 * Database Client - Direct PostgreSQL + Supabase Auth
 */
import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

// Check if we're in local development mode
const BASE_URL = process.env.BASE_URL || '';
export const isLocalDev = BASE_URL.includes('localhost') || !process.env.SUPABASE_URL;

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

// Railway PostgreSQL - no SSL needed (neither internal nor proxy)
const pool = databaseUrl ? new pg.Pool({
  connectionString: databaseUrl,
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

  // ==========================================================================
  // User Auth (for local development without Supabase Auth)
  // ==========================================================================
  async findUserByEmail(email) {
    const result = await this.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    return result.rows[0];
  },

  async findUserById(userId) {
    const result = await this.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    return result.rows[0];
  },

  async createUser({ email, password, name }) {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await this.query(
      `INSERT INTO users (email, password_hash, name, provider)
       VALUES ($1, $2, $3, 'email')
       RETURNING *`,
      [email.toLowerCase(), passwordHash, name]
    );
    return result.rows[0];
  },

  async verifyPassword(user, password) {
    if (!user.password_hash) return false;
    return bcrypt.compare(password, user.password_hash);
  },

  async updateUser(userId, updates) {
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
    values.push(userId);

    const result = await this.query(
      `UPDATE users SET ${setClauses.join(', ')} WHERE id = $${i} RETURNING *`,
      values
    );
    return result.rows[0];
  },

  // Sessions
  async createSession(userId) {
    const token = randomUUID() + '-' + randomUUID();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    const result = await this.query(
      `INSERT INTO sessions (user_id, token, expires_at)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [userId, token, expiresAt.toISOString()]
    );
    return result.rows[0];
  },

  async findSessionByToken(token) {
    const result = await this.query(
      'SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    return result.rows[0];
  },

  async deleteSession(token) {
    await this.query('DELETE FROM sessions WHERE token = $1', [token]);
  },

  async cleanupExpiredSessions() {
    await this.query('DELETE FROM sessions WHERE expires_at < NOW()');
  },
};

export default db;
