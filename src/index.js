/**
 * Kaliun Connect API v2
 * 
 * Device registration, claiming, OAuth2 Device Code Flow for Home Assistant
 * Now powered by Supabase for auth and database
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { supabase, supabaseAdmin, supabaseUrl, supabaseAnonKey, db, isLocalDev } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 7331;
const JWT_SECRET = process.env.JWT_SECRET || process.env.AUTH_JWT_SECRET || 'kaliun-dev-secret';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Token lifetimes
const ACCESS_TOKEN_LIFETIME = 7 * 24 * 60 * 60; // 7 days
const REFRESH_TOKEN_LIFETIME = 90 * 24 * 60 * 60; // 90 days
const DEVICE_CODE_LIFETIME = 900; // 15 minutes

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Helper functions
function generateClaimCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function generateUserCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  let code = '';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  code += '-';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function generateToken(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

function addSeconds(date, seconds) {
  return new Date(date.getTime() + seconds * 1000).toISOString();
}

function timeAgo(dateStr) {
  if (!dateStr) return 'Never';
  const seconds = Math.floor((new Date() - new Date(dateStr)) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
  if (seconds < 86400) return `about ${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Auth middleware - Check session from cookie
async function requireAuth(req, res, next) {
  console.log('[MIDDLEWARE] requireAuth called for:', req.path);
  console.log('[MIDDLEWARE] isLocalDev:', isLocalDev);
  
  const accessToken = req.cookies.sb_access_token;
  const refreshToken = req.cookies.sb_refresh_token;
  
  console.log('[MIDDLEWARE] Has access_token cookie:', !!accessToken);
  
  if (!accessToken) {
    console.log('[MIDDLEWARE] No access token, redirecting to login');
    return res.redirect('/login');
  }
  
  try {
    // LOCAL DEV MODE: Use direct DB sessions
    if (isLocalDev) {
      console.log('[MIDDLEWARE] Using LOCAL auth (direct DB)...');
      const session = await db.findSessionByToken(accessToken);
      
      if (!session) {
        console.log('[MIDDLEWARE] No valid session found');
        res.clearCookie('sb_access_token');
        return res.redirect('/login');
      }
      
      const user = await db.findUserById(session.user_id);
      if (!user) {
        console.log('[MIDDLEWARE] User not found for session');
        res.clearCookie('sb_access_token');
        return res.redirect('/login');
      }
      
      console.log('[MIDDLEWARE] LOCAL user authenticated:', user.email);
      req.user = user;
      req.supabaseUser = user; // Compat
      return next();
    }
    
    // PRODUCTION MODE: Use Supabase Auth
    console.log('[MIDDLEWARE] Using Supabase auth...');
    const { data: { user }, error } = await supabase.auth.getUser(accessToken);
    
    if (error || !user) {
      console.log('[MIDDLEWARE] Token invalid or no user:', error?.message || 'no user');
      // Try to refresh
      if (refreshToken) {
        console.log('[MIDDLEWARE] Attempting token refresh...');
        const { data: refreshData, error: refreshError } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
        if (!refreshError && refreshData.session) {
          console.log('[MIDDLEWARE] Token refreshed successfully');
          res.cookie('sb_access_token', refreshData.session.access_token, { httpOnly: true, maxAge: 3600000 });
          res.cookie('sb_refresh_token', refreshData.session.refresh_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
          req.user = refreshData.user;
          req.supabaseUser = refreshData.user;
          return next();
        }
        console.log('[MIDDLEWARE] Token refresh failed:', refreshError?.message);
      }
      console.log('[MIDDLEWARE] Clearing cookies, redirecting to login');
      res.clearCookie('sb_access_token');
      res.clearCookie('sb_refresh_token');
      return res.redirect('/login');
    }
    
    console.log('[MIDDLEWARE] User authenticated:', user.email);
    req.supabaseUser = user;
    
    // SYNC: Ensure Supabase Auth user exists in public.users with SAME ID
    // This prevents ID mismatch issues between Supabase Auth and our DB
    try {
      let profile = await db.findUserById(user.id);
      
      if (!profile) {
        // User doesn't exist with this ID - check by email
        const existingByEmail = await db.findUserByEmail(user.email);
        
        if (existingByEmail && existingByEmail.id !== user.id) {
          // User exists with different ID - update to match Supabase Auth ID
          console.log('[MIDDLEWARE] Syncing user ID:', existingByEmail.id, '->', user.id);
          await db.query(
            `UPDATE public.users SET id = $1 WHERE email = $2`,
            [user.id, user.email]
          );
          profile = { ...existingByEmail, id: user.id };
        } else if (!existingByEmail) {
          // Create new user with Supabase Auth ID
          console.log('[MIDDLEWARE] Creating user in DB with Supabase Auth ID');
          await db.query(
            `INSERT INTO public.users (id, email, name, provider) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO NOTHING`,
            [user.id, user.email, user.user_metadata?.name || user.email.split('@')[0], 'google']
          );
          profile = { id: user.id, email: user.email, name: user.user_metadata?.name };
        } else {
          profile = existingByEmail;
        }
      }
      
      console.log('[MIDDLEWARE] User synced to DB with ID:', user.id);
      req.user = { ...user, ...profile, name: profile?.name || user.user_metadata?.name };
    } catch (syncErr) {
      console.error('[MIDDLEWARE] User sync error:', syncErr.message);
      req.user = user;
    }
    
    next();
  } catch (e) {
    console.error('[MIDDLEWARE] Auth error:', e);
    return res.redirect('/login');
  }
}

// Bearer auth for device APIs
function requireBearerAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Bearer token required' });
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'unauthorized', code: 'TOKEN_EXPIRED', message: 'Invalid token' });
  }

  req.tokenPayload = payload;
  next();
}

// =============================================================================
// DEVICE APIs (unchanged interface, now uses Supabase DB)
// =============================================================================

// POST /api/v1/installations/register
app.post('/api/v1/installations/register', async (req, res) => {
  const { install_id, hostname, architecture, nixos_version } = req.body;
  if (!install_id) return res.status(400).json({ error: 'install_id is required' });

  try {
    // Check if already exists
    const existing = await db.findInstallationByInstallId(install_id);
    
    if (existing) {
      console.log(`[REGISTER] Existing: ${install_id} → ${existing.claim_code}`);
      return res.json({ claim_code: existing.claim_code });
    }

    // Create new installation
    const claimCode = generateClaimCode();
    await db.createInstallation({
      installId: install_id,
      hostname: hostname || 'kaliunbox',
      architecture,
      nixosVersion: nixos_version,
      claimCode,
    });

    console.log(`[REGISTER] New: ${install_id} → ${claimCode}`);
    res.status(201).json({ claim_code: claimCode });
  } catch (e) {
    console.error('[REGISTER] Error:', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// GET /api/v1/installations/:id/config
app.get('/api/v1/installations/:id/config', async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers.authorization;

  try {
    const installation = await db.findInstallationByInstallId(id);

    if (!installation) {
      return res.status(404).json({ error: 'not_found' });
    }

    if (!installation.claimed_at) {
      return res.status(404).json({ error: 'not_claimed' });
    }

    // If already confirmed, require bearer auth
    if (installation.config_confirmed && !authHeader) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    // Verify bearer token if provided
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const payload = verifyToken(token);
      if (!payload || payload.installation_id !== id) {
        return res.status(401).json({ error: 'unauthorized', code: 'TOKEN_EXPIRED' });
      }
      // Ongoing sync - return config without new tokens
      const pangolinSync = installation.pangolin_newt_id ? {
        newt_id: installation.pangolin_newt_id,
        newt_secret: installation.pangolin_newt_secret,
        endpoint: installation.pangolin_endpoint,
        url: installation.pangolin_url,
      } : {
        newt_id: `newt_${id.slice(0, 8)}`,
        newt_secret: `placeholder_${id.slice(0, 16)}`,
        endpoint: 'https://app.pangolin.net',
        url: null,
      };
      return res.json({
        customer: {
          name: installation.customer_name || '',
          email: installation.customer_email || '',
          address: installation.customer_address || '',
        },
        pangolin: pangolinSync,
      });
    }

    // Bootstrap - generate tokens
    const now = new Date();
    const accessToken = generateToken({ installation_id: id, type: 'access' }, ACCESS_TOKEN_LIFETIME);
    const refreshToken = generateToken({ installation_id: id, type: 'refresh' }, REFRESH_TOKEN_LIFETIME);

    await db.updateInstallation(id, {
      access_token: accessToken,
      refresh_token: refreshToken,
      access_expires_at: addSeconds(now, ACCESS_TOKEN_LIFETIME),
      refresh_expires_at: addSeconds(now, REFRESH_TOKEN_LIFETIME),
    });

    console.log(`[CONFIG] Bootstrap for: ${id}`);

    // Generate placeholder pangolin data if not configured (installer requires this)
    const pangolinData = installation.pangolin_newt_id ? {
      newt_id: installation.pangolin_newt_id,
      newt_secret: installation.pangolin_newt_secret,
      endpoint: installation.pangolin_endpoint,
      url: installation.pangolin_url,
    } : {
      newt_id: `newt_${id.slice(0, 8)}`,
      newt_secret: `placeholder_${randomUUID().slice(0, 16)}`,
      endpoint: 'https://app.pangolin.net',
      url: null, // Will be configured later
    };

    res.json({
      auth: {
        access_token: accessToken,
        refresh_token: refreshToken,
        access_expires_at: addSeconds(now, ACCESS_TOKEN_LIFETIME),
        refresh_expires_at: addSeconds(now, REFRESH_TOKEN_LIFETIME),
      },
      customer: {
        name: installation.customer_name || '',
        email: installation.customer_email || '',
        address: installation.customer_address || '',
      },
      pangolin: pangolinData,
    });
  } catch (e) {
    console.error('Config error:', e);
    res.status(500).json({ error: 'internal_error' });
  }
});

// DELETE /api/v1/installations/:id/config
app.delete('/api/v1/installations/:id/config', async (req, res) => {
  const { id } = req.params;

  try {
    await db.updateInstallation(id, { config_confirmed: true });
    console.log(`[CONFIG] Confirmed: ${id}`);
    res.status(204).send();
  } catch (e) {
    console.error('[CONFIG] Confirm error:', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// POST /api/v1/installations/token/refresh
app.post('/api/v1/installations/token/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token is required' });

  const payload = verifyToken(refresh_token);
  if (!payload || payload.type !== 'refresh') {
    return res.status(401).json({ error: 'invalid_grant' });
  }

  try {
    const now = new Date();
    const newAccessToken = generateToken({ installation_id: payload.installation_id, type: 'access' }, ACCESS_TOKEN_LIFETIME);

    await db.updateInstallation(payload.installation_id, {
      access_token: newAccessToken,
      access_expires_at: addSeconds(now, ACCESS_TOKEN_LIFETIME),
    });

    console.log(`[TOKEN] Refreshed: ${payload.installation_id}`);
    res.json({
      access_token: newAccessToken,
      access_expires_at: addSeconds(now, ACCESS_TOKEN_LIFETIME),
    });
  } catch (e) {
    console.error('[TOKEN] Refresh error:', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// POST /api/v1/installations/:id/health
app.post('/api/v1/installations/:id/health', requireBearerAuth, async (req, res) => {
  const { id } = req.params;
  if (req.tokenPayload.installation_id !== id) {
    return res.status(403).json({ error: 'forbidden' });
  }

  try {
    const installation = await db.findInstallationByInstallId(id);

    if (!installation) {
      return res.status(404).json({ error: 'not_found' });
    }

    // Store health report
    await db.createHealthReport(installation.id, req.body);

    // Build update object with latest health
    const updateData = {
      last_health_at: new Date().toISOString(),
      last_health: JSON.stringify(req.body),
    };

    // Update architecture from health report if provided (keeps it current)
    if (req.body.system?.arch) {
      // Convert "aarch64-linux" to "aarch64" for display, or keep as-is
      const arch = req.body.system.arch.replace('-linux', '');
      updateData.architecture = arch;
    }

    // Update NixOS version from health report if provided
    if (req.body.system?.nixos_version) {
      updateData.nixos_version = req.body.system.nixos_version;
    }

    await db.updateInstallation(id, updateData);

    console.log(`[HEALTH] ${id}`);
    res.status(204).send();
  } catch (e) {
    console.error('[HEALTH] Error:', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// POST /api/v1/installations/:id/logs
app.post('/api/v1/installations/:id/logs', requireBearerAuth, async (req, res) => {
  const { id } = req.params;
  if (req.tokenPayload.installation_id !== id) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { logs, service, level } = req.body;
  if (!logs || !Array.isArray(logs)) {
    return res.status(400).json({ error: 'logs array required' });
  }

  try {
    const installation = await db.findInstallationByInstallId(id);

    if (!installation) {
      return res.status(404).json({ error: 'not_found' });
    }

    const logEntries = logs.map(log => ({
      timestamp: log.timestamp || new Date().toISOString(),
      service: log.service || service || 'unknown',
      level: log.level || level || 'info',
      message: typeof log === 'string' ? log : log.message,
    }));

    await db.createLogs(installation.id, logEntries);

    console.log(`[LOGS] ${id}: ${logs.length} entries`);
    res.status(204).send();
  } catch (e) {
    console.error('[LOGS] Error:', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// =============================================================================
// Web UI Styles
// =============================================================================

const styles = `
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; }
.container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
.container-narrow { max-width: 500px; }
.logo { font-size: 28px; font-weight: bold; color: #3b82f6; margin-bottom: 40px; text-align: center; }
.card { background: #1a1a1a; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #333; }
h1 { font-size: 24px; margin-bottom: 8px; }
h1 span, h2 span { color: #3b82f6; }
h2 { font-size: 18px; margin-bottom: 16px; color: #888; }
h3 { font-size: 14px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
p { color: #888; margin-bottom: 16px; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 8px; font-size: 14px; color: #999; }
input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 12px 16px; border-radius: 8px; background: #0a0a0a; border: 1px solid #333; color: #fff; font-size: 16px; }
input:focus { outline: none; border-color: #3b82f6; }
.btn { display: inline-block; padding: 12px 24px; border-radius: 8px; border: none; background: #3b82f6; color: #fff; font-weight: 600; font-size: 14px; cursor: pointer; text-decoration: none; text-align: center; }
.btn:hover { background: #2563eb; }
.btn-secondary { background: #333; color: #fff; }
.btn-secondary:hover { background: #444; }
.btn-google { background: #fff; color: #333; border: 1px solid #ddd; display: flex; align-items: center; justify-content: center; gap: 10px; }
.btn-google:hover { background: #f5f5f5; }
.btn-github { background: #24292e; }
.btn-github:hover { background: #1b1f23; }
.btn-full { width: 100%; }
.btn-sm { padding: 8px 16px; font-size: 12px; }
.success { background: #166534; padding: 16px; border-radius: 8px; margin-bottom: 24px; color: #4ade80; }
.error { background: #991b1b; padding: 16px; border-radius: 8px; margin-bottom: 24px; color: #fca5a5; }
.divider { display: flex; align-items: center; margin: 24px 0; color: #666; }
.divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #333; }
.divider span { padding: 0 16px; font-size: 12px; text-transform: uppercase; }
nav { background: #111; border-bottom: 1px solid #333; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
nav .nav-left { display: flex; align-items: center; gap: 24px; }
nav a { color: #888; text-decoration: none; font-size: 14px; }
nav a:hover, nav a.active { color: #3b82f6; }
nav .brand { color: #3b82f6; font-weight: bold; font-size: 18px; }
.status { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
.status.online { background: #166534; color: #4ade80; }
.status.offline { background: #7f1d1d; color: #f87171; }
.status.pending { background: #78350f; color: #fcd34d; }
.status::before { content: ''; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.installation-item { display: flex; justify-content: space-between; align-items: center; padding: 20px; border-bottom: 1px solid #333; cursor: pointer; transition: background 0.2s; }
.installation-item:hover { background: #222; }
.installation-item:last-child { border-bottom: none; }
.installation-info h4 { font-size: 16px; margin-bottom: 4px; }
.installation-info p { font-size: 13px; color: #666; margin: 0; }
.metric { text-align: center; padding: 20px; }
.metric-value { font-size: 32px; font-weight: bold; color: #fff; margin-bottom: 4px; }
.metric-label { font-size: 12px; color: #666; text-transform: uppercase; }
.metric-sub { font-size: 11px; color: #555; margin-top: 4px; }
.progress { height: 8px; background: #333; border-radius: 4px; overflow: hidden; margin-top: 8px; }
.progress-bar { height: 100%; border-radius: 4px; }
.progress-bar.green { background: linear-gradient(90deg, #22c55e, #16a34a); }
.progress-bar.yellow { background: linear-gradient(90deg, #eab308, #ca8a04); }
.progress-bar.red { background: linear-gradient(90deg, #ef4444, #dc2626); }
.progress-bar.blue { background: linear-gradient(90deg, #3b82f6, #2563eb); }
.service-card { display: flex; align-items: center; gap: 16px; padding: 20px; background: #111; border-radius: 8px; }
.service-icon { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
.service-icon.ha { background: #18bcf2; }
.service-icon.vpn { background: #8b5cf6; }
.service-info { flex: 1; }
.service-info h4 { font-size: 14px; margin-bottom: 4px; }
.service-info p { font-size: 12px; color: #666; margin: 0; }
.timeline { padding: 0; }
.timeline-item { display: flex; gap: 16px; padding: 12px 0; position: relative; }
.timeline-item::before { content: ''; position: absolute; left: 11px; top: 32px; bottom: 0; width: 2px; background: #333; }
.timeline-item:last-child::before { display: none; }
.timeline-dot { width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0; }
.timeline-dot.green { background: #166534; color: #4ade80; }
.timeline-dot.blue { background: #1e3a8a; color: #60a5fa; }
.two-col { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
.code { font-family: monospace; font-size: 32px; letter-spacing: 4px; text-align: center; background: #0a0a0a; padding: 20px; border-radius: 8px; margin: 20px 0; }
.log-entry { font-family: monospace; font-size: 12px; padding: 8px 12px; border-bottom: 1px solid #222; display: flex; gap: 8px; }
.log-entry .time { color: #666; white-space: nowrap; }
.log-entry .service { color: #3b82f6; white-space: nowrap; }
.log-entry .msg { color: #ccc; word-break: break-word; }
.log-entry.error { background: rgba(239, 68, 68, 0.1); }
.log-entry.error .msg { color: #ef4444; }
.log-entry.warning { background: rgba(234, 179, 8, 0.1); }
.log-entry.warning .msg { color: #eab308; }
.log-tabs { display: flex; gap: 4px; }
.log-tab { background: transparent; border: 1px solid #333; color: #888; padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: all 0.2s; }
.log-tab:hover { border-color: #555; color: #fff; }
.log-tab.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
`;

const html = (title, content, user = null) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - Kaliun Connect</title>
  <style>${styles}</style>
</head>
<body>
  ${user ? `<nav>
    <div class="nav-left">
      <a href="/" class="brand">⚡ Kaliun</a>
      <a href="/installations">Installations</a>
      <a href="/settings">Settings</a>
    </div>
    <a href="/logout">Logout</a>
  </nav>` : ''}
  <div class="container ${!user ? 'container-narrow' : ''}">
    ${!user ? '<div class="logo">⚡ Kaliun</div>' : ''}
    ${content}
  </div>
</body>
</html>`;

// =============================================================================
// Auth Routes (Supabase)
// =============================================================================

// GET /login
app.get('/login', (req, res) => {
  const { error, message } = req.query;
  res.send(html('Login', `
    <script>
      // Handle OAuth tokens in URL fragment
      console.log('[CLIENT] Checking URL hash...');
      console.log('[CLIENT] Hash:', window.location.hash ? 'present' : 'empty');
      if (window.location.hash) {
        const params = new URLSearchParams(window.location.hash.substring(1));
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');
        console.log('[CLIENT] access_token:', accessToken ? 'found' : 'not found');
        console.log('[CLIENT] refresh_token:', refreshToken ? 'found' : 'not found');
        if (accessToken) {
          console.log('[CLIENT] Sending tokens to server...');
          // Send tokens to server
          fetch('/auth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ access_token: accessToken, refresh_token: refreshToken })
          }).then(res => {
            console.log('[CLIENT] Server response:', res.status);
            if (res.ok) {
              console.log('[CLIENT] Success! Redirecting to /installations');
              window.location.href = '/installations';
            } else {
              console.error('[CLIENT] Server returned error');
              window.location.href = '/login?error=Auth failed';
            }
          }).catch(err => {
            console.error('[CLIENT] Fetch error:', err);
            window.location.href = '/login?error=Auth failed';
          });
        }
      }
    </script>
    <div class="card">
      <h1>Welcome Back</h1>
      <p>Sign in to your account</p>
      ${error ? `<div class="error">${error}</div>` : ''}
      ${message ? `<div class="success">${message}</div>` : ''}
      
      <a href="/auth/google" class="btn btn-google btn-full" style="margin-bottom: 12px;">
        <svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z"/><path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/></svg>
        Continue with Google
      </a>
      
      <a href="/auth/github" class="btn btn-github btn-full" style="margin-bottom: 12px;">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
        Continue with GitHub
      </a>
      
      <div class="divider"><span>or</span></div>
      
      <form action="/auth/login" method="POST">
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required placeholder="••••••••">
        </div>
        <button type="submit" class="btn btn-full">Sign In</button>
      </form>
      <p style="text-align: center; margin-top: 20px;">
        Don't have an account? <a href="/register" style="color: #3b82f6;">Sign up</a>
      </p>
    </div>
  `));
});

// GET /register
app.get('/register', (req, res) => {
  const { error } = req.query;
  res.send(html('Register', `
    <div class="card">
      <h1>Create Account</h1>
      <p>Sign up to get started</p>
      ${error ? `<div class="error">${error}</div>` : ''}
      
      <a href="/auth/google" class="btn btn-google btn-full" style="margin-bottom: 12px;">
        <svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z"/><path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/></svg>
        Sign up with Google
      </a>
      
      <div class="divider"><span>or</span></div>
      
      <form action="/auth/register" method="POST">
        <div class="form-group">
          <label>Name</label>
          <input type="text" name="name" required placeholder="Your name">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required placeholder="At least 8 characters" minlength="8">
        </div>
        <button type="submit" class="btn btn-full">Create Account</button>
      </form>
      <p style="text-align: center; margin-top: 20px;">
        Already have an account? <a href="/login" style="color: #3b82f6;">Sign in</a>
      </p>
    </div>
  `));
});

// POST /auth/register
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.redirect('/register?error=All fields required');
  }
  
  try {
    // LOCAL DEV MODE: Create user directly in DB
    if (isLocalDev) {
      console.log('[REGISTER] Using LOCAL auth (direct DB)...');
      
      // Check if user exists
      const existing = await db.findUserByEmail(email);
      if (existing) {
        return res.redirect('/register?error=Email already registered');
      }
      
      // Create user
      const user = await db.createUser({ email, password, name });
      console.log('[REGISTER] Created user:', user.id);
      
      // Create session
      const session = await db.createSession(user.id);
      console.log('[REGISTER] Created session');
      
      res.cookie('sb_access_token', session.token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
      return res.redirect('/installations');
    }
    
    // PRODUCTION: Use Supabase Admin API to create auto-confirmed user
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true, // Auto-confirm, no email needed
      user_metadata: { name },
    });
    
    if (error) {
      return res.redirect(`/register?error=${encodeURIComponent(error.message)}`);
    }
    
    // Now sign them in to get a session
    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    
    if (signInError) {
      return res.redirect(`/login?error=${encodeURIComponent(signInError.message)}`);
    }
    
    res.cookie('sb_access_token', signInData.session.access_token, { httpOnly: true, maxAge: 3600000 });
    res.cookie('sb_refresh_token', signInData.session.refresh_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    return res.redirect('/installations');
  } catch (e) {
    console.error('Register error:', e);
    res.redirect(`/register?error=${encodeURIComponent(e.message || 'Registration failed')}`);
  }
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.redirect('/login?error=Email and password required');
  }
  
  try {
    // LOCAL DEV MODE: Check password directly in DB
    if (isLocalDev) {
      console.log('[LOGIN] Using LOCAL auth (direct DB)...');
      
      const user = await db.findUserByEmail(email);
      if (!user) {
        return res.redirect('/login?error=Invalid email or password');
      }
      
      const valid = await db.verifyPassword(user, password);
      if (!valid) {
        return res.redirect('/login?error=Invalid email or password');
      }
      
      console.log('[LOGIN] User verified:', user.id);
      
      // Create session
      const session = await db.createSession(user.id);
      console.log('[LOGIN] Created session');
      
      res.cookie('sb_access_token', session.token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
      return res.redirect('/installations');
    }
    
    // PRODUCTION: Use Supabase Auth
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    
    if (error) {
      return res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
    }
    
    res.cookie('sb_access_token', data.session.access_token, { httpOnly: true, maxAge: 3600000 });
    res.cookie('sb_refresh_token', data.session.refresh_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect('/installations');
  } catch (e) {
    console.error('Login error:', e);
    res.redirect(`/login?error=${encodeURIComponent(e.message || 'Login failed')}`);
  }
});

// GET /auth/google - Redirect to Google OAuth
app.get('/auth/google', async (req, res) => {
  console.log('[AUTH] Google OAuth initiated');
  console.log('[AUTH] Redirect URL:', `${BASE_URL}/auth/callback`);
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${BASE_URL}/auth/callback`,
    },
  });
  
  if (error) {
    console.error('[AUTH] Google OAuth error:', error.message);
    return res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
  }
  
  console.log('[AUTH] Redirecting to:', data.url);
  res.redirect(data.url);
});

// GET /auth/github - Redirect to GitHub OAuth
app.get('/auth/github', async (req, res) => {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'github',
    options: {
      redirectTo: `${BASE_URL}/auth/callback`,
    },
  });
  
  if (error) {
    return res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
  }
  
  res.redirect(data.url);
});

// GET /auth/callback - OAuth callback (for authorization code flow)
app.get('/auth/callback', async (req, res) => {
  console.log('[AUTH] Callback received');
  console.log('[AUTH] Query params:', req.query);
  
  const code = req.query.code;
  
  if (!code) {
    console.log('[AUTH] No code in callback, redirecting to login (tokens may be in fragment)');
    // No code, redirect to login (tokens might be in fragment)
    return res.redirect('/login');
  }
  
  try {
    console.log('[AUTH] Exchanging code for session...');
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    
    if (error) {
      console.error('[AUTH] Exchange error:', error.message);
      return res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
    }
    
    console.log('[AUTH] Session obtained, user:', data.user?.email);
    res.cookie('sb_access_token', data.session.access_token, { httpOnly: true, maxAge: 3600000 });
    res.cookie('sb_refresh_token', data.session.refresh_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect('/installations');
  } catch (e) {
    console.error('[AUTH] OAuth callback error:', e);
    res.redirect('/login?error=OAuth failed');
  }
});

// POST /auth/token - Receive tokens from client-side (implicit flow)
app.post('/auth/token', async (req, res) => {
  console.log('[AUTH] Token POST received');
  console.log('[AUTH] Has access_token:', !!req.body.access_token);
  console.log('[AUTH] Has refresh_token:', !!req.body.refresh_token);
  
  const { access_token, refresh_token } = req.body;
  
  if (!access_token) {
    console.error('[AUTH] No access_token in request');
    return res.status(400).json({ error: 'access_token required' });
  }
  
  try {
    console.log('[AUTH] Verifying token with Supabase...');
    // Verify the token is valid by getting the user
    const { data: { user }, error } = await supabase.auth.getUser(access_token);
    
    if (error || !user) {
      console.error('[AUTH] Token verification failed:', error?.message || 'No user');
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    console.log('[AUTH] Token valid, user:', user.email);
    // Set cookies
    res.cookie('sb_access_token', access_token, { httpOnly: true, maxAge: 3600000 });
    if (refresh_token) {
      res.cookie('sb_refresh_token', refresh_token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    }
    
    console.log('[AUTH] Cookies set, returning success');
    res.json({ success: true });
  } catch (e) {
    console.error('[AUTH] Token error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /logout
app.get('/logout', async (req, res) => {
  const token = req.cookies.sb_access_token;
  
  if (isLocalDev && token) {
    // Delete local session
    await db.deleteSession(token).catch(() => {});
  } else {
    await supabase.auth.signOut();
  }
  
  res.clearCookie('sb_access_token');
  res.clearCookie('sb_refresh_token');
  res.redirect('/login');
});

// =============================================================================
// Dashboard Routes
// =============================================================================

// GET /installations - List all installations
app.get('/installations', requireAuth, async (req, res) => {
  const { success } = req.query;
  
  // Use Supabase Auth ID consistently (not DB user ID)
  const userId = req.supabaseUser.id;
  console.log('[INSTALLATIONS] Loading for user:', userId);
  console.log('[INSTALLATIONS] DB user ID:', req.user?.id);
  
  try {
    // Use direct PostgreSQL query
    const installations = await db.findInstallationsByUserId(userId);
    console.log('[INSTALLATIONS] Found:', installations?.length || 0, 'installations');

    const list = installations?.length ? installations.map(i => {
      const isOnline = i.last_health_at && (Date.now() - new Date(i.last_health_at).getTime()) < 10 * 60 * 1000;
      return `
        <a href="/installations/${i.install_id}" class="installation-item" style="text-decoration: none; color: inherit;">
          <div class="installation-info">
            <h4>${i.customer_name || i.hostname || 'KaliunBox'}</h4>
            <p>${i.install_id.slice(0, 12)}...</p>
          </div>
          <span class="status ${isOnline ? 'online' : 'offline'}">${isOnline ? 'Online' : 'Offline'}</span>
        </a>`;
    }).join('') : `
      <div style="text-align: center; padding: 60px 20px; color: #666;">
        <p style="font-size: 48px; margin-bottom: 16px;">📦</p>
        <h3 style="color: #888;">No installations yet</h3>
        <p>Scan a KaliunBox QR code to claim your first device.</p>
        <a href="/claim" class="btn" style="margin-top: 16px;">Claim a Device</a>
      </div>`;

    res.send(html('My Installations', `
      <h1>My <span>Installations</span></h1>
      <p>View your Kaliun installations</p>
      ${success ? `<div class="success">${success}</div>` : ''}
      <div class="card" style="padding: 0; overflow: hidden;">${list}</div>
    `, req.user));
  } catch (e) {
    console.error('[INSTALLATIONS] Error:', e.message, e);
    res.send(html('Error', `<div class="error">Failed to load installations: ${e.message}</div>`, req.user));
  }
});

// GET /installations/:id - Detailed dashboard
app.get('/installations/:id', requireAuth, async (req, res) => {
  try {
    const installation = await db.findInstallationByInstallId(req.params.id);
    
    // Check ownership
    if (!installation || installation.claimed_by !== req.supabaseUser.id) {
      return res.redirect('/installations');
    }
    
    const isOnline = installation.last_health_at && (Date.now() - new Date(installation.last_health_at).getTime()) < 10 * 60 * 1000;
    const health = typeof installation.last_health === 'string' 
      ? JSON.parse(installation.last_health || '{}') 
      : (installation.last_health || {});
    
    // Get logs
    const logs = await db.getInstallationLogs(installation.id, 20);
    
    // Calculate metrics
    const uptime = health.uptime_seconds ? 
      (health.uptime_seconds > 86400 ? `${Math.floor(health.uptime_seconds / 86400)}d ${Math.floor((health.uptime_seconds % 86400) / 3600)}h` :
       health.uptime_seconds > 3600 ? `${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor((health.uptime_seconds % 3600) / 60)}m` :
       `${Math.floor(health.uptime_seconds / 60)}m`) : 'Unknown';
    
    // Health data uses nested structure: health.memory.total_bytes, health.disk.root_total_bytes
    const memoryTotal = health.memory?.total_bytes || 0;
    const memoryUsed = health.memory?.used_bytes || 0;
    const diskTotal = health.disk?.root_total_bytes || 0;
    const diskUsed = health.disk?.root_used_bytes || 0;
    const memoryPercent = memoryTotal ? Math.round((memoryUsed / memoryTotal) * 100) : 0;
    const diskPercent = diskTotal ? Math.round((diskUsed / diskTotal) * 100) : 0;
    
    // Separate logs by category
    // NOTE: log reporter sends systemd unit names (e.g. "homeassistant-vm.service", "kaliun-auto-update.service")
    const isHaService = (s) => {
      if (!s) return false;
      return (
        s.includes('homeassistant') ||
        s.includes('havm') ||
        s === 'homeassistant-vm.service'
      );
    };
    const isAutoUpdateService = (s) => {
      if (!s) return false;
      return s.includes('kaliun-auto-update') || s.includes('auto-update');
    };

    const haLogs = logs?.filter(l => isHaService(l.service)) || [];
    const updateLogs = logs?.filter(l => isAutoUpdateService(l.service)) || [];
    const systemLogs = logs?.filter(l => !isHaService(l.service) && !isAutoUpdateService(l.service)) || [];
    
    const renderLogs = (logList) => logList.length ? logList.map(log => `
      <div class="log-entry ${log.level}">
        <span class="time">${new Date(log.timestamp).toLocaleTimeString()}</span>
        <span class="service">[${log.service?.replace('.service', '') || 'system'}]</span>
        <span class="msg">${log.message}</span>
      </div>
    `).join('') : '<p style="padding: 20px; color: #666; text-align: center;">No logs</p>';
    
    const allLogsHtml = renderLogs(logs || []);
    const haLogsHtml = renderLogs(haLogs);
    const updateLogsHtml = renderLogs(updateLogs);
    const systemLogsHtml = renderLogs(systemLogs);

    res.send(html(`${installation.customer_name || 'KaliunBox'}`, `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
          <a href="/installations" style="color: #666; text-decoration: none; font-size: 14px;">← Back</a>
          <h1 style="margin-top: 8px;">${installation.customer_name || 'KaliunBox'}</h1>
        </div>
        <span class="status ${isOnline ? 'online' : 'offline'}">${isOnline ? 'Online' : 'Offline'}</span>
      </div>
      
      <div class="two-col">
        <div>
          <div class="card">
            <h3>Status</h3>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px;">
              <div>
                <div style="color: #666; font-size: 12px;">Status</div>
                <span class="status ${isOnline ? 'online' : 'offline'}" style="margin-top: 8px;">${isOnline ? 'Online' : 'Offline'}</span>
              </div>
              <div>
                <div style="color: #666; font-size: 12px;">Last Seen</div>
                <div style="margin-top: 8px;">${timeAgo(installation.last_health_at)}</div>
              </div>
              <div>
                <div style="color: #666; font-size: 12px;">Uptime</div>
                <div style="margin-top: 8px;">${uptime}</div>
              </div>
            </div>
          </div>
          
          <div class="card">
            <h3>Services</h3>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-top: 16px;">
              <div class="service-card">
                <div class="service-icon ha">🏠</div>
                <div class="service-info">
                  <h4>Home Assistant</h4>
                  <p>${health.home_assistant?.version || 'Unknown'}</p>
                </div>
                <span class="status ${health.home_assistant?.status === 'running' ? 'online' : 'offline'}">${health.home_assistant?.status === 'running' ? 'Running' : 'Stopped'}</span>
              </div>
              <div class="service-card">
                <div class="service-icon vpn">🔐</div>
                <div class="service-info">
                  <h4>Remote Access</h4>
                  <p>VPN tunnel</p>
                </div>
                <span class="status ${health.newt_connected ? 'online' : 'pending'}">${health.newt_connected ? 'Online' : 'Not configured'}</span>
              </div>
            </div>
          </div>
          
          <div class="card">
            <h3>Health</h3>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-top: 16px;">
              <div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                  <span>Memory</span><span>${memoryPercent}%</span>
                </div>
                <div class="progress">
                  <div class="progress-bar ${memoryPercent > 90 ? 'red' : memoryPercent > 70 ? 'yellow' : 'green'}" style="width: ${memoryPercent}%"></div>
                </div>
                <div style="font-size: 11px; color: #666; margin-top: 4px;">${formatBytes(memoryUsed)} / ${formatBytes(memoryTotal)}</div>
              </div>
              <div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                  <span>Disk</span><span>${diskPercent}%</span>
                </div>
                <div class="progress">
                  <div class="progress-bar ${diskPercent > 90 ? 'red' : diskPercent > 70 ? 'yellow' : 'blue'}" style="width: ${diskPercent}%"></div>
                </div>
                <div style="font-size: 11px; color: #666; margin-top: 4px;">${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}</div>
              </div>
            </div>
          </div>
          
          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <h3>Logs</h3>
              <div class="log-tabs">
                <button class="log-tab active" data-tab="all">All (${logs?.length || 0})</button>
                <button class="log-tab" data-tab="ha">Home Assistant (${haLogs.length})</button>
                <button class="log-tab" data-tab="update">Auto Update (${updateLogs.length})</button>
                <button class="log-tab" data-tab="system">System (${systemLogs.length})</button>
              </div>
            </div>
            <div style="max-height: 400px; overflow-y: auto; margin-top: 16px; background: #111; border-radius: 8px;">
              <div class="log-content" data-content="all">${allLogsHtml}</div>
              <div class="log-content" data-content="ha" style="display:none;">${haLogsHtml}</div>
              <div class="log-content" data-content="update" style="display:none;">${updateLogsHtml}</div>
              <div class="log-content" data-content="system" style="display:none;">${systemLogsHtml}</div>
            </div>
          </div>
          <script>
            document.querySelectorAll('.log-tab').forEach(tab => {
              tab.addEventListener('click', () => {
                document.querySelectorAll('.log-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const target = tab.dataset.tab;
                document.querySelectorAll('.log-content').forEach(c => c.style.display = 'none');
                document.querySelector('.log-content[data-content="' + target + '"]').style.display = 'block';
              });
            });
          </script>
        </div>
        
        <div>
          <div class="card">
            <h3>Homeowner</h3>
            <div style="margin-top: 16px;">
              <div style="color: #666; font-size: 12px;">Name</div>
              <div style="margin-top: 4px;">${installation.customer_name || 'Not set'}</div>
            </div>
            <div style="margin-top: 16px;">
              <div style="color: #666; font-size: 12px;">Email</div>
              <div style="margin-top: 4px;">${installation.customer_email || 'Not set'}</div>
            </div>
          </div>
          
          <div class="card">
            <h3>System</h3>
            <div style="margin-top: 16px; font-size: 13px;">
              <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333;">
                <span style="color: #666;">Host IP</span>
                <span>${health.network?.host_ip || 'Unknown'}</span>
              </div>
              <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333;">
                <span style="color: #666;">Architecture</span>
                <span>${installation.architecture || 'x86_64'}</span>
              </div>
              <div style="display: flex; justify-content: space-between; padding: 8px 0;">
                <span style="color: #666;">NixOS</span>
                <span>${health.system?.nixos_version || installation.nixos_version || 'Unknown'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `, req.user));
  } catch (e) {
    console.error('Installation detail error:', e);
    res.redirect('/installations');
  }
});

// =============================================================================
// Claim Routes
// =============================================================================

app.get('/claim/:code', requireAuth, async (req, res) => {
  const { code } = req.params;

  try {
    const installation = await db.findInstallationByClaimCode(code);
    
    if (!installation) {
      return res.send(html('Invalid Code', `
        <div class="card">
          <div class="error">Invalid claim code</div>
          <a href="/claim" class="btn btn-secondary">Try Again</a>
        </div>
      `, req.user));
    }

    if (installation.claimed_at) {
      return res.send(html('Already Claimed', `
        <div class="card">
          <div class="error">Device already claimed</div>
          <a href="/installations" class="btn">View Installations</a>
        </div>
      `, req.user));
    }

    res.send(html('Claim Device', `
      <div class="card">
        <h1>Claim Your <span>KaliunBox</span></h1>
        <p>Enter your information to complete setup</p>
        <div class="code">${code}</div>
        <form action="/claim/${code}" method="POST">
          <div class="form-group">
            <label>Your Name</label>
            <input type="text" name="customer_name" required value="${req.user.name || req.user.email?.split('@')[0] || ''}">
          </div>
          <div class="form-group">
            <label>Email</label>
            <input type="email" name="customer_email" required value="${req.user.email}">
          </div>
          <div class="form-group">
            <label>Address (optional)</label>
            <input type="text" name="customer_address">
          </div>
          <button type="submit" class="btn btn-full">Complete Setup</button>
        </form>
      </div>
    `, req.user));
  } catch (e) {
    console.error('Claim error:', e);
    res.redirect('/claim');
  }
});

app.get('/claim', (req, res) => {
  res.send(html('Claim Device', `
    <div class="card">
      <h1>Claim Your <span>Device</span></h1>
      <p>Enter the code displayed on your KaliunBox</p>
      <form action="/claim" method="POST">
        <div class="form-group">
          <label>Claim Code</label>
          <input type="text" name="code" required placeholder="ABC123" style="text-transform: uppercase; text-align: center; font-size: 24px;">
        </div>
        <button type="submit" class="btn btn-full">Continue</button>
      </form>
    </div>
  `));
});

app.post('/claim', (req, res) => {
  res.redirect(`/claim/${req.body.code.toUpperCase()}`);
});

app.post('/claim/:code', requireAuth, async (req, res) => {
  const { code } = req.params;
  const { customer_name, customer_email, customer_address } = req.body;

  // Use Supabase Auth ID consistently (same as /installations query)
  const userId = req.supabaseUser.id;
  console.log('[CLAIM] Attempting to claim code:', code);
  console.log('[CLAIM] Supabase User ID:', userId);
  console.log('[CLAIM] DB User ID:', req.user?.id);
  console.log('[CLAIM] User email:', req.user?.email);

  try {
    const installation = await db.findInstallationByClaimCode(code);
    console.log('[CLAIM] Found installation:', installation?.install_id || 'NOT FOUND');
    
    if (!installation) {
      console.log('[CLAIM] Installation not found for code:', code);
      return res.redirect('/claim?error=Invalid code');
    }
    
    if (installation.claimed_at) {
      console.log('[CLAIM] Already claimed at:', installation.claimed_at);
      return res.redirect('/claim?error=Already claimed');
    }

    await db.claimInstallation(code, userId, customer_name, customer_email, customer_address);

    console.log(`[CLAIM] Success! ${installation.install_id} claimed by ${req.user.email}`);
    res.redirect('/installations?success=Device claimed!');
  } catch (e) {
    console.error('[CLAIM] Error:', e.message, e.stack);
    res.redirect(`/claim?error=${encodeURIComponent(e.message || 'Failed')}`);
  }
});

// Settings
app.get('/settings', requireAuth, async (req, res) => {
  // Get DB user for debugging
  const dbUser = await db.findUserByEmail(req.user.email).catch(() => null);
  
  res.send(html('Settings', `
    <h1><span>Account</span> Settings</h1>
    <div class="card">
      <h3>Profile</h3>
      <form action="/settings/profile" method="POST" style="margin-top: 16px;">
        <div class="form-group">
          <label>Name</label>
          <input type="text" name="name" value="${req.user.name || ''}">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" disabled value="${req.user.email}">
        </div>
        <button type="submit" class="btn">Save Changes</button>
      </form>
    </div>
    
    <div class="card" style="margin-top: 24px; background: #1a1a2e; border: 1px solid #333;">
      <h3>🔧 Debug Info</h3>
      <div style="font-family: monospace; font-size: 12px; margin-top: 12px;">
        <div style="margin-bottom: 8px;">
          <span style="color: #888;">Supabase Auth ID:</span><br>
          <code style="color: #4ade80;">${req.supabaseUser?.id || 'N/A'}</code>
        </div>
        <div style="margin-bottom: 8px;">
          <span style="color: #888;">DB User ID:</span><br>
          <code style="color: #60a5fa;">${dbUser?.id || 'NOT IN DB'}</code>
        </div>
        <div style="margin-bottom: 8px;">
          <span style="color: #888;">IDs Match:</span>
          <code style="color: ${req.supabaseUser?.id === dbUser?.id ? '#4ade80' : '#f87171'};">
            ${req.supabaseUser?.id === dbUser?.id ? '✅ YES' : '❌ NO - MISMATCH!'}
          </code>
        </div>
        <div style="margin-bottom: 8px;">
          <span style="color: #888;">Provider:</span>
          <code style="color: #fbbf24;">${dbUser?.provider || req.supabaseUser?.app_metadata?.provider || 'unknown'}</code>
        </div>
        <div style="margin-bottom: 8px;">
          <span style="color: #888;">Local Dev Mode:</span>
          <code style="color: #c084fc;">${isLocalDev ? 'YES' : 'NO (Production)'}</code>
        </div>
      </div>
    </div>
  `, req.user));
});

app.post('/settings/profile', requireAuth, async (req, res) => {
  console.log('[SETTINGS] Updating profile for:', req.user.email);
  console.log('[SETTINGS] New name:', req.body.name);
  
  try {
    // LOCAL DEV: Update directly in database
    if (isLocalDev) {
      await db.updateUser(req.user.id, { name: req.body.name });
      console.log('[SETTINGS] Profile updated in DB');
    } else {
      // PRODUCTION: Update Supabase Auth user metadata
      const { error } = await supabaseAdmin.auth.admin.updateUserById(
        req.supabaseUser.id,
        { user_metadata: { name: req.body.name } }
      );
      
      if (error) {
        console.error('[SETTINGS] Update failed:', error.message);
      } else {
        // Also update in users table
        await db.updateUser(req.user.id, { name: req.body.name }).catch(() => {});
        console.log('[SETTINGS] Profile updated successfully');
      }
    }
  } catch (e) {
    console.error('[SETTINGS] Error:', e.message);
  }
  
  res.redirect('/settings');
});

// Root
app.get('/', (req, res) => {
  const accessToken = req.cookies.sb_access_token;
  if (accessToken) {
    return res.redirect('/installations');
  }
  res.redirect('/login');
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  ⚡ Kaliun Connect API v2 (Supabase)                          ║
║  Server: ${BASE_URL.padEnd(51)}║
║  Supabase: ${supabaseUrl.padEnd(49)}║
╚═══════════════════════════════════════════════════════════════╝
  `);
});
