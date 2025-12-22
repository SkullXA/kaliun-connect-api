/**
 * Kaliun Connect API
 * 
 * Device registration, claiming, OAuth2 Device Code Flow for Home Assistant
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 7331;
const JWT_SECRET = process.env.JWT_SECRET || 'kaliun-dev-secret-change-in-production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Token lifetimes
const ACCESS_TOKEN_LIFETIME = 7 * 24 * 60 * 60; // 7 days
const REFRESH_TOKEN_LIFETIME = 90 * 24 * 60 * 60; // 90 days
const DEVICE_CODE_LIFETIME = 900; // 15 minutes

// Simple JSON file-based database
const DB_PATH = process.env.DATABASE_PATH || './data.json';
let db = {
  users: {},
  installations: {},
  healthReports: [],
  deviceCodes: {},
  sessions: {},
  magicLinks: {},
};

// Load DB from file
function loadDb() {
  try {
    if (fs.existsSync(DB_PATH)) {
      db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.log('Starting with fresh database');
  }
}

// Save DB to file
function saveDb() {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

loadDb();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
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

// Auth middleware
function requireAuth(req, res, next) {
  const sessionId = req.cookies.session;
  if (!sessionId) return res.redirect('/login');

  const session = db.sessions[sessionId];
  if (!session || new Date(session.expiresAt) < new Date()) {
    res.clearCookie('session');
    return res.redirect('/login');
  }

  const user = db.users[session.userId];
  if (!user) return res.redirect('/login');

  req.user = user;
  next();
}

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
// DEVICE APIs
// =============================================================================

// POST /api/v1/installations/register
app.post('/api/v1/installations/register', (req, res) => {
  const { install_id, hostname } = req.body;
  if (!install_id) return res.status(400).json({ error: 'install_id is required' });

  if (db.installations[install_id]) {
    return res.json({ claim_code: db.installations[install_id].claimCode });
  }

  const claimCode = generateClaimCode();
  db.installations[install_id] = {
    id: install_id,
    hostname: hostname || 'kaliunbox',
    claimCode,
    createdAt: new Date().toISOString(),
  };
  saveDb();

  console.log(`[REGISTER] ${install_id} → ${claimCode}`);
  res.status(201).json({ claim_code: claimCode });
});

// GET /api/v1/installations/:id/config
app.get('/api/v1/installations/:id/config', (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers.authorization;
  const installation = db.installations[id];

  if (!installation) {
    return res.status(404).json({ error: 'not_found' });
  }

  if (!installation.claimedAt) {
    return res.status(404).json({ error: 'not_claimed' });
  }

  // If already confirmed, require bearer auth
  if (installation.configConfirmed && !authHeader) {
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
    return res.json({
      customer: {
        name: installation.customerName || '',
        email: installation.customerEmail || '',
        address: installation.customerAddress || '',
      },
      pangolin: {
        newt_id: `newt_${id.slice(0, 8)}`,
        newt_secret: `secret_${randomUUID()}`,
        endpoint: 'https://pangolin.kaliun.com',
      },
    });
  }

  // Bootstrap - generate tokens
  const now = new Date();
  const accessToken = generateToken({ installation_id: id, type: 'access' }, ACCESS_TOKEN_LIFETIME);
  const refreshToken = generateToken({ installation_id: id, type: 'refresh' }, REFRESH_TOKEN_LIFETIME);

  installation.accessToken = accessToken;
  installation.refreshToken = refreshToken;
  installation.accessExpiresAt = addSeconds(now, ACCESS_TOKEN_LIFETIME);
  installation.refreshExpiresAt = addSeconds(now, REFRESH_TOKEN_LIFETIME);
  saveDb();

  console.log(`[CONFIG] Bootstrap for: ${id}`);

  res.json({
    auth: {
      access_token: accessToken,
      refresh_token: refreshToken,
      access_expires_at: installation.accessExpiresAt,
      refresh_expires_at: installation.refreshExpiresAt,
    },
    customer: {
      name: installation.customerName || '',
      email: installation.customerEmail || '',
      address: installation.customerAddress || '',
    },
    pangolin: {
      newt_id: `newt_${id.slice(0, 8)}`,
      newt_secret: `secret_${randomUUID()}`,
      endpoint: 'https://pangolin.kaliun.com',
    },
  });
});

// DELETE /api/v1/installations/:id/config
app.delete('/api/v1/installations/:id/config', (req, res) => {
  const { id } = req.params;
  const installation = db.installations[id];

  if (!installation) return res.status(404).json({ error: 'not_found' });

  installation.configConfirmed = true;
  saveDb();

  console.log(`[CONFIG] Confirmed: ${id}`);
  res.status(204).send();
});

// POST /api/v1/installations/token/refresh
app.post('/api/v1/installations/token/refresh', (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token is required' });

  const payload = verifyToken(refresh_token);
  if (!payload || payload.type !== 'refresh') {
    return res.status(401).json({ error: 'invalid_grant' });
  }

  const installation = db.installations[payload.installation_id];
  if (!installation) return res.status(401).json({ error: 'invalid_grant' });

  const now = new Date();
  const newAccessToken = generateToken({ installation_id: payload.installation_id, type: 'access' }, ACCESS_TOKEN_LIFETIME);

  installation.accessToken = newAccessToken;
  installation.accessExpiresAt = addSeconds(now, ACCESS_TOKEN_LIFETIME);
  saveDb();

  console.log(`[TOKEN] Refreshed: ${payload.installation_id}`);
  res.json({
    access_token: newAccessToken,
    access_expires_at: installation.accessExpiresAt,
  });
});

// POST /api/v1/installations/:id/health
app.post('/api/v1/installations/:id/health', requireBearerAuth, (req, res) => {
  const { id } = req.params;
  if (req.tokenPayload.installation_id !== id) {
    return res.status(403).json({ error: 'forbidden' });
  }

  db.healthReports.push({ installationId: id, data: req.body, createdAt: new Date().toISOString() });
  if (db.healthReports.length > 1000) db.healthReports = db.healthReports.slice(-500);
  
  const installation = db.installations[id];
  if (installation) installation.lastHealthAt = new Date().toISOString();
  saveDb();

  console.log(`[HEALTH] ${id}`);
  res.status(204).send();
});

// =============================================================================
// OAuth2 Device Code Flow
// =============================================================================

// POST /oauth/device/code
app.post('/oauth/device/code', (req, res) => {
  const { client_id, scope } = req.body;
  if (!client_id) return res.status(400).json({ error: 'invalid_request' });

  const deviceCode = randomUUID();
  const userCode = generateUserCode();

  db.deviceCodes[deviceCode] = {
    deviceCode,
    userCode,
    clientId: client_id,
    scope: scope || 'profile',
    expiresAt: addSeconds(new Date(), DEVICE_CODE_LIFETIME),
    authorized: false,
  };
  saveDb();

  console.log(`[OAUTH] Device code: ${userCode}`);

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${BASE_URL}/link`,
    verification_uri_complete: `${BASE_URL}/link?code=${userCode}`,
    expires_in: DEVICE_CODE_LIFETIME,
    interval: 5,
  });
});

// POST /oauth/token
app.post('/oauth/token', (req, res) => {
  const { grant_type, device_code, refresh_token } = req.body;

  // Handle refresh token
  if (grant_type === 'refresh_token') {
    if (!refresh_token) return res.status(400).json({ error: 'invalid_request' });

    const payload = verifyToken(refresh_token);
    if (!payload || payload.type !== 'oauth_refresh') {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const user = db.users[payload.user_id];
    if (!user) return res.status(400).json({ error: 'invalid_grant' });

    return res.json({
      access_token: generateToken({ user_id: user.id, type: 'oauth_access' }, 3600),
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: generateToken({ user_id: user.id, type: 'oauth_refresh' }, 30 * 24 * 60 * 60),
      scope: 'profile',
    });
  }

  // Handle device code
  if (grant_type !== 'urn:ietf:params:oauth:grant-type:device_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (!device_code) return res.status(400).json({ error: 'invalid_request' });

  const dc = db.deviceCodes[device_code];
  if (!dc) return res.status(400).json({ error: 'invalid_grant' });

  if (new Date(dc.expiresAt) < new Date()) {
    delete db.deviceCodes[device_code];
    saveDb();
    return res.status(400).json({ error: 'expired_token' });
  }

  if (!dc.authorized || !dc.userId) {
    return res.status(400).json({ error: 'authorization_pending' });
  }

  const user = db.users[dc.userId];
  if (!user) return res.status(400).json({ error: 'invalid_grant' });

  delete db.deviceCodes[device_code];
  saveDb();

  console.log(`[OAUTH] Token issued: ${user.email}`);

  res.json({
    access_token: generateToken({ user_id: user.id, type: 'oauth_access' }, 3600),
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: generateToken({ user_id: user.id, type: 'oauth_refresh' }, 30 * 24 * 60 * 60),
    scope: dc.scope || 'profile',
  });
});

// GET /oauth/userinfo
app.get('/oauth/userinfo', requireBearerAuth, (req, res) => {
  if (req.tokenPayload.type !== 'oauth_access') {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const user = db.users[req.tokenPayload.user_id];
  if (!user) return res.status(401).json({ error: 'invalid_token' });

  res.json({ sub: user.id, name: user.name || user.email, email: user.email });
});

// =============================================================================
// Web UI
// =============================================================================

const styles = `
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; }
.container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
.logo { font-size: 28px; font-weight: bold; color: #f59e0b; margin-bottom: 40px; text-align: center; }
.card { background: #1a1a1a; border-radius: 12px; padding: 32px; margin-bottom: 24px; border: 1px solid #333; }
h1 { font-size: 24px; margin-bottom: 8px; }
h1 span { color: #f59e0b; }
p { color: #888; margin-bottom: 24px; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 8px; font-size: 14px; color: #999; }
input[type="text"], input[type="email"] { width: 100%; padding: 12px 16px; border-radius: 8px; background: #0a0a0a; border: 1px solid #333; color: #fff; font-size: 16px; }
input:focus { outline: none; border-color: #f59e0b; }
.btn { width: 100%; padding: 14px; border-radius: 8px; border: none; background: #f59e0b; color: #000; font-weight: 600; font-size: 16px; cursor: pointer; }
.btn:hover { background: #d97706; }
.btn-secondary { background: #333; color: #fff; }
.success { background: #166534; padding: 16px; border-radius: 8px; margin-bottom: 24px; }
.error { background: #991b1b; padding: 16px; border-radius: 8px; margin-bottom: 24px; }
.code { font-family: monospace; font-size: 32px; letter-spacing: 4px; text-align: center; background: #0a0a0a; padding: 20px; border-radius: 8px; margin: 20px 0; }
nav { background: #111; border-bottom: 1px solid #333; padding: 16px 24px; }
nav a { color: #888; text-decoration: none; margin-right: 24px; }
nav a:hover, nav a.active { color: #f59e0b; }
.installation { padding: 20px; border-bottom: 1px solid #333; }
.status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
.status.online { background: #166534; color: #4ade80; }
.status.offline { background: #7f1d1d; color: #f87171; }
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
    <a href="/" style="color: #f59e0b; font-weight: bold;">⚡ Kaliun</a>
    <a href="/project">My Project</a>
    <a href="/installations">Installations</a>
    <a href="/settings">Settings</a>
    <a href="/logout" style="float: right;">Logout</a>
  </nav>` : ''}
  <div class="container">
    ${!user ? '<div class="logo">⚡ Kaliun</div>' : ''}
    ${content}
  </div>
</body>
</html>`;

// GET /login
app.get('/login', (req, res) => {
  const { error, success } = req.query;
  res.send(html('Login', `
    <div class="card">
      <h1>Welcome Back</h1>
      <p>Sign in to your account</p>
      ${error ? `<div class="error">${error}</div>` : ''}
      ${success ? `<div class="success">${success}</div>` : ''}
      <form action="/auth/magic-link" method="POST">
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" required placeholder="you@example.com">
        </div>
        <button type="submit" class="btn">Send login code</button>
      </form>
    </div>
  `));
});

// POST /auth/magic-link
app.post('/auth/magic-link', (req, res) => {
  const { email } = req.body;
  if (!email) return res.redirect('/login?error=Email required');

  // Create or get user
  let user = Object.values(db.users).find(u => u.email === email);
  if (!user) {
    const userId = randomUUID();
    user = { id: userId, email, createdAt: new Date().toISOString() };
    db.users[userId] = user;
  }

  // Create magic link
  const token = randomUUID();
  db.magicLinks[token] = { email, expiresAt: addSeconds(new Date(), 900) };
  saveDb();

  // In dev, print link. In prod, send email.
  const link = `${BASE_URL}/auth/verify?token=${token}`;
  console.log(`\n[AUTH] Magic link for ${email}:\n${link}\n`);

  res.redirect(`/login?success=Check console for login link`);
});

// GET /auth/verify
app.get('/auth/verify', (req, res) => {
  const { token } = req.query;
  const ml = db.magicLinks[token];

  if (!ml || new Date(ml.expiresAt) < new Date()) {
    return res.redirect('/login?error=Invalid or expired link');
  }

  delete db.magicLinks[token];

  const user = Object.values(db.users).find(u => u.email === ml.email);
  if (!user) return res.redirect('/login?error=User not found');

  // Create session
  const sessionId = randomUUID();
  db.sessions[sessionId] = { userId: user.id, expiresAt: addSeconds(new Date(), 30 * 24 * 60 * 60) };
  saveDb();

  res.cookie('session', sessionId, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.redirect('/installations');
});

// GET /logout
app.get('/logout', (req, res) => {
  const sessionId = req.cookies.session;
  if (sessionId) delete db.sessions[sessionId];
  saveDb();
  res.clearCookie('session');
  res.redirect('/login');
});

// GET /claim/:code
app.get('/claim/:code', (req, res) => {
  const { code } = req.params;
  const sessionId = req.cookies.session;

  // Find installation by claim code
  const installation = Object.values(db.installations).find(i => i.claimCode === code);
  
  if (!installation) {
    return res.send(html('Invalid Code', `
      <div class="card">
        <div class="error">Invalid claim code</div>
        <p>The code "${code}" was not found.</p>
        <a href="/claim" class="btn btn-secondary">Try Again</a>
      </div>
    `));
  }

  if (installation.claimedAt) {
    return res.send(html('Already Claimed', `
      <div class="card">
        <div class="error">Device already claimed</div>
        <a href="/installations" class="btn">View Installations</a>
      </div>
    `));
  }

  // Check auth
  let user = null;
  if (sessionId && db.sessions[sessionId]) {
    const session = db.sessions[sessionId];
    if (new Date(session.expiresAt) > new Date()) {
      user = db.users[session.userId];
    }
  }

  if (!user) return res.redirect(`/login?return=/claim/${code}`);

  res.send(html('Claim Device', `
    <div class="card">
      <h1>Claim Your <span>KaliunBox</span></h1>
      <p>Enter your information to complete setup</p>
      <div class="code">${code}</div>
      <form action="/claim/${code}" method="POST">
        <div class="form-group">
          <label>Your Name</label>
          <input type="text" name="customer_name" required value="${user.name || ''}">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="customer_email" required value="${user.email}">
        </div>
        <div class="form-group">
          <label>Address (optional)</label>
          <input type="text" name="customer_address">
        </div>
        <button type="submit" class="btn">Complete Setup</button>
      </form>
    </div>
  `, user));
});

// GET /claim
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
        <button type="submit" class="btn">Continue</button>
      </form>
    </div>
  `));
});

// POST /claim
app.post('/claim', (req, res) => {
  res.redirect(`/claim/${req.body.code.toUpperCase()}`);
});

// POST /claim/:code
app.post('/claim/:code', requireAuth, (req, res) => {
  const { code } = req.params;
  const { customer_name, customer_email, customer_address } = req.body;

  const installation = Object.values(db.installations).find(i => i.claimCode === code);
  if (!installation || installation.claimedAt) {
    return res.redirect('/claim?error=Invalid');
  }

  installation.claimedAt = new Date().toISOString();
  installation.claimedBy = req.user.id;
  installation.customerName = customer_name;
  installation.customerEmail = customer_email;
  installation.customerAddress = customer_address || '';
  saveDb();

  console.log(`[CLAIM] ${installation.id} by ${req.user.email}`);
  res.redirect('/installations?success=Device claimed!');
});

// GET /installations
app.get('/installations', requireAuth, (req, res) => {
  const { success } = req.query;
  const myInstallations = Object.values(db.installations).filter(i => i.claimedBy === req.user.id);

  const list = myInstallations.length ? myInstallations.map(i => {
    const lastSeen = i.lastHealthAt ? new Date(i.lastHealthAt) : null;
    const isOnline = lastSeen && (Date.now() - lastSeen.getTime()) < 30 * 60 * 1000;
    return `<div class="installation">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <strong>${i.customerName || i.hostname || 'KaliunBox'}</strong>
          <div style="color: #666; font-size: 14px;">${i.id.slice(0, 8)}...</div>
        </div>
        <span class="status ${isOnline ? 'online' : 'offline'}">${isOnline ? 'Online' : 'Offline'}</span>
      </div>
    </div>`;
  }).join('') : `<div style="text-align: center; padding: 60px 20px; color: #666;">
    <p style="font-size: 48px; margin-bottom: 16px;">📦</p>
    <h3>No installations yet</h3>
    <p>Your installations will appear here once set up.</p>
    <a href="/claim" class="btn" style="display: inline-block; width: auto; padding: 12px 24px; margin-top: 16px;">Claim a Device</a>
  </div>`;

  res.send(html('My Installations', `
    <h1 style="margin-bottom: 8px;">My <span style="color: #f59e0b;">Installations</span></h1>
    <p>View your Kaliun installations</p>
    ${success ? `<div class="success">${success}</div>` : ''}
    <div class="card" style="padding: 0;">${list}</div>
  `, req.user));
});

// GET /link
app.get('/link', (req, res) => {
  const { code } = req.query;
  const sessionId = req.cookies.session;

  let user = null;
  if (sessionId && db.sessions[sessionId]) {
    const session = db.sessions[sessionId];
    if (new Date(session.expiresAt) > new Date()) {
      user = db.users[session.userId];
    }
  }

  if (!user) return res.redirect(`/login?return=/link${code ? '?code=' + code : ''}`);

  if (code) {
    const dc = Object.values(db.deviceCodes).find(d => d.userCode === code);
    if (!dc || new Date(dc.expiresAt) < new Date()) {
      return res.send(html('Invalid Code', `
        <div class="card">
          <div class="error">Invalid or expired code</div>
          <a href="/link" class="btn btn-secondary">Try Again</a>
        </div>
      `, user));
    }

    if (dc.authorized) {
      return res.send(html('Already Authorized', `
        <div class="card">
          <div class="success">✓ Already authorized</div>
          <p>You can close this window.</p>
        </div>
      `, user));
    }

    return res.send(html('Link Home Assistant', `
      <div class="card">
        <h1>Link <span>Home Assistant</span></h1>
        <p>Allow Home Assistant to access your Kaliun account?</p>
        <div class="code">${code}</div>
        <form action="/link" method="POST">
          <input type="hidden" name="code" value="${code}">
          <button type="submit" class="btn">Authorize</button>
        </form>
        <a href="/" class="btn btn-secondary" style="margin-top: 12px;">Cancel</a>
      </div>
    `, user));
  }

  res.send(html('Link Home Assistant', `
    <div class="card">
      <h1>Link <span>Home Assistant</span></h1>
      <p>Enter the code shown in Home Assistant</p>
      <form action="/link" method="GET">
        <div class="form-group">
          <label>Device Code</label>
          <input type="text" name="code" required placeholder="XXXX-XXXX" style="text-transform: uppercase; text-align: center; font-size: 24px;">
        </div>
        <button type="submit" class="btn">Continue</button>
      </form>
    </div>
  `, user));
});

// POST /link
app.post('/link', requireAuth, (req, res) => {
  const { code } = req.body;
  const dc = Object.values(db.deviceCodes).find(d => d.userCode === code);

  if (!dc || new Date(dc.expiresAt) < new Date()) {
    return res.redirect('/link?error=Invalid code');
  }

  dc.authorized = true;
  dc.userId = req.user.id;
  saveDb();

  console.log(`[OAUTH] ${code} authorized by ${req.user.email}`);

  res.send(html('Success', `
    <div class="card">
      <div class="success">✓ Successfully linked!</div>
      <h1>Home Assistant <span>Connected</span></h1>
      <p>You can close this window.</p>
    </div>
  `, req.user));
});

// GET /settings
app.get('/settings', requireAuth, (req, res) => {
  res.send(html('Account Settings', `
    <h1 style="margin-bottom: 8px;"><span style="color: #f59e0b;">Account</span> Settings</h1>
    <p>Manage your account</p>
    <div class="card">
      <form action="/settings/profile" method="POST">
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
  `, req.user));
});

// POST /settings/profile
app.post('/settings/profile', requireAuth, (req, res) => {
  req.user.name = req.body.name;
  saveDb();
  res.redirect('/settings');
});

// GET /project
app.get('/project', requireAuth, (req, res) => {
  res.send(html('My Project', `
    <h1 style="text-align: center;">Your <span style="color: #f59e0b;">Smart Home</span> Project</h1>
    <p style="text-align: center;">Tell us about your project</p>
    <div class="card">
      <h3>What type of project is this?</h3>
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px;">
        <button class="btn btn-secondary" style="padding: 20px;">🏠<br>New Setup</button>
        <button class="btn btn-secondary" style="padding: 20px;">🏗️<br>New Build</button>
        <button class="btn btn-secondary" style="padding: 20px;">🔧<br>Repair</button>
      </div>
      <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 12px;">
        <button class="btn btn-secondary" style="padding: 20px;">➕<br>Upgrade</button>
        <button class="btn btn-secondary" style="padding: 20px;">•••<br>Other</button>
      </div>
      <button class="btn" style="margin-top: 24px;">Save and Continue →</button>
    </div>
  `, req.user));
});

// Root
app.get('/', (req, res) => {
  const sessionId = req.cookies.session;
  if (sessionId && db.sessions[sessionId]) {
    const session = db.sessions[sessionId];
    if (new Date(session.expiresAt) > new Date()) {
      return res.redirect('/installations');
    }
  }
  res.redirect('/login');
});

// Start
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  ⚡ Kaliun Connect API                                        ║
║  Server: ${BASE_URL.padEnd(51)}║
║                                                               ║
║  Device: POST /api/v1/installations/register                  ║
║  OAuth:  POST /oauth/device/code                              ║
║  Web:    GET  /login, /claim, /installations                  ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});
