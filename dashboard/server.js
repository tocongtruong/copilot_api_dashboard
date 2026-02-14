import dotenv from 'dotenv';
import express from 'express';
import initSqlJs from 'sql.js';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from project root (parent directory)
dotenv.config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const PORT = process.env.DASHBOARD_PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const COPILOT_API_URL = process.env.COPILOT_API_URL || 'http://localhost:4141';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'dashboard.db');

// Ensure data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// ==================== sql.js setup ====================
let db;

async function initDb() {
  const SQL = await initSqlJs();

  // Load existing db file or create new
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Enable WAL mode & foreign keys
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      user_id TEXT NOT NULL,
      permissions TEXT DEFAULT '["chat","models","embeddings","messages"]',
      rate_limit INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      last_used_at DATETIME,
      expires_at DATETIME,
      total_requests INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      api_key_id TEXT,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      status_code INTEGER,
      response_time_ms INTEGER,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS github_tokens (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      token TEXT NOT NULL,
      is_active INTEGER DEFAULT 1,
      user_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create default admin user if not exists
  const adminResult = db.exec("SELECT id FROM users WHERE username = 'admin'");
  if (adminResult.length === 0 || adminResult[0].values.length === 0) {
    const adminId = uuidv4();
    const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hash = bcrypt.hashSync(defaultPassword, 10);
    db.run('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)', [adminId, 'admin', hash, 'admin']);
    console.log(`Default admin user created. Username: admin, Password: ${defaultPassword}`);
  }

  saveDb();
}

// Save DB to file periodically
function saveDb() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (err) {
    console.error('Failed to save DB:', err);
  }
}

// Auto-save every 30 seconds
setInterval(saveDb, 30000);

// ==================== sql.js helper functions ====================
// Mimic better-sqlite3 API
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let result = null;
  if (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    result = {};
    cols.forEach((col, i) => { result[col] = vals[i]; });
  }
  stmt.free();
  return result;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  const cols = stmt.getColumnNames();
  while (stmt.step()) {
    const vals = stmt.get();
    const row = {};
    cols.forEach((col, i) => { row[col] = vals[i]; });
    results.push(row);
  }
  stmt.free();
  return results;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  const changes = db.getRowsModified();
  saveDb();
  return { changes };
}

// Vietnam timezone helper (UTC+7)
function vnNow() {
  const d = new Date();
  d.setHours(d.getHours() + 7);
  return d.toISOString().replace('T', ' ').substring(0, 19);
}

// ==================== Middleware ==
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('auth_token', token, { httpOnly: true, maxAge: 86400000, sameSite: 'lax' });
  res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  dbRun('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
  res.json({ success: true });
});

// ==================== API KEY ROUTES ====================

app.get('/api/keys', authMiddleware, (req, res) => {
  const keys = dbAll(`
    SELECT id, name, key_prefix, permissions, rate_limit, is_active, 
           last_used_at, expires_at, total_requests, created_at 
    FROM api_keys WHERE user_id = ? ORDER BY created_at DESC
  `, [req.user.id]);
  res.json({ keys });
});

app.post('/api/keys', authMiddleware, (req, res) => {
  const { name, custom_key, permissions, rate_limit, expires_in_days } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const id = uuidv4();
  const rawKey = custom_key && custom_key.trim() ? custom_key.trim() : `cpk_${crypto.randomBytes(32).toString('hex')}`;

  // Check if custom key already exists
  if (custom_key && custom_key.trim()) {
    const allKeys = dbAll('SELECT key_hash FROM api_keys');
    for (const existing of allKeys) {
      if (bcrypt.compareSync(rawKey, existing.key_hash)) {
        return res.status(400).json({ error: 'API key already exists' });
      }
    }
  }

  const keyHash = bcrypt.hashSync(rawKey, 10);
  const keyPrefix = rawKey.substring(0, Math.min(12, rawKey.length)) + (rawKey.length > 12 ? '...' : '');
  const expiresAt = expires_in_days ? new Date(Date.now() + expires_in_days * 86400000).toISOString() : null;

  dbRun(`
    INSERT INTO api_keys (id, name, key_hash, key_prefix, user_id, permissions, rate_limit, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `, [id, name, keyHash, keyPrefix, req.user.id, JSON.stringify(permissions || ['chat', 'models', 'embeddings', 'messages']), rate_limit || 0, expiresAt]);

  res.json({ success: true, key: rawKey, id, name, key_prefix: keyPrefix });
});

app.put('/api/keys/:id', authMiddleware, (req, res) => {
  const { name, permissions, rate_limit, is_active } = req.body;
  const key = dbGet('SELECT * FROM api_keys WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!key) return res.status(404).json({ error: 'API key not found' });

  // Build dynamic update
  const updates = [];
  const values = [];
  if (name !== undefined) { updates.push('name = ?'); values.push(name); }
  if (permissions !== undefined) { updates.push('permissions = ?'); values.push(JSON.stringify(permissions)); }
  if (rate_limit !== undefined) { updates.push('rate_limit = ?'); values.push(rate_limit); }
  if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active); }

  if (updates.length > 0) {
    values.push(req.params.id);
    dbRun(`UPDATE api_keys SET ${updates.join(', ')} WHERE id = ?`, values);
  }

  res.json({ success: true });
});

app.delete('/api/keys/:id', authMiddleware, (req, res) => {
  const result = dbRun('DELETE FROM api_keys WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'API key not found' });
  res.json({ success: true });
});

// ==================== GITHUB TOKEN ROUTES ====================

const GITHUB_BASE_URL = 'https://github.com';
const GITHUB_CLIENT_ID = 'Iv1.b507a08c87ecfe98';
const GITHUB_APP_SCOPES = 'read:user';

const authSessions = new Map();

app.post('/api/github-auth/start', authMiddleware, async (req, res) => {
  try {
    const response = await fetch(`${GITHUB_BASE_URL}/login/device/code`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, scope: GITHUB_APP_SCOPES }),
    });

    if (!response.ok) {
      const text = await response.text();
      return res.status(500).json({ error: 'Failed to start auth flow', details: text });
    }

    const data = await response.json();
    const sessionId = uuidv4();

    authSessions.set(sessionId, {
      device_code: data.device_code,
      interval: data.interval,
      expires_in: data.expires_in,
      user_id: req.user.id,
      created_at: Date.now(),
      status: 'pending',
    });

    setTimeout(() => authSessions.delete(sessionId), data.expires_in * 1000);

    res.json({
      session_id: sessionId,
      user_code: data.user_code,
      verification_uri: data.verification_uri,
      expires_in: data.expires_in,
      interval: data.interval,
    });
  } catch (error) {
    console.error('Auth start error:', error);
    res.status(500).json({ error: 'Failed to start authentication' });
  }
});

app.post('/api/github-auth/poll', authMiddleware, async (req, res) => {
  const { session_id } = req.body;
  const session = authSessions.get(session_id);

  if (!session) return res.status(404).json({ error: 'Auth session not found or expired' });
  if (session.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

  try {
    const response = await fetch(`${GITHUB_BASE_URL}/login/oauth/access_token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        device_code: session.device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }),
    });

    if (!response.ok) {
      return res.json({ status: 'pending', message: 'Waiting for authorization...' });
    }

    const data = await response.json();

    if (data.access_token) {
      const { name } = req.body;
      const tokenName = name || `GitHub Auth ${new Date().toLocaleString('vi-VN')}`;
      const tokenId = uuidv4();

      dbRun('INSERT INTO github_tokens (id, name, token, user_id) VALUES (?, ?, ?, ?)',
        [tokenId, tokenName, data.access_token, req.user.id]);

      // Deactivate others and activate this one, then push
      dbRun('UPDATE github_tokens SET is_active = 0 WHERE user_id = ? AND id != ?', [req.user.id, tokenId]);
      dbRun('UPDATE github_tokens SET is_active = 1 WHERE id = ?', [tokenId]);
      pushTokenToCopilotApi(data.access_token);

      authSessions.delete(session_id);
      res.json({
        status: 'success',
        token_id: tokenId,
        token_preview: data.access_token.substring(0, 10) + '...',
        message: 'Token created successfully!',
      });
    } else if (data.error === 'authorization_pending') {
      res.json({ status: 'pending', message: 'Đang chờ bạn xác nhận trên GitHub...' });
    } else if (data.error === 'slow_down') {
      res.json({ status: 'pending', message: 'Đang chờ... (slow down)' });
    } else if (data.error === 'expired_token') {
      authSessions.delete(session_id);
      res.json({ status: 'expired', message: 'Phiên xác thực đã hết hạn.' });
    } else if (data.error === 'access_denied') {
      authSessions.delete(session_id);
      res.json({ status: 'denied', message: 'Bạn đã từ chối xác thực.' });
    } else {
      res.json({ status: 'pending', message: 'Đang chờ xác nhận...' });
    }
  } catch (error) {
    console.error('Poll error:', error);
    res.json({ status: 'pending', message: 'Lỗi kết nối, đang thử lại...' });
  }
});

app.get('/api/github-tokens', authMiddleware, (req, res) => {
  const tokens = dbAll(`
    SELECT id, name, SUBSTR(token, 1, 10) || '...' as token_preview, is_active, created_at 
    FROM github_tokens WHERE user_id = ? ORDER BY created_at DESC
  `, [req.user.id]);
  res.json({ tokens });
});

app.post('/api/github-tokens', authMiddleware, (req, res) => {
  const { name, token } = req.body;
  if (!name || !token) return res.status(400).json({ error: 'Name and token are required' });

  const id = uuidv4();
  // Deactivate all other tokens, then insert new one as active
  dbRun('UPDATE github_tokens SET is_active = 0 WHERE user_id = ?', [req.user.id]);
  dbRun('INSERT INTO github_tokens (id, name, token, user_id, is_active) VALUES (?, ?, ?, ?, 1)', [id, name, token, req.user.id]);

  // Push to copilot-api
  pushTokenToCopilotApi(token);

  res.json({ success: true, id });
});

app.put('/api/github-tokens/:id/activate', authMiddleware, (req, res) => {
  dbRun('UPDATE github_tokens SET is_active = 0 WHERE user_id = ?', [req.user.id]);
  dbRun('UPDATE github_tokens SET is_active = 1 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);

  const ghToken = dbGet('SELECT token FROM github_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (ghToken) {
    fetch(`${COPILOT_API_URL}/internal/update-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
      body: JSON.stringify({ github_token: ghToken.token }),
    }).catch(err => console.error('Failed to update copilot-api token:', err));
  }
  res.json({ success: true });
});

app.put('/api/github-tokens/:id/deactivate', authMiddleware, (req, res) => {
  dbRun('UPDATE github_tokens SET is_active = 0 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);

  // Check if any token is still active; if not, clear copilot-api token
  const anyActive = dbGet('SELECT id FROM github_tokens WHERE user_id = ? AND is_active = 1', [req.user.id]);
  if (!anyActive) {
    fetch(`${COPILOT_API_URL}/internal/update-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
      body: JSON.stringify({ action: 'clear' }),
    }).catch(err => console.error('Failed to clear copilot-api token:', err));
  }
  res.json({ success: true });
});

app.delete('/api/github-tokens/:id', authMiddleware, (req, res) => {
  // Check if the token being deleted is the active one
  const tokenToDelete = dbGet('SELECT is_active FROM github_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  const result = dbRun('DELETE FROM github_tokens WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Token not found' });

  // If deleted token was active, clear copilot-api token
  if (tokenToDelete && tokenToDelete.is_active) {
    const nextActive = dbGet('SELECT id, token FROM github_tokens WHERE user_id = ? AND is_active = 1', [req.user.id]);
    if (nextActive) {
      // Push next active token
      fetch(`${COPILOT_API_URL}/internal/update-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
        body: JSON.stringify({ github_token: nextActive.token }),
      }).catch(err => console.error('Failed to update copilot-api token:', err));
    } else {
      // No more active tokens, clear
      fetch(`${COPILOT_API_URL}/internal/update-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
        body: JSON.stringify({ action: 'clear' }),
      }).catch(err => console.error('Failed to clear copilot-api token:', err));
    }
  }
  res.json({ success: true });
});

// ==================== STATS ROUTES ====================

// Helper: push token to copilot-api
function pushTokenToCopilotApi(token, retries = 3) {
  const attempt = (n) => {
    console.log(`Pushing token to copilot-api... (attempt ${4 - n}/3)`);
    fetch(`${COPILOT_API_URL}/internal/update-token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret',
      },
      body: JSON.stringify({ github_token: token }),
      signal: AbortSignal.timeout(15000),
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          console.log(`Token pushed successfully. Models cached: ${data.models_count}`);
        } else {
          console.warn('Push token response:', data.error || data.details);
          if (n > 1) setTimeout(() => attempt(n - 1), 5000);
        }
      })
      .catch(err => {
        console.warn(`Push token failed: ${err.message}`);
        if (n > 1) setTimeout(() => attempt(n - 1), 5000);
      });
  };
  attempt(retries);
}

app.get('/api/stats', authMiddleware, (req, res) => {
  const totalKeys = dbGet('SELECT COUNT(*) as count FROM api_keys WHERE user_id = ?', [req.user.id]);
  const activeKeys = dbGet('SELECT COUNT(*) as count FROM api_keys WHERE user_id = ? AND is_active = 1', [req.user.id]);
  const totalRequests = dbGet('SELECT COALESCE(SUM(total_requests), 0) as total FROM api_keys WHERE user_id = ?', [req.user.id]);
  const todayVN = vnNow().substring(0, 10);
  const todayRequests = dbGet(`
    SELECT COUNT(*) as count FROM request_logs 
    WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?) 
    AND date(created_at) = ?
  `, [req.user.id, todayVN]);
  const recentLogs = dbAll(`
    SELECT rl.*, ak.name as key_name FROM request_logs rl
    LEFT JOIN api_keys ak ON rl.api_key_id = ak.id
    WHERE ak.user_id = ?
    ORDER BY rl.created_at DESC LIMIT 50
  `, [req.user.id]);

  res.json({
    total_keys: totalKeys.count,
    active_keys: activeKeys.count,
    total_requests: totalRequests.total || 0,
    today_requests: todayRequests.count,
    recent_logs: recentLogs,
  });
});

app.get('/api/stats/chart', authMiddleware, (req, res) => {
  const days = parseInt(req.query.days) || 7;
  const data = dbAll(`
    SELECT date(created_at) as date, COUNT(*) as requests
    FROM request_logs
    WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)
    AND created_at >= datetime('now', '-' || ? || ' days')
    GROUP BY date(created_at)
    ORDER BY date ASC
  `, [req.user.id, days]);
  res.json({ data });
});

// ==================== API KEY VALIDATION (for copilot-api) ====================

app.post('/api/validate-key', (req, res) => {
  const internalSecret = req.headers['x-internal-secret'];
  if (internalSecret !== (process.env.INTERNAL_SECRET || 'internal-secret')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { api_key, endpoint } = req.body;
  if (!api_key) return res.status(400).json({ valid: false, error: 'API key required' });

  const keys = dbAll('SELECT * FROM api_keys WHERE is_active = 1');
  let matchedKey = null;

  for (const key of keys) {
    if (bcrypt.compareSync(api_key, key.key_hash)) {
      matchedKey = key;
      break;
    }
  }

  if (!matchedKey) return res.json({ valid: false, error: 'Invalid API key' });

  if (matchedKey.expires_at && new Date(matchedKey.expires_at) < new Date()) {
    return res.json({ valid: false, error: 'API key expired' });
  }

  const permissions = JSON.parse(matchedKey.permissions);
  const endpointCategory = getEndpointCategory(endpoint);
  if (endpointCategory && !permissions.includes(endpointCategory)) {
    return res.json({ valid: false, error: 'Insufficient permissions' });
  }

  dbRun('UPDATE api_keys SET last_used_at = ?, total_requests = total_requests + 1 WHERE id = ?', [vnNow(), matchedKey.id]);
  dbRun(`INSERT INTO request_logs (api_key_id, endpoint, method, status_code, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [matchedKey.id, endpoint, req.body.method || 'POST', 200, req.body.ip || '', vnNow()]);

  res.json({ valid: true, key_id: matchedKey.id, rate_limit: matchedKey.rate_limit });
});

function getEndpointCategory(endpoint) {
  if (!endpoint) return null;
  if (endpoint.includes('chat/completions')) return 'chat';
  if (endpoint.includes('models')) return 'models';
  if (endpoint.includes('embeddings')) return 'embeddings';
  if (endpoint.includes('messages')) return 'messages';
  return null;
}

// ==================== REQUEST LOGGING (separate from validate-key) ====================

app.post('/api/log-request', (req, res) => {
  const internalSecret = req.headers['x-internal-secret'];
  if (internalSecret !== (process.env.INTERNAL_SECRET || 'internal-secret')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { api_key, endpoint, method, status_code, ip, response_time_ms } = req.body;
  if (!endpoint) return res.status(400).json({ error: 'endpoint required' });

  let keyId = null;
  let keyName = null;

  if (api_key && api_key !== 'dummy') {
    const keys = dbAll('SELECT id, name, key_hash FROM api_keys WHERE is_active = 1');
    for (const key of keys) {
      if (bcrypt.compareSync(api_key, key.key_hash)) {
        keyId = key.id;
        keyName = key.name;
        break;
      }
    }
  }

  dbRun(`INSERT INTO request_logs (api_key_id, endpoint, method, status_code, response_time_ms, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [keyId, endpoint, method || 'GET', status_code || 200, response_time_ms || 0, ip || '', vnNow()]);

  if (keyId) {
    dbRun('UPDATE api_keys SET last_used_at = ?, total_requests = total_requests + 1 WHERE id = ?', [vnNow(), keyId]);
  }

  res.json({ logged: true });
});

// ==================== CONFIG (for frontend) ====================

app.get('/api/config', authMiddleware, (req, res) => {
  // Return the public-facing API URL for the guide section
  // In Docker: COPILOT_API_URL is internal (http://copilot-api:4141), so we use PUBLIC_API_URL
  // If PUBLIC_API_URL is not set, derive from request host
  const publicApiUrl = process.env.PUBLIC_API_URL
    || `${req.protocol}://${req.hostname}:${process.env.COPILOT_API_PORT || 4141}`;
  res.json({ api_url: publicApiUrl });
});

// ==================== PROXY STATUS ==

app.get('/api/proxy-status', authMiddleware, async (req, res) => {
  try {
    const healthRes = await fetch(`${COPILOT_API_URL}/health`, { signal: AbortSignal.timeout(5000) });
    if (!healthRes.ok) {
      return res.json({ status: 'offline', models: null, error: 'Health check failed' });
    }

    try {
      const modelsRes = await fetch(`${COPILOT_API_URL}/v1/models`, {
        headers: { 'Authorization': 'Bearer dummy' },
        signal: AbortSignal.timeout(10000),
      });
      if (modelsRes.ok) {
        const data = await modelsRes.json();
        if (data.data && data.data.length > 0) {
          return res.json({ status: 'online', models: data });
        }
        return res.json({ status: 'no-token', models: null, error: data.error || 'Server đang chạy nhưng chưa có GitHub Token hợp lệ.' });
      }
      const errData = await modelsRes.json().catch(() => ({}));
      return res.json({ status: 'no-token', models: null, error: errData?.error || 'Server đang chạy nhưng chưa có GitHub Token hợp lệ.' });
    } catch {
      return res.json({ status: 'no-token', models: null, error: 'Không thể lấy danh sách models.' });
    }
  } catch (err) {
    res.json({ status: 'offline', models: null, error: 'Không thể kết nối tới Copilot API server' });
  }
});

app.get('/api/proxy-usage', authMiddleware, async (req, res) => {
  try {
    const response = await fetch(`${COPILOT_API_URL}/usage`);
    const data = await response.json();
    res.json(data);
  } catch {
    res.json({ error: 'Failed to fetch usage data' });
  }
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START SERVER ====================
async function start() {
  await initDb();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  ┌──────────────────────────────────────────┐`);
    console.log(`  │                                          │`);
    console.log(`  │   Dashboard: http://localhost:${PORT}        │`);
    console.log(`  │   Login:     admin / admin123             │`);
    console.log(`  │                                          │`);
    console.log(`  └──────────────────────────────────────────┘\n`);

    // On startup, push active GitHub token to copilot-api (with retries)
    const pushStartupToken = (retryNum = 1, maxRetries = 6) => {
      setTimeout(async () => {
        try {
          const activeToken = dbGet('SELECT token FROM github_tokens WHERE is_active = 1 LIMIT 1');
          if (activeToken) {
            console.log(`[Startup] Pushing active token to copilot-api (attempt ${retryNum}/${maxRetries})...`);
            const resp = await fetch(`${COPILOT_API_URL}/internal/update-token`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
              body: JSON.stringify({ github_token: activeToken.token }),
              signal: AbortSignal.timeout(15000),
            });
            const data = await resp.json();
            if (data.success) {
              console.log(`[Startup] Token pushed successfully. Models cached: ${data.models_count}`);
            } else {
              console.warn('[Startup] Push failed:', data.error || data.details);
              if (retryNum < maxRetries) pushStartupToken(retryNum + 1, maxRetries);
            }
          } else {
            console.log('[Startup] No active GitHub token. Use the dashboard to add one.');
          }
        } catch (err) {
          console.warn(`[Startup] Could not push token (attempt ${retryNum}/${maxRetries}):`, err.message);
          if (retryNum < maxRetries) pushStartupToken(retryNum + 1, maxRetries);
        }
      }, retryNum === 1 ? 5000 : 10000);
    };
    pushStartupToken();
  });
}

// Handle graceful shutdown - save DB
process.on('SIGINT', () => {
  console.log('\nSaving database...');
  saveDb();
  process.exit(0);
});

process.on('SIGTERM', () => {
  saveDb();
  process.exit(0);
});

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
