import express from 'express';
import Database from 'better-sqlite3';
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

const app = express();
const PORT = process.env.DASHBOARD_PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const COPILOT_API_URL = process.env.COPILOT_API_URL || 'http://copilot-api:4141';
const DB_PATH = process.env.DB_PATH || '/data/dashboard.db';

// Ensure data directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite database
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

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
  );

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
  );

  CREATE TABLE IF NOT EXISTS github_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    user_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Create default admin user if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const adminId = uuidv4();
  const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const hash = bcrypt.hashSync(defaultPassword, 10);
  db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(adminId, 'admin', hash, 'admin');
  console.log(`Default admin user created. Username: admin, Password: ${defaultPassword}`);
}

// Middleware
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
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
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
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ success: true });
});

// ==================== API KEY ROUTES ====================

app.get('/api/keys', authMiddleware, (req, res) => {
  const keys = db.prepare(`
    SELECT id, name, key_prefix, permissions, rate_limit, is_active, 
           last_used_at, expires_at, total_requests, created_at 
    FROM api_keys WHERE user_id = ? ORDER BY created_at DESC
  `).all(req.user.id);
  res.json({ keys });
});

app.post('/api/keys', authMiddleware, (req, res) => {
  const { name, custom_key, permissions, rate_limit, expires_in_days } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const id = uuidv4();
  // Allow user to specify their own API key, or generate one
  const rawKey = custom_key && custom_key.trim() ? custom_key.trim() : `cpk_${crypto.randomBytes(32).toString('hex')}`;
  
  // Check if custom key already exists
  if (custom_key && custom_key.trim()) {
    const allKeys = db.prepare('SELECT key_hash FROM api_keys').all();
    for (const existing of allKeys) {
      if (bcrypt.compareSync(rawKey, existing.key_hash)) {
        return res.status(400).json({ error: 'API key already exists' });
      }
    }
  }
  
  const keyHash = bcrypt.hashSync(rawKey, 10);
  const keyPrefix = rawKey.substring(0, Math.min(12, rawKey.length)) + (rawKey.length > 12 ? '...' : '');
  const expiresAt = expires_in_days ? new Date(Date.now() + expires_in_days * 86400000).toISOString() : null;

  db.prepare(`
    INSERT INTO api_keys (id, name, key_hash, key_prefix, user_id, permissions, rate_limit, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, keyHash, keyPrefix, req.user.id, JSON.stringify(permissions || ['chat', 'models', 'embeddings', 'messages']), rate_limit || 0, expiresAt);

  res.json({ success: true, key: rawKey, id, name, key_prefix: keyPrefix });
});

app.put('/api/keys/:id', authMiddleware, (req, res) => {
  const { name, permissions, rate_limit, is_active } = req.body;
  const key = db.prepare('SELECT * FROM api_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ error: 'API key not found' });

  db.prepare(`
    UPDATE api_keys SET name = COALESCE(?, name), permissions = COALESCE(?, permissions),
    rate_limit = COALESCE(?, rate_limit), is_active = COALESCE(?, is_active) WHERE id = ?
  `).run(name || null, permissions ? JSON.stringify(permissions) : null, rate_limit ?? null, is_active ?? null, req.params.id);

  res.json({ success: true });
});

app.delete('/api/keys/:id', authMiddleware, (req, res) => {
  const result = db.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'API key not found' });
  res.json({ success: true });
});

// ==================== GITHUB TOKEN ROUTES ====================

// GitHub OAuth constants (same as copilot-api uses)
const GITHUB_BASE_URL = 'https://github.com';
const GITHUB_CLIENT_ID = 'Iv1.b507a08c87ecfe98';
const GITHUB_APP_SCOPES = 'read:user';

// Store active auth sessions
const authSessions = new Map();

// Step 1: Start device code auth flow
app.post('/api/github-auth/start', authMiddleware, async (req, res) => {
  try {
    const response = await fetch(`${GITHUB_BASE_URL}/login/device/code`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        scope: GITHUB_APP_SCOPES,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      return res.status(500).json({ error: 'Failed to start auth flow', details: text });
    }

    const data = await response.json();
    const sessionId = uuidv4();

    // Store session for polling
    authSessions.set(sessionId, {
      device_code: data.device_code,
      interval: data.interval,
      expires_in: data.expires_in,
      user_id: req.user.id,
      created_at: Date.now(),
      status: 'pending',
    });

    // Auto-cleanup expired sessions after expires_in
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

// Step 2: Poll for token (called by frontend periodically)
app.post('/api/github-auth/poll', authMiddleware, async (req, res) => {
  const { session_id } = req.body;
  const session = authSessions.get(session_id);

  if (!session) {
    return res.status(404).json({ error: 'Auth session not found or expired' });
  }

  if (session.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

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
      // Success! Save the token
      const { name } = req.body;
      const tokenName = name || `GitHub Auth ${new Date().toLocaleString('vi-VN')}`;
      const tokenId = uuidv4();

      db.prepare('INSERT INTO github_tokens (id, name, token, user_id) VALUES (?, ?, ?, ?)')
        .run(tokenId, tokenName, data.access_token, req.user.id);

      // Cleanup session
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
      res.json({ status: 'expired', message: 'Phiên xác thực đã hết hạn. Vui lòng thử lại.' });
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
  const tokens = db.prepare(`
    SELECT id, name, SUBSTR(token, 1, 10) || '...' as token_preview, is_active, created_at 
    FROM github_tokens WHERE user_id = ? ORDER BY created_at DESC
  `).all(req.user.id);
  res.json({ tokens });
});

app.post('/api/github-tokens', authMiddleware, (req, res) => {
  const { name, token } = req.body;
  if (!name || !token) return res.status(400).json({ error: 'Name and token are required' });

  const id = uuidv4();
  db.prepare('INSERT INTO github_tokens (id, name, token, user_id) VALUES (?, ?, ?, ?)').run(id, name, token, req.user.id);
  res.json({ success: true, id });
});

app.put('/api/github-tokens/:id/activate', authMiddleware, (req, res) => {
  // Deactivate all other tokens first
  db.prepare('UPDATE github_tokens SET is_active = 0 WHERE user_id = ?').run(req.user.id);
  db.prepare('UPDATE github_tokens SET is_active = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  
  // Get the token to update copilot-api
  const ghToken = db.prepare('SELECT token FROM github_tokens WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (ghToken) {
    // Notify copilot-api about the token change
    fetch(`${COPILOT_API_URL}/internal/update-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
      body: JSON.stringify({ github_token: ghToken.token }),
    }).catch(err => console.error('Failed to update copilot-api token:', err));
  }
  res.json({ success: true });
});

app.put('/api/github-tokens/:id/deactivate', authMiddleware, (req, res) => {
  db.prepare('UPDATE github_tokens SET is_active = 0 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

app.delete('/api/github-tokens/:id', authMiddleware, (req, res) => {
  const result = db.prepare('DELETE FROM github_tokens WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Token not found' });
  res.json({ success: true });
});

// ==================== STATS ROUTES ====================

app.get('/api/stats', authMiddleware, (req, res) => {
  const totalKeys = db.prepare('SELECT COUNT(*) as count FROM api_keys WHERE user_id = ?').get(req.user.id);
  const activeKeys = db.prepare('SELECT COUNT(*) as count FROM api_keys WHERE user_id = ? AND is_active = 1').get(req.user.id);
  const totalRequests = db.prepare('SELECT SUM(total_requests) as total FROM api_keys WHERE user_id = ?').get(req.user.id);
  const todayRequests = db.prepare(`
    SELECT COUNT(*) as count FROM request_logs 
    WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?) 
    AND date(created_at) = date('now')
  `).get(req.user.id);
  const recentLogs = db.prepare(`
    SELECT rl.*, ak.name as key_name FROM request_logs rl
    LEFT JOIN api_keys ak ON rl.api_key_id = ak.id
    WHERE ak.user_id = ?
    ORDER BY rl.created_at DESC LIMIT 50
  `).all(req.user.id);

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
  const data = db.prepare(`
    SELECT date(created_at) as date, COUNT(*) as requests
    FROM request_logs
    WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)
    AND created_at >= datetime('now', '-${days} days')
    GROUP BY date(created_at)
    ORDER BY date ASC
  `).all(req.user.id);
  res.json({ data });
});

// ==================== API KEY VALIDATION ENDPOINT (for copilot-api) ====================

app.post('/api/validate-key', (req, res) => {
  const internalSecret = req.headers['x-internal-secret'];
  if (internalSecret !== (process.env.INTERNAL_SECRET || 'internal-secret')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { api_key, endpoint } = req.body;
  if (!api_key) return res.status(400).json({ valid: false, error: 'API key required' });

  const keys = db.prepare('SELECT * FROM api_keys WHERE is_active = 1').all();
  let matchedKey = null;

  for (const key of keys) {
    if (bcrypt.compareSync(api_key, key.key_hash)) {
      matchedKey = key;
      break;
    }
  }

  if (!matchedKey) {
    return res.json({ valid: false, error: 'Invalid API key' });
  }

  // Check expiration
  if (matchedKey.expires_at && new Date(matchedKey.expires_at) < new Date()) {
    return res.json({ valid: false, error: 'API key expired' });
  }

  // Check permissions
  const permissions = JSON.parse(matchedKey.permissions);
  const endpointCategory = getEndpointCategory(endpoint);
  if (endpointCategory && !permissions.includes(endpointCategory)) {
    return res.json({ valid: false, error: 'Insufficient permissions' });
  }

  // Update usage stats
  db.prepare('UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, total_requests = total_requests + 1 WHERE id = ?').run(matchedKey.id);

  // Log request
  db.prepare(`
    INSERT INTO request_logs (api_key_id, endpoint, method, status_code, ip_address)
    VALUES (?, ?, ?, ?, ?)
  `).run(matchedKey.id, endpoint, req.body.method || 'POST', 200, req.body.ip || '');

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

// ==================== PROXY STATUS ====================

app.get('/api/proxy-status', authMiddleware, async (req, res) => {
  try {
    // First check if server is alive via /health
    const healthRes = await fetch(`${COPILOT_API_URL}/health`, { signal: AbortSignal.timeout(5000) });
    if (!healthRes.ok) {
      return res.json({ status: 'offline', models: null, error: 'Health check failed' });
    }

    // Server is alive, try to get models
    try {
      const modelsRes = await fetch(`${COPILOT_API_URL}/v1/models`, {
        headers: { 'Authorization': 'Bearer dummy' },
        signal: AbortSignal.timeout(10000),
      });
      if (modelsRes.ok) {
        const data = await modelsRes.json();
        return res.json({ status: 'online', models: data });
      }
      // Server online but models failed (no token or token expired)
      return res.json({ status: 'no-token', models: null, error: 'Server đang chạy nhưng chưa có GitHub Token hợp lệ. Hãy thêm token ở mục GitHub Tokens.' });
    } catch {
      return res.json({ status: 'no-token', models: null, error: 'Không thể lấy danh sách models. Kiểm tra GitHub Token.' });
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Dashboard running at http://0.0.0.0:${PORT}`);

  // On startup, push active GitHub token to copilot-api (if any)
  // Delay to allow copilot-api to start up
  setTimeout(async () => {
    try {
      const activeToken = db.prepare('SELECT token FROM github_tokens WHERE is_active = 1 LIMIT 1').get();
      if (activeToken) {
        console.log('Found active GitHub token, pushing to copilot-api...');
        const resp = await fetch(`${COPILOT_API_URL}/internal/update-token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': process.env.INTERNAL_SECRET || 'internal-secret' },
          body: JSON.stringify({ github_token: activeToken.token }),
        });
        const data = await resp.json();
        if (data.success) {
          console.log(`Token pushed successfully. Models cached: ${data.models_count}`);
        } else {
          console.warn('Failed to push token:', data.error || data.details);
        }
      } else {
        console.log('No active GitHub token found. Use the dashboard to add one.');
      }
    } catch (err) {
      console.warn('Could not push token to copilot-api (may not be ready yet):', err.message);
    }
  }, 10000); // Wait 10 seconds for copilot-api to be ready
});
