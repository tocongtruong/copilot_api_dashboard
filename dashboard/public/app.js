// ==================== API Helper ====================
async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ==================== Toast ====================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const icons = { success: 'check-circle', error: 'exclamation-circle', info: 'info-circle' };
  toast.innerHTML = `<i class="fas fa-${icons[type]}"></i><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s forwards';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ==================== Modal ====================
function showModal(id) { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
function showCreateKeyModal() { showModal('modal-create-key'); }
function showAddTokenModal() { showModal('modal-add-token'); }

// ==================== Auth ====================
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('login-error');
  errorEl.classList.add('hidden');
  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('login-username').value,
        password: document.getElementById('login-password').value,
      }),
    });
    document.getElementById('user-name').textContent = data.user.username;
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    loadDashboard();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
});

// Check if already logged in
(async () => {
  try {
    const data = await api('/api/auth/me');
    document.getElementById('user-name').textContent = data.user.username;
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    loadDashboard();
  } catch { /* not logged in */ }
})();

document.getElementById('btn-logout').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  location.reload();
});

// ==================== Navigation ====================
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');

    document.querySelectorAll('.page').forEach(p => { p.classList.add('hidden'); p.classList.remove('active'); });
    const target = document.getElementById(`page-${page}`);
    target.classList.remove('hidden');
    target.classList.add('active');

    const titles = { overview: 'Tổng quan', 'api-keys': 'API Keys', 'github-tokens': 'GitHub Tokens', logs: 'Request Logs', settings: 'Cài đặt' };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Load page data
    if (page === 'overview') loadStats();
    if (page === 'api-keys') loadApiKeys();
    if (page === 'github-tokens') loadGithubTokens();
    if (page === 'logs') loadLogs();

    // Close sidebar on mobile
    document.querySelector('.sidebar').classList.remove('open');
  });
});

document.getElementById('sidebar-toggle').addEventListener('click', () => {
  document.querySelector('.sidebar').classList.toggle('open');
});

// ==================== Dashboard Load ====================
function loadDashboard() {
  loadStats();
  checkProxyStatus();
}

// ==================== Stats ====================
async function loadStats() {
  try {
    const data = await api('/api/stats');
    document.getElementById('stat-total-keys').textContent = data.total_keys;
    document.getElementById('stat-active-keys').textContent = data.active_keys;
    document.getElementById('stat-total-requests').textContent = data.total_requests.toLocaleString();
    document.getElementById('stat-today-requests').textContent = data.today_requests;

    // Recent logs
    const tbody = document.querySelector('#recent-logs-table tbody');
    tbody.innerHTML = data.recent_logs.slice(0, 10).map(log => `
      <tr>
        <td>${formatDate(log.created_at)}</td>
        <td><span class="badge badge-blue">${log.key_name || 'N/A'}</span></td>
        <td><code>${log.endpoint}</code></td>
        <td><span class="badge badge-orange">${log.method}</span></td>
        <td><span class="badge ${log.status_code < 400 ? 'badge-green' : 'badge-red'}">${log.status_code}</span></td>
      </tr>
    `).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Chưa có request nào</td></tr>';
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// ==================== Proxy Status ====================
async function checkProxyStatus() {
  const statusEl = document.getElementById('proxy-status');
  const detailsEl = document.getElementById('proxy-details');
  try {
    const data = await api('/api/proxy-status');
    if (data.status === 'online' && data.models?.data?.length > 0) {
      statusEl.innerHTML = '<span class="status-dot online"></span><span>Copilot API Online</span>';
      const models = data.models.data;
      const totalCount = models.length;

      // Group models by provider (owned_by / vendor)
      const grouped = {};
      models.forEach(m => {
        const provider = m.owned_by || m.vendor || 'unknown';
        if (!grouped[provider]) grouped[provider] = [];
        grouped[provider].push(m);
      });

      // Provider display config
      const providerMeta = {
        'azure': { icon: 'fab fa-microsoft', color: '#0078d4', label: 'Azure OpenAI' },
        'openai': { icon: 'fas fa-brain', color: '#10a37f', label: 'OpenAI' },
        'anthropic': { icon: 'fas fa-robot', color: '#d97706', label: 'Anthropic' },
        'google': { icon: 'fab fa-google', color: '#4285f4', label: 'Google' },
        'microsoft': { icon: 'fab fa-microsoft', color: '#0078d4', label: 'Microsoft' },
        'xai': { icon: 'fas fa-bolt', color: '#ef4444', label: 'xAI' },
        'mistral': { icon: 'fas fa-wind', color: '#ff7000', label: 'Mistral' },
        'meta': { icon: 'fab fa-meta', color: '#0668E1', label: 'Meta' },
        'cohere': { icon: 'fas fa-layer-group', color: '#39594d', label: 'Cohere' },
        'unknown': { icon: 'fas fa-cube', color: '#6b7280', label: 'Other' },
      };

      const providersHtml = Object.entries(grouped).map(([provider, providerModels]) => {
        const meta = providerMeta[provider.toLowerCase()] || providerMeta['unknown'];
        const modelItems = providerModels.map(m => {
          const displayName = m.display_name || m.id;
          return `<div class="model-item">
            <span class="model-id">${m.id}</span>
            ${m.display_name && m.display_name !== m.id ? `<span class="model-name">${m.display_name}</span>` : ''}
          </div>`;
        }).join('');

        return `<div class="provider-group">
          <div class="provider-header" onclick="this.parentElement.classList.toggle('collapsed')">
            <div class="provider-info">
              <i class="${meta.icon}" style="color:${meta.color};font-size:18px"></i>
              <span class="provider-name">${meta.label || provider}</span>
              <span class="badge badge-blue">${providerModels.length}</span>
            </div>
            <i class="fas fa-chevron-down provider-toggle"></i>
          </div>
          <div class="provider-models">${modelItems}</div>
        </div>`;
      }).join('');

      detailsEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
          <span class="badge badge-green">Online</span>
          <span style="color:var(--text-secondary)">${totalCount} models từ ${Object.keys(grouped).length} nhà cung cấp</span>
        </div>
        <div class="providers-list">${providersHtml}</div>
      `;
    } else if (data.status === 'online' || data.status === 'no-token') {
      statusEl.innerHTML = '<span class="status-dot" style="background:var(--accent-orange)"></span><span>Copilot API Online (No Token)</span>';
      detailsEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span class="badge badge-orange">Chờ Token</span>
          <span style="color:var(--text-secondary)">${data.error || 'Server đang chạy nhưng chưa có token hợp lệ.'}</span>
        </div>
        <div style="margin-top:12px">
          <a href="#" onclick="event.preventDefault();navigate('github-tokens')" style="color:var(--accent-blue);text-decoration:underline">→ Thêm GitHub Token</a>
        </div>
      `;
    } else {
      throw new Error(data.error || 'offline');
    }
  } catch (err) {
    statusEl.innerHTML = '<span class="status-dot offline"></span><span>Copilot API Offline</span>';
    detailsEl.innerHTML = `<p style="color:var(--accent-red)"><i class="fas fa-exclamation-triangle"></i> Copilot API server hiện không hoạt động</p>
      <p style="color:var(--text-secondary);font-size:13px;margin-top:4px">${err.message || ''}</p>`;
  }
}

// ==================== API Keys ====================
async function loadApiKeys() {
  try {
    const data = await api('/api/keys');
    const tbody = document.querySelector('#api-keys-table tbody');
    tbody.innerHTML = data.keys.map(key => `
      <tr>
        <td><strong>${escapeHtml(key.name)}</strong></td>
        <td><code style="color:var(--text-secondary)">${key.key_prefix}</code></td>
        <td>${JSON.parse(key.permissions).map(p => `<span class="badge badge-blue" style="margin:1px">${p}</span>`).join(' ')}</td>
        <td>${key.rate_limit ? key.rate_limit + '/min' : 'Không giới hạn'}</td>
        <td>${key.total_requests}</td>
        <td>${key.is_active ? '<span class="badge badge-green">Hoạt động</span>' : '<span class="badge badge-red">Đã tắt</span>'}</td>
        <td>${key.expires_at ? formatDate(key.expires_at) : 'Vĩnh viễn'}</td>
        <td>
          <button class="btn-icon" onclick="toggleKey('${key.id}', ${key.is_active ? 0 : 1})" title="${key.is_active ? 'Tắt' : 'Bật'}">
            <i class="fas fa-${key.is_active ? 'pause' : 'play'}"></i>
          </button>
          <button class="btn-icon danger" onclick="deleteKey('${key.id}')" title="Xóa">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-secondary)">Chưa có API Key nào</td></tr>';
  } catch (err) {
    showToast('Lỗi tải API Keys: ' + err.message, 'error');
  }
}

document.getElementById('create-key-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const permissions = Array.from(document.querySelectorAll('#create-key-form .checkbox input:checked')).map(cb => cb.value);
  const customKey = document.getElementById('key-custom').value.trim();
  try {
    const data = await api('/api/keys', {
      method: 'POST',
      body: JSON.stringify({
        name: document.getElementById('key-name').value,
        custom_key: customKey || undefined,
        permissions,
        rate_limit: parseInt(document.getElementById('key-rate-limit').value) || 0,
        expires_in_days: parseInt(document.getElementById('key-expires').value) || undefined,
      }),
    });
    closeModal('modal-create-key');
    document.getElementById('new-key-value').textContent = data.key;
    showModal('modal-show-key');
    document.getElementById('key-name').value = '';
    document.getElementById('key-custom').value = '';
    loadApiKeys();
    loadStats();
    showToast('API Key đã được tạo thành công!', 'success');
  } catch (err) {
    showToast('Lỗi tạo API Key: ' + err.message, 'error');
  }
});

async function toggleKey(id, isActive) {
  try {
    await api(`/api/keys/${id}`, { method: 'PUT', body: JSON.stringify({ is_active: isActive }) });
    loadApiKeys();
    showToast(isActive ? 'Đã bật API Key' : 'Đã tắt API Key', 'success');
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
  }
}

async function deleteKey(id) {
  if (!confirm('Bạn có chắc muốn xóa API Key này?')) return;
  try {
    await api(`/api/keys/${id}`, { method: 'DELETE' });
    loadApiKeys();
    loadStats();
    showToast('Đã xóa API Key', 'success');
  } catch (err) {
    showToast('Lỗi xóa: ' + err.message, 'error');
  }
}

function copyKey() {
  const key = document.getElementById('new-key-value').textContent;
  navigator.clipboard.writeText(key).then(() => showToast('Đã copy API Key!', 'success'));
}

// ==================== GitHub Tokens ====================
let authPollInterval = null;
let authTimerInterval = null;
let currentAuthSessionId = null;

async function loadGithubTokens() {
  try {
    const data = await api('/api/github-tokens');
    const tbody = document.querySelector('#github-tokens-table tbody');
    tbody.innerHTML = data.tokens.map(token => `
      <tr>
        <td><strong>${escapeHtml(token.name)}</strong></td>
        <td><code style="color:var(--text-secondary)">${token.token_preview}</code></td>
        <td>
          <label class="toggle-switch">
            <input type="checkbox" ${token.is_active ? 'checked' : ''} onchange="toggleGithubToken('${token.id}', this.checked)">
            <span class="toggle-slider"></span>
          </label>
          <span style="margin-left:8px;font-size:12px;color:${token.is_active ? 'var(--accent-green)' : 'var(--text-muted)'}">
            ${token.is_active ? 'Đang dùng' : 'Tắt'}
          </span>
        </td>
        <td>${formatDate(token.created_at)}</td>
        <td>
          <button class="btn-icon danger" onclick="deleteGithubToken('${token.id}')" title="Xóa">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Chưa có GitHub Token nào</td></tr>';
  } catch (err) {
    showToast('Lỗi tải GitHub Tokens: ' + err.message, 'error');
  }
}

document.getElementById('add-token-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/github-tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: document.getElementById('token-name').value,
        token: document.getElementById('token-value').value,
      }),
    });
    closeModal('modal-add-token');
    document.getElementById('token-name').value = '';
    document.getElementById('token-value').value = '';
    loadGithubTokens();
    showToast('Đã thêm GitHub Token!', 'success');
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
  }
});

async function toggleGithubToken(id, isActive) {
  try {
    if (isActive) {
      await api(`/api/github-tokens/${id}/activate`, { method: 'PUT' });
      showToast('Đã kích hoạt token!', 'success');
    } else {
      await api(`/api/github-tokens/${id}/deactivate`, { method: 'PUT' });
      showToast('Đã tắt token', 'success');
    }
    loadGithubTokens();
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
    loadGithubTokens(); // reload to reset toggle state
  }
}

async function activateToken(id) {
  try {
    await api(`/api/github-tokens/${id}/activate`, { method: 'PUT' });
    loadGithubTokens();
    showToast('Đã kích hoạt token!', 'success');
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
  }
}

async function deleteGithubToken(id) {
  if (!confirm('Bạn có chắc muốn xóa token này?')) return;
  try {
    await api(`/api/github-tokens/${id}`, { method: 'DELETE' });
    loadGithubTokens();
    showToast('Đã xóa token!', 'success');
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
  }
}

// ==================== GitHub OAuth Auth Flow ====================
function startGitHubAuth() {
  resetAuthUI();
  document.getElementById('auth-token-name').value = '';
  showModal('modal-github-auth');
}

function resetAuthUI() {
  document.getElementById('auth-step-name').classList.remove('hidden');
  document.getElementById('auth-step-code').classList.add('hidden');
  document.getElementById('auth-step-success').classList.add('hidden');
  document.getElementById('auth-step-error').classList.add('hidden');
}

async function initiateGitHubAuth() {
  const name = document.getElementById('auth-token-name').value.trim() || 'GitHub Token ' + new Date().toLocaleString('vi-VN');

  try {
    const data = await api('/api/github-auth/start', { method: 'POST' });

    currentAuthSessionId = data.session_id;

    // Show code step
    document.getElementById('auth-step-name').classList.add('hidden');
    document.getElementById('auth-step-code').classList.remove('hidden');

    // Set code and URL
    document.getElementById('auth-user-code').textContent = data.user_code;
    document.getElementById('auth-url-text').textContent = data.verification_uri;
    document.getElementById('auth-verification-url').href = data.verification_uri;

    // Start countdown timer
    let timeLeft = data.expires_in;
    updateTimer(timeLeft);
    authTimerInterval = setInterval(() => {
      timeLeft--;
      updateTimer(timeLeft);
      if (timeLeft <= 0) {
        clearInterval(authTimerInterval);
        showAuthError('Phiên xác thực đã hết hạn.');
      }
    }, 1000);

    // Start polling for token
    const pollInterval = (data.interval + 1) * 1000; // interval + 1 second safety margin
    authPollInterval = setInterval(() => pollGitHubAuth(name), pollInterval);

  } catch (err) {
    showToast('Lỗi bắt đầu xác thực: ' + err.message, 'error');
  }
}

async function pollGitHubAuth(tokenName) {
  if (!currentAuthSessionId) return;

  try {
    const data = await api('/api/github-auth/poll', {
      method: 'POST',
      body: JSON.stringify({ session_id: currentAuthSessionId, name: tokenName }),
    });

    document.getElementById('auth-status-text').textContent = data.message || 'Đang chờ...';

    if (data.status === 'success') {
      clearAuthIntervals();
      // Show success
      document.getElementById('auth-step-code').classList.add('hidden');
      document.getElementById('auth-step-success').classList.remove('hidden');
      document.getElementById('auth-success-msg').textContent = `Token "${tokenName}" đã được tạo thành công!`;
      document.getElementById('step2-circle').classList.add('completed');
    } else if (data.status === 'expired' || data.status === 'denied') {
      clearAuthIntervals();
      showAuthError(data.message);
    }
  } catch (err) {
    console.error('Poll error:', err);
  }
}

function showAuthError(message) {
  clearAuthIntervals();
  document.getElementById('auth-step-name').classList.add('hidden');
  document.getElementById('auth-step-code').classList.add('hidden');
  document.getElementById('auth-step-success').classList.add('hidden');
  document.getElementById('auth-step-error').classList.remove('hidden');
  document.getElementById('auth-error-msg').textContent = message;
}

function cancelGitHubAuth() {
  clearAuthIntervals();
  currentAuthSessionId = null;
  closeModal('modal-github-auth');
}

function closeGitHubAuthSuccess() {
  closeModal('modal-github-auth');
  currentAuthSessionId = null;
  loadGithubTokens();
}

function resetGitHubAuth() {
  clearAuthIntervals();
  currentAuthSessionId = null;
  resetAuthUI();
}

function clearAuthIntervals() {
  if (authPollInterval) { clearInterval(authPollInterval); authPollInterval = null; }
  if (authTimerInterval) { clearInterval(authTimerInterval); authTimerInterval = null; }
}

function updateTimer(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  document.getElementById('auth-timer-countdown').textContent =
    `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function copyAuthCode() {
  const code = document.getElementById('auth-user-code').textContent;
  navigator.clipboard.writeText(code).then(() => showToast('Đã copy mã code!', 'success'));
}

// ==================== Logs ====================
async function loadLogs() {
  try {
    const days = document.getElementById('log-days')?.value || 7;
    const [statsData, chartData] = await Promise.all([
      api('/api/stats'),
      api(`/api/stats/chart?days=${days}`),
    ]);

    // Simple bar chart using HTML/CSS
    const container = document.getElementById('logs-container');
    const logs = statsData.recent_logs;

    container.innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th>Thời gian</th>
            <th>API Key</th>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Status</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          ${logs.map(log => `
            <tr>
              <td>${formatDate(log.created_at)}</td>
              <td><span class="badge badge-blue">${log.key_name || 'N/A'}</span></td>
              <td><code>${log.endpoint}</code></td>
              <td><span class="badge badge-orange">${log.method}</span></td>
              <td><span class="badge ${log.status_code < 400 ? 'badge-green' : 'badge-red'}">${log.status_code}</span></td>
              <td>${log.ip_address || '-'}</td>
            </tr>
          `).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">Chưa có log</td></tr>'}
        </tbody>
      </table>
    `;

    // Simple chart
    renderChart(chartData.data);
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

function renderChart(data) {
  const canvas = document.getElementById('requests-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width - 24;
  canvas.height = 200;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (!data || data.length === 0) {
    ctx.fillStyle = '#94a3b8';
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Chưa có dữ liệu', canvas.width / 2, canvas.height / 2);
    return;
  }

  const maxVal = Math.max(...data.map(d => d.requests), 1);
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };
  const chartW = canvas.width - padding.left - padding.right;
  const chartH = canvas.height - padding.top - padding.bottom;
  const barW = Math.min(40, (chartW / data.length) - 8);

  // Grid lines
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(canvas.width - padding.right, y);
    ctx.stroke();

    ctx.fillStyle = '#64748b';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), padding.left - 8, y + 4);
  }

  // Bars
  data.forEach((d, i) => {
    const x = padding.left + (chartW / data.length) * i + (chartW / data.length - barW) / 2;
    const barH = (d.requests / maxVal) * chartH;
    const y = padding.top + chartH - barH;

    const gradient = ctx.createLinearGradient(x, y, x, y + barH);
    gradient.addColorStop(0, '#3b82f6');
    gradient.addColorStop(1, '#1d4ed8');
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.roundRect(x, y, barW, barH, [4, 4, 0, 0]);
    ctx.fill();

    // Label
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(d.date.substring(5), x + barW / 2, canvas.height - padding.bottom + 16);

    // Value
    ctx.fillStyle = '#f1f5f9';
    ctx.font = '11px sans-serif';
    ctx.fillText(d.requests, x + barW / 2, y - 6);
  });
}

// ==================== Settings ====================
document.getElementById('change-password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const newPass = document.getElementById('new-password').value;
  const confirmPass = document.getElementById('confirm-password').value;
  if (newPass !== confirmPass) {
    showToast('Mật khẩu xác nhận không khớp!', 'error');
    return;
  }
  try {
    await api('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword: document.getElementById('current-password').value,
        newPassword: newPass,
      }),
    });
    showToast('Đã đổi mật khẩu thành công!', 'success');
    e.target.reset();
  } catch (err) {
    showToast('Lỗi: ' + err.message, 'error');
  }
});

// ==================== Utilities ====================
function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  return d.toLocaleString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
