/* =============================================================
   SnortIDS Dashboard – main.js
   ============================================================= */
'use strict';

// ── State ──────────────────────────────────────────────────────
let currentMode = 'ip';      // 'ip' | 'website'
let activeFilter = 'all';
let allAlerts = [];
let allLogFiles = [];

// ── Init ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Restore saved theme before first render
    applyTheme(localStorage.getItem('ids-theme') || 'dark');

    updateClock();
    setInterval(updateClock, 1000);
    fetchAll();
    setInterval(fetchAll, 10000);

    // Enter key on both inputs
    ['dashTargetInput', 'scanTargetInput'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('keydown', e => {
            if (e.key === 'Enter') startScan(id === 'dashTargetInput' ? 'dash' : 'scan');
        });
    });
});

// ── Theme ───────────────────────────────────────────────────────
function applyTheme(theme) {
    document.body.classList.toggle('light', theme === 'light');
    const dark = document.querySelector('.theme-icon-dark');
    const light = document.querySelector('.theme-icon-light');
    if (dark) dark.style.display = theme === 'light' ? 'none' : 'flex';
    if (light) light.style.display = theme === 'light' ? 'flex' : 'none';
}

function toggleTheme() {
    const current = localStorage.getItem('ids-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('ids-theme', next);
    applyTheme(next);
}

function fetchAll() {
    fetchAlerts();
    fetchLogs();
    fetchStats();
    fetchLogFiles();
}

// ── Clock ───────────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('sidebarTime');
    if (el) el.textContent = new Date().toLocaleTimeString('en-GB');
}

// ── Section Routing ─────────────────────────────────────────────
const SECTION_TITLES = {
    dashboard: { title: 'Dashboard', sub: 'Security overview and real-time threat monitoring' },
    scanner: { title: 'Target Scanner', sub: 'Scan IP addresses and websites using Snort rules' },
    alerts: { title: 'Alert Feed', sub: 'All IDS alerts triggered by rule matching' },
    history: { title: 'Scan History', sub: 'Historical log of all scans performed' },
    logfiles: { title: 'Log Files', sub: 'Download structured scan reports saved to disk' },
};

function showSection(name, linkEl) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));

    const target = document.getElementById(`section-${name}`);
    if (target) target.classList.add('active');
    if (linkEl) linkEl.classList.add('active');

    const meta = SECTION_TITLES[name] || {};
    const titleEl = document.getElementById('pageTitle');
    const subEl = document.getElementById('pageSubtitle');
    if (titleEl) titleEl.textContent = meta.title || name;
    if (subEl) subEl.textContent = meta.sub || '';

    return false;
}

// ── Scan Mode Toggle ────────────────────────────────────────────
function setMode(mode, panel) {
    currentMode = mode;

    // Sync both panels
    _applyMode('dashBtnIP', 'dashBtnWeb', 'dashInputLabel', 'dashTargetInput', null);
    _applyMode('scanBtnIP', 'scanBtnWeb', 'scanInputLabel', 'scanTargetInput', 'chkHttpRow');
}

function _applyMode(btnIPId, btnWebId, labelId, inputId, chkRowId) {
    const btnIP = document.getElementById(btnIPId);
    const btnWeb = document.getElementById(btnWebId);
    const label = document.getElementById(labelId);
    const input = document.getElementById(inputId);
    const chkRow = document.getElementById(chkRowId);
    const hint = document.getElementById('scanHint');
    const chkHttp = document.getElementById('chkHttp');

    if (currentMode === 'ip') {
        btnIP && btnIP.classList.add('active');
        btnWeb && btnWeb.classList.remove('active');
        if (label) label.textContent = 'Target IP Address';
        if (input) input.placeholder = '192.168.1.1';
        if (chkRow) { chkRow.style.opacity = '0.45'; chkRow.style.pointerEvents = 'none'; }
        if (chkHttp) { chkHttp.disabled = true; chkHttp.checked = false; }
        if (hint) hint.textContent = 'Enter an IPv4 address to perform a port scan and match against Snort rules.';
    } else {
        btnIP && btnIP.classList.remove('active');
        btnWeb && btnWeb.classList.add('active');
        if (label) label.textContent = 'Target Website / Domain';
        if (input) input.placeholder = 'example.com';
        if (chkRow) { chkRow.style.opacity = '1'; chkRow.style.pointerEvents = 'auto'; }
        if (chkHttp) { chkHttp.disabled = false; chkHttp.checked = true; }
        if (hint) hint.textContent = 'Enter a domain name. The scanner will resolve it to an IP, run a port scan, and analyse HTTP security headers.';
    }
}

// ── Presets ─────────────────────────────────────────────────────
function presetDash(target, mode) {
    currentMode = mode;
    setMode(mode);
    const el = document.getElementById('dashTargetInput');
    if (el) el.value = target;
}
function presetScan(target, mode) {
    currentMode = mode;
    setMode(mode);
    const el = document.getElementById('scanTargetInput');
    if (el) el.value = target;
}

// ── Start Scan ──────────────────────────────────────────────────
async function startScan(panel) {
    const inputId = panel === 'dash' ? 'dashTargetInput' : 'scanTargetInput';
    const resultId = panel === 'dash' ? 'dashScanResult' : 'scanScanResult';
    const btnId = panel === 'dash' ? 'dashScanBtn' : 'mainScanBtn';

    const target = (document.getElementById(inputId)?.value || '').trim();
    if (!target) {
        showResult(resultId, 'Please enter a target.', 'error');
        return;
    }

    setScanning(true, target, btnId);
    clearResult(resultId);

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: currentMode })
        });
        const data = await resp.json();
        setScanning(false, '', btnId);

        if (data.error) {
            showResult(resultId, `Error: ${esc(data.error)}`, 'error');
            return;
        }

        let msg = `Scan complete — <strong>${esc(data.target)}</strong>`;
        if (data.resolved_ip) msg += ` &rarr; ${esc(data.resolved_ip)}`;
        msg += `&ensp;|&ensp;Open ports: <strong>${data.open_ports?.length ?? 0}</strong>`;
        if (data.http_alerts) msg += `&ensp;|&ensp;HTTP issues: <strong>${data.http_alerts.length}</strong>`;
        msg += `&ensp;|&ensp;Alerts: <strong>${data.alert_count}</strong>`;
        if (data.log_file) msg += `<br><span style="opacity:.7">Saved &rarr;</span> <span style="font-family:'JetBrains Mono',monospace">logs/${esc(data.log_file)}</span>`;
        showResult(resultId, msg, 'success');

        fetchAll();
    } catch (err) {
        setScanning(false, '', btnId);
        showResult(resultId, `Network error: ${esc(err.message)}`, 'error');
    }
}

function setScanning(active, target, btnId) {
    const btn = document.getElementById(btnId);
    const overlay = document.getElementById('scanOverlay');
    const sub = document.getElementById('scanningTarget');

    if (active) {
        if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
        if (overlay) overlay.classList.add('active');
        if (sub) sub.textContent = target;
    } else {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Run Scan`;
        }
        if (overlay) overlay.classList.remove('active');
    }
}

function showResult(id, html, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'block';
    el.className = `scan-result-box ${type}`;
    el.innerHTML = html;
}
function clearResult(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'none';
    el.innerHTML = '';
}

// ── Fetch Alerts ────────────────────────────────────────────────
async function fetchAlerts() {
    try {
        const r = await fetch('/api/alerts');
        allAlerts = await r.json();
        renderFilterPills();
        renderAlerts();
        renderMiniAlerts();
        // Update sidebar badge
        const badge = document.getElementById('sidebarAlertBadge');
        if (badge) badge.textContent = allAlerts.length;
    } catch { }
}

function renderFilterPills() {
    const container = document.getElementById('alertFilterPills');
    if (!container) return;

    // Get unique targets
    const targets = [...new Set(allAlerts.map(a => a.target))];

    // If activeFilter target was deleted, reset to all
    if (activeFilter !== 'all' && !targets.includes(activeFilter)) {
        activeFilter = 'all';
    }

    let html = `<button class="pill ${activeFilter === 'all' ? 'active' : ''}" data-filter="all" onclick="filterAlerts('all')">All Targets</button>`;

    targets.forEach(target => {
        const isActive = activeFilter === target ? 'active' : '';
        html += `<button class="pill ${isActive}" data-filter="${target}" onclick="filterAlerts('${target}')">${esc(target)}</button>`;
    });

    container.innerHTML = html;
}

function filterAlerts(filter) {
    activeFilter = filter;
    renderFilterPills();
    renderAlerts();
}

function renderAlerts() {
    const list = document.getElementById('alertsList');
    if (!list) return;

    // Get unique targets to group by
    const targets = [...new Set(allAlerts.map(a => a.target))];

    // ── Filtered (single target) ──────────────────────────────
    if (activeFilter !== 'all') {
        const items = allAlerts.filter(a => a.target === activeFilter);
        if (items.length === 0) {
            list.innerHTML = `
              <div class="empty-state">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <p>No alerts recorded for this target.</p>
              </div>`;
            return;
        }
        list.innerHTML = _targetGroupHTML(activeFilter, items);
        return;
    }

    // ── All (grouped by target) ───────────────────────────────
    if (allAlerts.length === 0) {
        list.innerHTML = `
          <div class="empty-state">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <p>No alerts recorded. Run a scan to begin detection.</p>
          </div>`;
        return;
    }

    list.innerHTML = targets.map(target => {
        const items = allAlerts.filter(a => a.target === target);
        return _targetGroupHTML(target, items);
    }).join('');
}

function _targetGroupHTML(target, items) {
    const color = 'var(--primary)';

    const rows = items.length === 0
        ? `<div class="sev-group-empty">No alerts for ${esc(target)}</div>`
        : items.map(a => `
            <div class="alert-row ${esc(a.severity)}" onclick="showAlertModal(${a.id})">
              <div class="alert-sev"><div class="sev-dot"></div></div>
              <div class="alert-main">
                <div class="alert-head-row">
                  <span class="alert-sev-badge">${esc(a.severity)}</span>
                  <span class="alert-target">${esc(a.target)}</span>
                  <span class="alert-ts">${esc(a.timestamp)}</span>
                </div>
                <div class="alert-msg">${esc(a.message)}</div>
                <div class="alert-rule">${esc(a.rule)}</div>
              </div>
            </div>`).join('');

    return `
      <div class="sev-group">
        <div class="sev-group-header" style="border-left-color:${color}">
          <span class="sev-group-label" style="color:${color}">${esc(target)}</span>
          <span class="sev-group-count" style="background:${color}20;color:${color};border-color:${color}40">
            ${items.length}
          </span>
        </div>
        <div class="sev-group-body">${rows}</div>
      </div>`;
}


function renderMiniAlerts() {
    const el = document.getElementById('dashMiniAlerts');
    if (!el) return;
    const top5 = allAlerts.slice(0, 5);
    if (top5.length === 0) {
        el.innerHTML = `<div class="empty-mini">No alerts recorded yet.</div>`;
        return;
    }
    el.innerHTML = top5.map(a => `
    <div class="mini-alert-row ${esc(a.severity)}">
      <span class="mini-sev">${esc(a.severity)}</span>
      <span class="mini-msg">${esc(a.message)}</span>
      <span class="mini-target">${esc(a.target)}</span>
    </div>
  `).join('');
}

// ── Alert Modal ─────────────────────────────────────────────────
function showAlertModal(id) {
    const a = allAlerts.find(x => x.id === id);
    if (!a) return;
    document.getElementById('modalTitle').textContent = `Alert #${a.id}`;
    document.getElementById('modalBody').innerHTML = `
    <div class="modal-field"><label>Timestamp</label><span>${esc(a.timestamp)}</span></div>
    <div class="modal-field"><label>Target</label><span>${esc(a.target)}</span></div>
    <div class="modal-field"><label>Severity</label><span class="alert-sev-badge ${esc(a.severity)}">${esc(a.severity)}</span></div>
    <div class="modal-field"><label>Message</label><span>${esc(a.message)}</span></div>
    <div class="modal-field"><label>Snort Rule</label><div class="modal-rule">${esc(a.rule)}</div></div>
  `;
    document.getElementById('modalOverlay').classList.add('open');
}
function closeModal() {
    document.getElementById('modalOverlay').classList.remove('open');
}

// ── Clear Alerts ────────────────────────────────────────────────
async function clearAlerts() {
    if (!confirm('Clear all IDS alerts?')) return;
    await fetch('/api/alerts', { method: 'DELETE' });
    allAlerts = [];
    renderAlerts();
    renderMiniAlerts();
    document.getElementById('sidebarAlertBadge').textContent = '0';
    fetchStats();
}

// ── Fetch Logs ──────────────────────────────────────────────────
async function fetchLogs() {
    try {
        const r = await fetch('/api/logs');
        renderLogs(await r.json());
    } catch { }
}

function renderLogs(logs) {
    const tb = document.getElementById('logsBody');
    if (!tb) return;
    if (!logs || logs.length === 0) {
        tb.innerHTML = `<tr><td colspan="5" class="table-empty">No scan history yet.</td></tr>`;
        return;
    }
    tb.innerHTML = logs.map(l => `
    <tr>
      <td>${esc(l.timestamp)}</td>
      <td class="td-target">${esc(l.target)}</td>
      <td><span class="td-type">${esc(l.scan_type)}</span></td>
      <td><span class="td-count ${l.alert_count > 0 ? 'has' : 'none'}">${l.alert_count}</span></td>
      <td class="td-summary">${esc(l.result_summary)}</td>
    </tr>
  `).join('');
}

// ── Fetch Log Files ─────────────────────────────────────────────
async function fetchLogFiles() {
    try {
        const r = await fetch('/api/logfiles');
        allLogFiles = await r.json();
        renderLogFiles(Array.isArray(allLogFiles) ? allLogFiles : []);
        // Update dashboard KPI
        const el = document.getElementById('dashLogFiles');
        if (el) el.textContent = Array.isArray(allLogFiles) ? allLogFiles.length : 0;
    } catch { }
}

function renderLogFiles(files) {
    const tb = document.getElementById('logFilesBody');
    if (!tb) return;
    if (!files || files.length === 0) {
        tb.innerHTML = `<tr><td colspan="4" class="table-empty">No log files yet. Run a scan to generate one.</td></tr>`;
        return;
    }
    tb.innerHTML = files.map((f, i) => {
        const kb = (f.size / 1024).toFixed(1);
        return `
      <tr>
        <td style="color:var(--text-3)">${i + 1}</td>
        <td class="td-filename">${esc(f.name)}</td>
        <td style="color:var(--text-3);font-size:0.75rem">${kb} KB</td>
        <td>
          <a class="download-link" href="/api/logfiles/${encodeURIComponent(f.name)}" download="${esc(f.name)}">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Download
          </a>
        </td>
      </tr>`;
    }).join('');
}

// ── Fetch Stats ─────────────────────────────────────────────────
async function fetchStats() {
    try {
        const r = await fetch('/api/stats');
        const s = await r.json();
        ['statTotalScans', 'dashTotalScans'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = s.total_scans ?? 0;
        });
        ['statTotalAlerts', 'dashTotalAlerts'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = s.total_alerts ?? 0;
        });
        ['statCriticalAlerts', 'dashCritical'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = s.critical_alerts ?? 0;
        });
    } catch { }
}

// ── Helpers ─────────────────────────────────────────────────────
function esc(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
