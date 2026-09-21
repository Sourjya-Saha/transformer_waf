"""Classical Terminal-Based SOC & Firewall Console UI for WAF Gateway."""

def render_terminal_html() -> str:
    """Renders the authentic macOS Terminal console HTML for localhost:8000."""
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WAF Gateway Console — macOS Terminal</title>
  <style>
    :root {
      --bg-canvas: #07090e;
      --terminal-bg: #0b0f17;
      --titlebar-bg: #141824;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-glow: rgba(0, 255, 102, 0.2);
      --text-green: #39d353;
      --text-green-bright: #00ff66;
      --text-red: #ff5577;
      --text-amber: #f0883e;
      --text-cyan: #58a6ff;
      --text-muted: #8b949e;
      --text-dim: #484f58;
      --text-white: #f0f6fc;
      --font-mono: 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Menlo', 'Monaco', 'Consolas', monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-canvas);
      color: var(--text-white);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: flex-start;
      padding: 28px 20px;
      overflow-x: hidden;
    }

    /* Ambient glow background */
    body::before {
      content: "";
      position: fixed;
      top: -20%; left: -20%; right: -20%; bottom: -20%;
      background: radial-gradient(circle at 50% 10%, rgba(0, 255, 102, 0.04) 0%, rgba(20, 35, 55, 0.25) 40%, rgba(7, 9, 14, 0.95) 80%);
      z-index: -1;
      pointer-events: none;
    }

    /* =========================================================================
       OUTSIDE HEADER & METRICS
       ========================================================================= */
    .waf-outside-header {
      width: 100%;
      max-width: 1240px;
      display: flex;
      flex-direction: column;
      align-items: center;
      margin-bottom: 20px;
      text-align: center;
    }

    .ascii-banner {
      color: var(--text-green-bright);
      font-size: 10px;
      line-height: 1.15;
      white-space: pre;
      overflow-x: auto;
      text-shadow: 0 0 12px rgba(0, 255, 102, 0.45);
      user-select: none;
      margin-bottom: 6px;
    }

    .waf-subtitle {
      font-family: var(--font-mono);
      font-size: 11px;
      letter-spacing: 2px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 16px;
    }

    .metrics-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: 16px;
      padding: 10px 20px;
      background: rgba(20, 24, 36, 0.6);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-subtle);
      border-radius: 30px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }

    .metric-item {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
    }

    .metric-label {
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }

    .metric-val {
      font-weight: 700;
      font-size: 13px;
    }
    .metric-val.cyan { color: var(--text-cyan); }
    .metric-val.green { color: var(--text-green-bright); }
    .metric-val.red { color: var(--text-red); }
    .metric-val.amber { color: var(--text-amber); }

    .metric-divider {
      width: 1px;
      height: 14px;
      background: rgba(255, 255, 255, 0.1);
    }

    .live-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--text-muted);
      font-size: 11px;
    }

    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--text-green-bright);
      box-shadow: 0 0 8px var(--text-green-bright);
      animation: pulse-dot 2s infinite ease-in-out;
    }

    @keyframes pulse-dot {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.3); opacity: 0.7; }
    }

    /* =========================================================================
       MACOS TERMINAL WINDOW (LOGS ONLY)
       ========================================================================= */
    .mac-window {
      max-width: 1240px;
      width: 100%;
      background-color: var(--terminal-bg);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px;
      box-shadow: 0 25px 70px rgba(0, 0, 0, 0.85), 0 0 1px rgba(255, 255, 255, 0.25);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      margin: 0 auto;
      flex-grow: 1;
      height: calc(100vh - 210px);
      min-height: 520px;
    }

    /* macOS Window Title Bar */
    .mac-titlebar {
      background-color: var(--titlebar-bg);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      height: 44px;
      padding: 0 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      user-select: none;
      position: relative;
    }

    /* macOS Traffic Light Buttons */
    .traffic-lights {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 70px;
    }

    .traffic-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      position: relative;
      cursor: pointer;
    }

    .dot-close { background-color: #ff5f56; border: 1px solid #e0443e; }
    .dot-minimize { background-color: #ffbd2e; border: 1px solid #dea125; }
    .dot-maximize { background-color: #27c93f; border: 1px solid #1aab29; }

    .mac-title {
      font-family: var(--font-sans);
      font-size: 12px;
      font-weight: 500;
      color: #94a3b8;
      letter-spacing: 0.2px;
      pointer-events: none;
      white-space: nowrap;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .mac-title-badge {
      font-family: var(--font-mono);
      font-size: 10px;
      background: rgba(255, 255, 255, 0.08);
      padding: 1px 6px;
      border-radius: 4px;
      color: #cbd5e1;
    }

    /* Professional Control Actions */
    .mac-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* Segmented Filter Control */
    .filter-segmented {
      display: flex;
      align-items: center;
      background: rgba(0, 0, 0, 0.35);
      padding: 3px;
      border-radius: 7px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      gap: 2px;
    }

    .filter-btn {
      background: transparent;
      border: none;
      color: #94a3b8;
      font-family: var(--font-sans);
      font-size: 11px;
      font-weight: 500;
      padding: 4px 10px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .filter-btn:hover {
      color: #f8fafc;
      background: rgba(255, 255, 255, 0.06);
    }

    .filter-btn.active {
      background: rgba(57, 211, 83, 0.16);
      color: var(--text-green-bright);
      font-weight: 600;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.3);
    }

    /* Action Buttons (Autoscroll & Clear) */
    .btn-action {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: #cbd5e1;
      font-family: var(--font-sans);
      font-size: 11px;
      font-weight: 500;
      padding: 4px 11px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .btn-action:hover {
      background: rgba(255, 255, 255, 0.09);
      color: #ffffff;
      border-color: rgba(255, 255, 255, 0.22);
    }

    .btn-action.active {
      background: rgba(57, 211, 83, 0.12);
      border-color: rgba(57, 211, 83, 0.35);
      color: var(--text-green-bright);
    }

    .btn-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--text-dim);
      transition: background-color 0.2s ease;
    }

    .btn-action.active .btn-dot {
      background: var(--text-green-bright);
      box-shadow: 0 0 6px var(--text-green-bright);
    }

    /* =========================================================================
       TERMINAL LOG FEED VIEWPORT (PURE LOGS ONLY)
       ========================================================================= */
    .terminal-body {
      padding: 16px 20px;
      background-color: var(--terminal-bg);
      flex-grow: 1;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }

    .terminal-body::-webkit-scrollbar {
      width: 7px;
    }
    .terminal-body::-webkit-scrollbar-track {
      background: var(--terminal-bg);
    }
    .terminal-body::-webkit-scrollbar-thumb {
      background: #1e293b;
      border-radius: 4px;
    }
    .terminal-body::-webkit-scrollbar-thumb:hover {
      background: #334155;
    }

    .terminal-feed {
      display: flex;
      flex-direction: column;
      gap: 10px;
      flex-grow: 1;
    }

    .log-entry {
      font-size: 12px;
      line-height: 1.6;
      border-radius: 6px;
      padding: 8px 12px;
      background-color: rgba(20, 24, 36, 0.5);
      border-left: 3px solid var(--text-muted);
      animation: fadeIn 0.15s ease-in;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-3px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .log-entry.allow {
      border-left-color: var(--text-green-bright);
      background-color: rgba(57, 211, 83, 0.03);
    }

    .log-entry.block {
      border-left-color: var(--text-red);
      background-color: rgba(255, 85, 119, 0.05);
    }

    .log-entry.ratelimit {
      border-left-color: var(--text-amber);
      background-color: rgba(240, 136, 62, 0.05);
    }

    .log-main {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 8px;
    }

    .log-ts { color: var(--text-dim); }
    .log-verdict {
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
      font-size: 11px;
    }
    .log-verdict.pass { color: var(--text-green-bright); background: rgba(57, 211, 83, 0.15); }
    .log-verdict.fail { color: var(--text-red); background: rgba(255, 85, 119, 0.15); }
    .log-verdict.limit { color: var(--text-amber); background: rgba(240, 136, 62, 0.15); }

    .log-ip { color: var(--text-cyan); }
    .log-cmd { color: var(--text-white); font-weight: 600; }
    .log-url { color: #cbd5e1; word-break: break-all; }

    .log-tree {
      margin-top: 4px;
      padding-left: 8px;
      color: #94a3b8;
      font-size: 11px;
      line-height: 1.5;
    }

    .tree-branch {
      color: #484f58;
      margin-right: 4px;
    }

    .log-highlight-red { color: var(--text-red); font-weight: 600; }
    .log-highlight-green { color: var(--text-green-bright); font-weight: 600; }

    .empty-logs {
      text-align: center;
      padding: 60px 20px;
      color: var(--text-dim);
      font-size: 13px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }

    .empty-sub {
      font-size: 11px;
      color: #334155;
    }
  </style>
</head>
<body>

  <!-- =======================================================================
       OUTSIDE LOGO, TITLE, & LIVE METRICS BAR
       ======================================================================= -->
  <header class="waf-outside-header">
    <div class="ascii-banner">
╦ ╦╔═╗╔═╗  ╔═╗╦╦═╗╔═╗╦ ╦╔═╗╦  ╦  
║║║╠═╣╠╣   ╠╣ ║╠╦╝║╣ ║║║╠═╣║  ║  
╚╩╝╩ ╩╚    ╚  ╩╩╚═╚═╝╚╩╝╩ ╩╩═╝╩═╝</div>
    <div class="waf-subtitle">Deterministic Reverse Proxy &amp; Audit Console</div>

    <div class="metrics-bar">
      <div class="metric-item">
        <span class="metric-label">TOTAL:</span>
        <span class="metric-val cyan" id="stat-total">0</span>
      </div>
      <div class="metric-divider"></div>
      <div class="metric-item">
        <span class="metric-label">PASSED:</span>
        <span class="metric-val green" id="stat-passed">0</span>
      </div>
      <div class="metric-divider"></div>
      <div class="metric-item">
        <span class="metric-label">BLOCKED:</span>
        <span class="metric-val red" id="stat-blocked">0</span>
      </div>
      <div class="metric-divider"></div>
      <div class="metric-item">
        <span class="metric-label">RATE-LIMITED:</span>
        <span class="metric-val amber" id="stat-ratelimit">0</span>
      </div>
      
    </div>
  </header>

  <!-- =======================================================================
       MACOS TERMINAL WINDOW (CONTAINS ONLY LOGS)
       ======================================================================= -->
  <main class="mac-window">
    <!-- macOS Titlebar -->
    <div class="mac-titlebar">
      <div class="traffic-lights">
        <div class="traffic-dot dot-close" title="Close"></div>
        <div class="traffic-dot dot-minimize" title="Minimize"></div>
        <div class="traffic-dot dot-maximize" title="Maximize"></div>
      </div>

      <div class="mac-title">
        
      </div>

      <div class="mac-controls">
        <!-- Professional Segmented Filters -->
        <div class="filter-segmented">
          <button id="filter-all" class="filter-btn active" onclick="setFilter('ALL')">All</button>
          <button id="filter-blocked" class="filter-btn" onclick="setFilter('BLOCKED')">Blocked</button>
          <button id="filter-passed" class="filter-btn" onclick="setFilter('PASSED')">Passed</button>
        </div>

        <!-- Sleek Action Controls -->
        <button id="autoscroll-btn" class="btn-action active" onclick="toggleAutoScroll()">
          <span class="btn-dot"></span>
          <span id="autoscroll-text">Autoscroll: On</span>
        </button>
        <button class="btn-action" onclick="clearLogs()">Clear</button>
      </div>
    </div>

    <!-- Terminal Body: ONLY LOGS -->
    <div class="terminal-body" id="terminal-screen">
      <div class="terminal-feed" id="terminal-feed">
        <div class="empty-logs" id="empty-state">
          <div>Listening on 0.0.0.0:8000 &rarr; 127.0.0.1:8080 &bull; Ready for incoming HTTP traffic...</div>
          <div class="empty-sub">Packets will stream here in real time as requests are inspected.</div>
        </div>
      </div>
    </div>
  </main>

  <script>
    let logs = [];
    let currentFilter = 'ALL';
    let autoScroll = true;
    let stats = { total: 0, passed: 0, blocked: 0, ratelimit: 0 };

    function updateStatsDisplay() {
      document.getElementById('stat-total').innerText = stats.total;
      document.getElementById('stat-passed').innerText = stats.passed;
      document.getElementById('stat-blocked').innerText = stats.blocked;
      document.getElementById('stat-ratelimit').innerText = stats.ratelimit;
    }

    function renderLogEntry(item) {
      const isBlocked = item.action === 'BLOCK' || item.status_code === 403;
      const isRateLimit = item.status_code === 429;
      
      let typeClass = 'allow';
      let tagText = `[PASSED - ${item.status_code || 200}]`;
      let tagClass = 'pass';

      if (isRateLimit) {
        typeClass = 'ratelimit';
        tagText = '[RATE-LIMITED - 429]';
        tagClass = 'limit';
      } else if (isBlocked) {
        typeClass = 'block';
        tagText = `[BLOCKED - ${item.status_code || 403}]`;
        tagClass = 'fail';
      }

      const div = document.createElement('div');
      div.className = `log-entry ${typeClass}`;
      div.dataset.action = isBlocked ? 'BLOCKED' : 'PASSED';

      let treeHtml = '';
      if (isBlocked) {
        treeHtml = `
          <div class="log-tree">
            <div><span class="tree-branch">├──</span> <span class="log-highlight-red">VIOLATION:</span> ${escapeHtml(item.rule_id || 'SECURITY_POLICY')} (Stage: ${escapeHtml(item.pipeline_stage || 'INSPECTION')})</div>
            <div><span class="tree-branch">├──</span> <span>Reason:</span> ${escapeHtml(item.reason || 'Malicious signature detected')}</div>
            ${item.threat_score ? `<div><span class="tree-branch">└──</span> <span>Confidence:</span> ${(item.threat_score * 100).toFixed(0)}%</div>` : '<div><span class="tree-branch">└──</span> <span>Action:</span> Immediate 403 Drop</div>'}
          </div>
        `;
      } else {
        treeHtml = `
          <div class="log-tree">
            <div><span class="tree-branch">└──</span> <span class="log-highlight-green">VERDICT:</span> Clean Request &bull; Forwarded to Upstream Backend (:8080)</div>
          </div>
        `;
      }

      const timeStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();

      div.innerHTML = `
        <div class="log-main">
          <span class="log-ts">[${timeStr}]</span>
          <span class="log-verdict ${tagClass}">${tagText}</span>
          <span class="log-ip">${escapeHtml(item.client_ip || '127.0.0.1')}</span>
          <span class="log-cmd">${escapeHtml(item.method || 'GET')}</span>
          <span class="log-url">${escapeHtml(item.url || '/')}</span>
        </div>
        ${treeHtml}
      `;

      return div;
    }

    function applyFilter() {
      const feed = document.getElementById('terminal-feed');
      const emptyState = document.getElementById('empty-state');
      let visibleCount = 0;
      const items = feed.getElementsByClassName('log-entry');

      for (let el of items) {
        const matches = (currentFilter === 'ALL') || (el.dataset.action === currentFilter);
        el.style.display = matches ? 'block' : 'none';
        if (matches) visibleCount++;
      }

      if (emptyState) {
        emptyState.style.display = (items.length === 0 || visibleCount === 0) ? 'flex' : 'none';
      }
    }

    function addLog(event) {
      const feed = document.getElementById('terminal-feed');
      const emptyState = document.getElementById('empty-state');
      if (emptyState) emptyState.style.display = 'none';

      stats.total++;
      if (event.action === 'BLOCK' || event.status_code === 403) {
        stats.blocked++;
      } else if (event.status_code === 429) {
        stats.ratelimit++;
        stats.blocked++;
      } else {
        stats.passed++;
      }
      updateStatsDisplay();

      const el = renderLogEntry(event);
      feed.appendChild(el);
      logs.push(event);

      applyFilter();

      if (autoScroll) {
        const bodyScreen = document.getElementById('terminal-screen');
        bodyScreen.scrollTop = bodyScreen.scrollHeight;
      }
    }

    function setFilter(filter) {
      currentFilter = filter;
      document.getElementById('filter-all').className = filter === 'ALL' ? 'filter-btn active' : 'filter-btn';
      document.getElementById('filter-blocked').className = filter === 'BLOCKED' ? 'filter-btn active' : 'filter-btn';
      document.getElementById('filter-passed').className = filter === 'PASSED' ? 'filter-btn active' : 'filter-btn';
      applyFilter();
    }

    function toggleAutoScroll() {
      autoScroll = !autoScroll;
      const btn = document.getElementById('autoscroll-btn');
      const text = document.getElementById('autoscroll-text');
      text.innerText = `Autoscroll: ${autoScroll ? 'On' : 'Off'}`;
      btn.className = autoScroll ? 'btn-action active' : 'btn-action';
    }

    function clearLogs() {
      const feed = document.getElementById('terminal-feed');
      feed.innerHTML = `
        <div class="empty-logs" id="empty-state">
          <div>Console cleared. Waiting for traffic...</div>
          <div class="empty-sub">Packets will stream here in real time as requests are inspected.</div>
        </div>
      `;
      logs = [];
      stats = { total: 0, passed: 0, blocked: 0, ratelimit: 0 };
      updateStatsDisplay();
    }

    function escapeHtml(text) {
      if (!text) return '';
      return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    // 1. Initial Load of past logs
    async function loadPastLogs() {
      try {
        const res = await fetch('/api/waf/logs');
        if (res.ok) {
          const data = await res.json();
          if (data.logs && Array.isArray(data.logs)) {
            data.logs.forEach(log => addLog(log));
          }
        }
      } catch (err) {}
    }

    // 2. Connect to SSE Stream
    function initEventStream() {
      try {
        const source = new EventSource('/api/waf/stream');

        source.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data);
            addLog(data);
          } catch (err) {}
        };

        source.onerror = () => {
          source.close();
          setInterval(pollLatestLogs, 1500);
        };
      } catch (err) {
        setInterval(pollLatestLogs, 1500);
      }
    }

    let lastPolledIndex = 0;
    async function pollLatestLogs() {
      try {
        const res = await fetch('/api/waf/logs?since=' + lastPolledIndex);
        if (res.ok) {
          const data = await res.json();
          if (data.logs && data.logs.length > 0) {
            data.logs.forEach(log => addLog(log));
            lastPolledIndex = data.total_count || (lastPolledIndex + data.logs.length);
          }
        }
      } catch (err) {}
    }

    loadPastLogs().then(() => {
      initEventStream();
    });
  </script>
</body>
</html>
"""
