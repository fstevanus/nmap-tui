/* ---------------------------------------------------------------------------
 * NMAP·WEB — frontend application
 * Vanilla JS. No dependencies, no build step, no external resources.
 * ------------------------------------------------------------------------ */
(function () {
  'use strict';

  /* =======================================================================
   * Constants & defaults
   * ==================================================================== */

  const MAX_LOG_LINES = 2000;
  const PORT_RENDER_LIMIT = 200;

  const FALLBACK_PRESETS = [
    { id: 'regular', label: 'Regular scan', desc: 'Default: 1000 most common TCP ports, SYN stealth.' },
    { id: 'quick', label: 'Quick scan', desc: 'Top 100 ports, timing template 4. Fast first look.' },
    { id: 'quickPlus', label: 'Quick scan plus', desc: 'Quick scan + service/version and OS detection.' },
    { id: 'pingSweep', label: 'Ping sweep', desc: 'Find which hosts are online. No port scan.' },
    { id: 'quickTraceroute', label: 'Quick traceroute', desc: 'Ping sweep plus traceroute to each host.' },
    { id: 'intense', label: 'Intense scan', desc: '-T4 -A -v: OS, versions, scripts, traceroute.' },
    { id: 'intenseUdp', label: 'Intense + UDP', desc: 'Intense scan including common UDP ports.' },
    { id: 'intenseAllTcp', label: 'Intense, all TCP', desc: 'All 65535 TCP ports, -T4 -A -v.' },
    { id: 'intenseAllPlusUdp', label: 'Intense, all + UDP', desc: 'All TCP and UDP ports, -T4 -A -v.' },
    { id: 'intenseNoPing', label: 'Intense, no ping', desc: 'Skips host discovery (-Pn). For firewalled hosts.' },
    { id: 'fullPortSyn', label: 'Full port SYN', desc: 'All 65535 TCP ports, SYN stealth, -T4.' },
    { id: 'vuln', label: 'Vulnerability', desc: '-sV plus the vuln NSE script category. Use responsibly.' },
    { id: 'slowComprehensive', label: 'Slow comprehensive', desc: 'TCP+UDP, many ping probes, discovery+safe scripts.' },
    { id: 'custom', label: 'Custom', desc: 'Compose your own scan from the options below.' }
  ];

  const PRESET_FLAGS = {
    regular: '',
    quick: '-T4 -F',
    quickPlus: '-sV -T4 -O -F',
    pingSweep: '-sn',
    quickTraceroute: '-sn --traceroute',
    intense: '-T4 -A -v',
    intenseUdp: '-sS -sU -T4 -A -v',
    intenseAllTcp: '-p 1-65535 -T4 -A -v',
    intenseAllPlusUdp: '-sS -sU -T4 -A -v -p 1-65535',
    intenseNoPing: '-T4 -A -v -Pn',
    fullPortSyn: '-sS -p- -T4',
    vuln: '-Pn -sV --script=vuln',
    slowComprehensive: '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -g 53 --script "default or (discovery and safe)"',
    custom: ''
  };

  const PRESET_ICONS = {
    regular: 'target',
    quick: 'zap',
    quickPlus: 'gauge',
    pingSweep: 'radar',
    quickTraceroute: 'route',
    intense: 'flame',
    intenseUdp: 'waves',
    intenseAllTcp: 'grid',
    intenseAllPlusUdp: 'layers',
    intenseNoPing: 'shield',
    fullPortSyn: 'plug',
    vuln: 'alert',
    slowComprehensive: 'clock',
    custom: 'sliders'
  };

  const ICON_PATHS = {
    dot: '<circle cx="12" cy="12" r="3.2" fill="currentColor" stroke="none"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5.2"/><path d="M12 12 18 6"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="11" cy="11" r="6.3"/><path d="m15.7 15.7 4.3 4.3"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12 19 4M17 4l3 3M15 6l2 2"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    close: '<path d="M6 6l12 12M18 6 6 18"/>',
    chevron: '<path d="m6 9 6 6 6-6"/>',
    terminal: '<path d="m5 7 5 5-5 5M13 17h6"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14M10 11v6M14 11v6"/>',
    stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    alert: '<path d="M12 3 2.5 20h19L12 3z"/><path d="M12 9v5M12 17v.4"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    plug: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v4"/>',
    shield: '<path d="M12 3 4.5 6v6c0 4.5 3 7.5 7.5 9 4.5-1.5 7.5-4.5 7.5-9V6z"/>',
    route: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h5a4 4 0 0 1 0 8H9a4 4 0 0 0 0 8h7"/>',
    activity: '<path d="M3 12h4l2-7 4 14 2-7h6"/>',
    gauge: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="m12 14 4-4"/><circle cx="12" cy="14" r="1.5"/>',
    flame: '<path d="M12 3c1 4-3 5-3 9a3 3 0 0 0 6 0c0-1-.5-2-1-3 3 2 5 4 5 7a7 7 0 0 1-14 0c0-5 4-8 7-13z"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17l9 5 9-5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z"/>',
    sliders: '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
    target: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
    zap: '<path d="M13 2 4 14h6l-1 8 9-12h-6l1-8z"/>',
    grid: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>',
    waves: '<path d="M3 8c3-3 6 3 9 0s6 3 9 0M3 14c3-3 6 3 9 0s6 3 9 0M3 20c3-3 6 3 9 0s6 3 9 0"/>',
    lock: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    refresh: '<path d="M20 11a8 8 0 1 0-2.3 6.7M20 5v6h-6"/>',
    arrowLeft: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    eye: '<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/>'
  };

  function icon(name, cls) {
    const path = ICON_PATHS[name] || ICON_PATHS.dot;
    return '<svg class="ico' + (cls ? ' ' + cls : '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + path + '</svg>';
  }

  function defaultOptions() {
    return {
      scanType: 'syn',
      ports: 'default',
      topPorts: 100,
      portList: '',
      ping: {
        skip: false,
        synPorts: '',
        ackPorts: '',
        udpPorts: '',
        icmpEcho: false,
        icmpTimestamp: false,
        icmpNetmask: false,
        disableArp: false,
        dns: 'default'
      },
      service: { version: false, intensity: 7, light: false, all: false },
      os: { detect: false, guess: false },
      aggressive: false,
      scripts: { defaults: false, list: '', args: '', trace: false },
      timing: { template: 3, minRate: '', maxRate: '', hostTimeout: '', scanDelay: '', maxRetries: '' },
      firewall: {
        fragment: false, mtu: '', decoys: '', spoofSource: '', sourcePort: '',
        dataLength: '', ttl: '', spoofMac: '', badsum: false, interface: ''
      },
      output: { verbose: 0, reason: false, openOnly: false, packetTrace: false, traceroute: false, ipv6: false },
      extraArgs: ''
    };
  }

  /* =======================================================================
   * State
   * ==================================================================== */

  const state = {
    token: '',
    view: 'form',
    routeKey: null,
    currentId: null,
    current: null,
    presets: FALLBACK_PRESETS.slice(),
    history: [],
    historyKey: '',
    historyFilter: '',
    health: null,
    backendOk: true,
    authError: false,
    authToastAt: 0,
    connKind: '',
    form: { name: '', targets: '', profile: 'quick', options: defaultOptions() },
    formOpen: new Set(['technique', 'ports']),
    previewTimer: null,
    logLines: [],
    logScanId: null,
    logQueue: [],
    logRaf: null,
    autoScroll: true,
    progress: { percent: 0, stats: '', known: false },
    queuedPosition: null,
    ws: null,
    wsAttempt: 0,
    wsTimer: null,
    wsWasReconnect: false,
    elapsedTimer: null,
    transitionTimer: null,
    openHosts: new Set(),
    openHostsScan: null,
    allPorts: new Set(),
    hosts: [],
    armed: new Map(),
    starting: false,
    booted: false
  };

  /* =======================================================================
   * Tiny utilities
   * ==================================================================== */

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

  const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
  }
  const escAttr = esc;

  function parseTargets(raw) {
    return String(raw == null ? '' : raw).split(/[\s,]+/).filter(Boolean);
  }

  function truncate(str, n) {
    const s = String(str == null ? '' : str);
    return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s;
  }

  function getPath(obj, path) {
    return String(path).split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
  }

  function setPath(obj, path, value) {
    const parts = String(path).split('.');
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = value;
  }

  function debounce(fn, ms) {
    let t = null;
    return function () {
      const args = arguments;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), ms);
    };
  }

  function clamp(n, min, max) {
    n = Number(n);
    if (!isFinite(n)) return min;
    return Math.max(min, Math.min(max, n));
  }

  function parseDate(value) {
    if (!value) return null;
    const t = Date.parse(value);
    return isNaN(t) ? null : t;
  }

  function timeAgo(iso) {
    const t = parseDate(iso);
    if (t == null) return '—';
    const diff = Date.now() - t;
    if (diff < 0) return 'just now';
    const sec = Math.floor(diff / 1000);
    if (sec < 10) return 'just now';
    if (sec < 60) return sec + 's ago';
    const min = Math.floor(sec / 60);
    if (min < 60) return min + 'm ago';
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + 'h ago';
    const day = Math.floor(hr / 24);
    if (day < 7) return day + 'd ago';
    return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function absTime(iso) {
    const t = parseDate(iso);
    if (t == null) return '';
    return new Date(t).toLocaleString();
  }

  function formatClock(ms) {
    if (!isFinite(ms) || ms < 0) ms = 0;
    const total = Math.floor(ms / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return h + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
    return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
  }

  function formatDurationMs(ms) {
    if (ms == null || !isFinite(Number(ms)) || Number(ms) < 0) return '—';
    ms = Number(ms);
    if (ms < 1000) return Math.round(ms) + 'ms';
    if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + 's';
    const total = Math.floor(ms / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm ' + s + 's';
  }

  function formatUptime(seconds) {
    const n = parseInt(seconds, 10);
    if (!n || n < 0) return '';
    const d = Math.floor(n / 86400);
    const h = Math.floor((n % 86400) / 3600);
    const m = Math.floor((n % 3600) / 60);
    const parts = [];
    if (d) parts.push(d + 'd');
    if (h) parts.push(h + 'h');
    if (m && parts.length < 2) parts.push(m + 'm');
    return parts.join(' ') || n + 's';
  }

  function firstLine(text) {
    return String(text == null ? '' : text).split('\n')[0].trim();
  }

  /* stderrTail arrives as an ARRAY in live WS error events but as a STRING
   * in snapshots built from the stored record — accept both shapes. */
  function stderrLines(tail) {
    if (Array.isArray(tail)) {
      return tail.filter((l) => l != null && String(l).trim() !== '').map(String);
    }
    if (typeof tail === 'string' && tail.trim()) {
      return tail.split(/\r?\n/).filter((l) => l.trim() !== '');
    }
    return [];
  }

  function targetPreview(targets, max) {
    const tokens = parseTargets(targets);
    if (!tokens.length) return '—';
    const lim = max || 2;
    if (tokens.length <= lim) return tokens.join(' ');
    return tokens.slice(0, lim).join(' ') + ' +' + (tokens.length - lim);
  }

  function stateClass(value) {
    return 'st-' + String(value == null ? 'unknown' : value).replace(/[^a-z]/gi, '').toLowerCase();
  }

  function stateChip(value) {
    const v = value == null || value === '' ? 'unknown' : String(value);
    return '<span class="chip state-chip ' + stateClass(v) + '">' + esc(v) + '</span>';
  }

  function statusPill(value, queuePosition) {
    const status = String(value || 'queued');
    const label = status === 'queued' && queuePosition ? 'QUEUED #' + queuePosition : status.toUpperCase();
    const spinner = status === 'running' ? '<span class="pill-spinner" aria-hidden="true"></span>' : '<span class="pill-dot" aria-hidden="true"></span>';
    return '<span class="status-pill sp-' + escAttr(status) + '">' + spinner + esc(label) + '</span>';
  }

  function classifyLine(line) {
    const s = String(line == null ? '' : line);
    if (/^\[server\]/i.test(s)) return 'log-server';
    if (/^Timing:/i.test(s)) return 'log-dim';
    if (/\b(warning|caution|deprecated)\b/i.test(s)) return 'log-warn';
    if (/\b(error|failed|failure|fatal|cannot|unable|refused)\b/i.test(s)) return 'log-error';
    if (/\bStats:|About\s+[\d.]+\s*%\s+done|elapsed/i.test(s)) return 'log-stats';
    if (/Nmap scan report for|Discovered open port/i.test(s)) return 'log-ok';
    if (/^Nmap done|^Host is up|^Not shown:/i.test(s)) return 'log-accent';
    return 'log-line';
  }

  /* =======================================================================
   * Toasts & clipboard
   * ==================================================================== */

  function toast(message, type, ms) {
    const root = $('#toasts');
    if (!root) return;
    while (root.children.length >= 4) root.removeChild(root.firstElementChild);
    const kind = type || 'info';
    const el = document.createElement('div');
    el.className = 'toast toast-' + kind;
    const ico = kind === 'success' ? 'check' : kind === 'error' ? 'alert' : 'activity';
    el.innerHTML = '<span class="toast-ico">' + icon(ico) + '</span>' +
      '<span class="toast-msg"></span>' +
      '<button class="toast-close" type="button" aria-label="Dismiss notification">' + icon('close') + '</button>';
    el.querySelector('.toast-msg').textContent = String(message);
    const dismiss = () => {
      if (el.classList.contains('out')) return;
      el.classList.add('out');
      setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 190);
    };
    el.querySelector('.toast-close').addEventListener('click', dismiss);
    root.appendChild(el);
    setTimeout(dismiss, ms || (kind === 'error' ? 5600 : 3800));
  }

  async function copyText(text, okMessage) {
    const value = String(text == null ? '' : text);
    if (!value) {
      toast('Nothing to copy', 'info');
      return false;
    }
    try {
      await navigator.clipboard.writeText(value);
      toast(okMessage || 'Copied to clipboard', 'success');
      return true;
    } catch (err) {
      try {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast(okMessage || 'Copied to clipboard', 'success');
        return true;
      } catch (err2) {
        toast('Could not copy to clipboard', 'error');
        return false;
      }
    }
  }

  /* =======================================================================
   * API
   * ==================================================================== */

  class ApiError extends Error {
    constructor(message, status, data) {
      super(message);
      this.name = 'ApiError';
      this.status = status || 0;
      this.data = data;
    }
  }

  function handleUnauthorized() {
    state.authError = true;
    const now = Date.now();
    if (now - state.authToastAt > 4000) {
      state.authToastAt = now;
      toast('Access token required — open the key icon in the sidebar', 'error');
    }
    setBackend(false, { status: 401 });
  }

  async function api(path, options) {
    const opts = Object.assign({ method: 'GET' }, options || {});
    const headers = new Headers(opts.headers || {});
    if (state.token) headers.set('X-Auth-Token', state.token);
    let body = opts.body;
    if (body !== undefined && body !== null && typeof body !== 'string' && !(body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, {
        method: opts.method,
        headers: headers,
        body: body,
        signal: opts.signal,
        cache: 'no-store'
      });
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
      throw new ApiError('Backend unreachable', 0, null);
    }
    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (err) { data = text; }
    }
    if (!res.ok) {
      let message = 'Request failed (' + res.status + ')';
      if (data && typeof data === 'object' && data.error) message = data.error;
      else if (typeof data === 'string' && data.trim() && res.status !== 404) message = truncate(data.trim(), 180);
      if (res.status === 401) handleUnauthorized();
      throw new ApiError(message, res.status, data);
    }
    return data == null ? {} : data;
  }

  function setConn(kind, text) {
    state.connKind = kind;
    $$('.conn-dot').forEach((dot) => { dot.className = 'conn-dot ' + kind; });
    const label = $('#connText');
    if (label) label.textContent = text || kind;
  }

  function setBackend(ok, detail) {
    state.backendOk = ok;
    const banner = $('#backendBanner');
    if (!banner) return;
    if (ok) {
      state.authError = false;
      banner.hidden = true;
      banner.classList.remove('show', 'is-auth');
      return;
    }
    const auth = state.authError || (detail && detail.status === 401);
    banner.hidden = false;
    banner.classList.add('show');
    banner.classList.toggle('is-auth', !!auth);
    const text = $('#bannerText');
    if (text) {
      text.textContent = auth
        ? 'The server rejected the request. Set your access token to continue.'
        : 'Could not reach the API. Is the server running?';
    }
    const tokenBtn = $('#bannerToken');
    if (tokenBtn) tokenBtn.hidden = !auth;
    const heading = $('.banner-copy strong');
    if (heading) heading.textContent = auth ? 'Authentication required' : 'Backend unreachable';
    setConn('offline', auth ? 'Unauthorized' : 'Offline');
  }

  function setVersion(version) {
    const el = $('#nmapVersion');
    if (!el) return;
    const raw = String(version || '');
    const m = /nmap version\s+([0-9.]+)/i.exec(raw);
    el.textContent = m ? 'nmap ' + m[1] : (raw ? truncate(raw, 26) : 'nmap —');
    el.title = raw || 'nmap version unavailable';
  }

  async function loadHealth() {
    try {
      const data = await api('/api/health');
      state.health = data || {};
      setVersion(state.health.nmapVersion);
      setBackend(true);
      if (!state.ws || state.ws.readyState !== 1) setConn('online', 'API online');
    } catch (err) {
      if (err.status !== 401) setBackend(false, err);
    }
  }

  async function loadPresets() {
    try {
      const data = await api('/api/presets');
      if (data && Array.isArray(data.presets) && data.presets.length) {
        state.presets = data.presets;
        if (state.view === 'form') {
          const track = $('#presetTrack');
          if (track) {
            track.innerHTML = presetCardsHTML();
            syncPresetUI();
            updatePreview();
          }
        }
      }
    } catch (err) {
      /* fallback presets are already in state */
    }
  }

  async function loadHistory(opts) {
    const silent = !!(opts && opts.silent);
    try {
      const data = await api('/api/scans');
      const scans = data && Array.isArray(data.scans) ? data.scans : [];
      const key = JSON.stringify(scans);
      state.history = scans;
      if (key !== state.historyKey) {
        state.historyKey = key;
        renderHistory();
      } else {
        refreshAgo();
      }
      if (state.backendOk === false) {
        setBackend(true);
        if (!state.ws || state.ws.readyState !== 1) setConn('online', 'API online');
      }
    } catch (err) {
      if (!silent) setBackend(false, err);
    }
  }

  /* =======================================================================
   * History sidebar
   * ==================================================================== */

  function historyBadges(scan) {
    if (scan.status !== 'done' || !scan.summary) return '';
    const s = scan.summary;
    const up = Number(s.hostsUp) || 0;
    const open = Number(s.openPorts) || 0;
    return '<span class="history-badges">' +
      '<span class="mini-badge" title="' + up + ' host' + (up === 1 ? '' : 's') + ' up">' + icon('server', 'xs') + up + '</span>' +
      '<span class="mini-badge" title="' + open + ' open port' + (open === 1 ? '' : 's') + '">' + icon('plug', 'xs') + open + '</span>' +
      '</span>';
  }

  function historyLabel(scan) {
    if (scan.name) return scan.name;
    const tokens = parseTargets(scan.targets);
    if (!tokens.length) return 'Untitled scan';
    if (tokens.length === 1) return tokens[0];
    return tokens[0] + ' +' + (tokens.length - 1);
  }

  function renderHistory() {
    const list = $('#historyList');
    if (!list) return;
    const keepScroll = list.scrollTop;
    const filter = state.historyFilter.trim().toLowerCase();
    const filtered = filter
      ? state.history.filter((s) => {
          const hay = [s.name, s.targets, s.status, s.profile, s.id].join(' ').toLowerCase();
          return hay.indexOf(filter) !== -1;
        })
      : state.history;

    const count = $('#historyCount');
    if (count) count.textContent = String(state.history.length);

    if (!filtered.length) {
      list.innerHTML = '<div class="history-empty">' +
        (filter ? icon('search') + '<span>No matching scans</span>' : icon('radar') + '<span>No scans yet</span><small>Start one above to see it here.</small>') +
        '</div>';
      list.scrollTop = keepScroll;
      return;
    }

    list.innerHTML = filtered.map((scan) => {
      const status = scan.status || 'queued';
      const active = scan.id === state.currentId;
      const when = scan.finishedAt || scan.createdAt;
      const profile = scan.profile && scan.profile !== 'custom' ? scan.profile : '';
      return '<button type="button" class="history-item' + (active ? ' is-active' : '') + '" data-action="open-scan" data-id="' + escAttr(scan.id) + '" title="' + escAttr(scan.name || scan.targets || scan.id) + '">' +
        '<span class="history-dot ' + escAttr(status) + '" title="' + escAttr(status) + '"></span>' +
        '<span class="history-main">' +
          '<span class="history-name">' + esc(historyLabel(scan)) + '</span>' +
          '<span class="history-sub"><span data-ago="' + escAttr(when || '') + '">' + esc(timeAgo(when)) + '</span>' + (profile ? '<span class="history-sep">·</span><span>' + esc(profile) + '</span>' : '') + '</span>' +
        '</span>' +
        historyBadges(scan) +
        '</button>';
    }).join('');
    list.scrollTop = keepScroll;
  }

  function refreshAgo() {
    $$('[data-ago]').forEach((el) => {
      el.textContent = timeAgo(el.getAttribute('data-ago'));
    });
  }

  /* =======================================================================
   * Form definitions & markup
   * ==================================================================== */

  function check(path, label, flag, checked, title) {
    return '<label class="check" title="' + escAttr(title || label + (flag ? ' ' + flag : '')) + '">' +
      '<input type="checkbox" data-opt="' + escAttr(path) + '"' + (checked ? ' checked' : '') + '>' +
      '<span class="checkbox" aria-hidden="true"></span>' +
      '<span class="check-text">' + esc(label) + (flag ? ' <code>' + esc(flag) + '</code>' : '') + '</span>' +
      '</label>';
  }

  function pill(path, value, label, flag, checked, title) {
    return '<label class="pill" title="' + escAttr(title || label + (flag ? ' ' + flag : '')) + '">' +
      '<input type="radio" name="' + escAttr(path) + '" data-opt="' + escAttr(path) + '" value="' + escAttr(value) + '"' + (checked ? ' checked' : '') + '>' +
      '<span class="pill-body"><span class="pill-label">' + esc(label) + '</span>' + (flag ? '<code>' + esc(flag) + '</code>' : '') + '</span>' +
      '</label>';
  }

  function field(opts) {
    const o = opts || {};
    const type = o.type || 'text';
    const attrs = [];
    attrs.push('data-opt="' + escAttr(o.path) + '"');
    if (o.cast) attrs.push('data-cast="' + escAttr(o.cast) + '"');
    if (type === 'number') {
      if (o.min != null) attrs.push('min="' + escAttr(o.min) + '"');
      if (o.max != null) attrs.push('max="' + escAttr(o.max) + '"');
      if (o.step != null) attrs.push('step="' + escAttr(o.step) + '"');
    }
    if (o.inputmode) attrs.push('inputmode="' + escAttr(o.inputmode) + '"');
    return '<label class="field" title="' + escAttr(o.title || o.label + (o.flag ? ' ' + o.flag : '')) + '"' + (o.showIf ? ' data-show-if="' + escAttr(o.showIf) + '"' : '') + '>' +
      '<span class="field-label">' + esc(o.label) + (o.flag ? ' <code>' + esc(o.flag) + '</code>' : '') + '</span>' +
      '<span class="input-shell' + (o.prefix ? ' has-prefix' : '') + '">' +
        (o.prefix ? '<span class="input-prefix">' + esc(o.prefix) + '</span>' : '') +
        '<input class="input" type="' + type + '" ' + attrs.join(' ') + ' value="' + escAttr(o.value == null ? '' : o.value) + '" placeholder="' + escAttr(o.placeholder || '') + '" spellcheck="false" autocomplete="off">' +
      '</span>' +
      '</label>';
  }

  function selectField(opts) {
    return '<label class="field" title="' + escAttr(opts.title || opts.label) + '">' +
      '<span class="field-label">' + esc(opts.label) + (opts.flag ? ' <code>' + esc(opts.flag) + '</code>' : '') + '</span>' +
      '<span class="select-shell"><select class="input select" data-opt="' + escAttr(opts.path) + '" title="' + escAttr(opts.title || opts.label) + '">' +
      opts.options.map((o) => '<option value="' + escAttr(o.value) + '"' + (String(o.value) === String(opts.value) ? ' selected' : '') + '>' + esc(o.label) + '</option>').join('') +
      '</select>' + icon('chevron', 'select-chev') + '</span>' +
      '</label>';
  }

  function segmented(path, options, value, cast) {
    return '<div class="segmented" role="radiogroup">' + options.map((o) => {
      return '<label class="seg" title="' + escAttr(o.title || o.label) + '">' +
        '<input type="radio" name="' + escAttr(path) + '" data-opt="' + escAttr(path) + '" value="' + escAttr(o.value) + '"' + (cast ? ' data-cast="' + escAttr(cast) + '"' : '') + (String(o.value) === String(value) ? ' checked' : '') + '>' +
        '<span>' + esc(o.label) + (o.sub ? '<em>' + esc(o.sub) + '</em>' : '') + '</span>' +
        '</label>';
    }).join('') + '</div>';
  }

  function accordion(id, title, subtitle, body, open) {
    return '<section class="acc' + (open ? ' open' : '') + '" data-acc-section="' + escAttr(id) + '">' +
      '<button type="button" class="acc-head" data-action="accordion" data-acc-id="' + escAttr(id) + '" aria-expanded="' + (open ? 'true' : 'false') + '">' +
        '<span class="acc-title"><span class="acc-name">' + esc(title) + '</span><span class="acc-sub">' + esc(subtitle) + '</span></span>' +
        '<span class="acc-chev">' + icon('chevron') + '</span>' +
      '</button>' +
      '<div class="acc-panel"><div class="acc-inner"><div class="acc-body">' + body + '</div></div></div>' +
      '</section>';
  }

  function presetCardsHTML() {
    return state.presets.map((p) => {
      const selected = p.id === state.form.profile;
      return '<button type="button" class="preset-card' + (selected ? ' is-selected' : '') + '" data-action="select-preset" data-preset="' + escAttr(p.id) + '" aria-pressed="' + (selected ? 'true' : 'false') + '" title="' + escAttr(p.desc || p.label) + '">' +
        '<span class="preset-ico">' + icon(PRESET_ICONS[p.id] || 'target') + '</span>' +
        '<span class="preset-copy"><span class="preset-name">' + esc(p.label) + '</span><span class="preset-desc">' + esc(p.desc || '') + '</span></span>' +
        '</button>';
    }).join('');
  }

  function techniqueBody(o) {
    const types = [
      ['syn', 'TCP SYN', '-sS', 'Stealth half-open scan. Requires raw packet privileges.'],
      ['connect', 'TCP Connect', '-sT', 'Full TCP connect; works without raw privileges.'],
      ['udp', 'UDP', '-sU', 'UDP scan; slow but essential for DNS, SNMP, DHCP and more.'],
      ['ack', 'TCP ACK', '-sA', 'Map firewall rules; tells filtered from unfiltered.'],
      ['window', 'TCP Window', '-sW', 'Detect open/closed/filtered using TCP window size.'],
      ['maimon', 'TCP Maimon', '-sM', 'FIN/ACK probe for some BSD-derived stacks.'],
      ['fin', 'TCP FIN', '-sF', 'Stealth FIN probe; may slip past simple filters.'],
      ['xmas', 'Xmas', '-sX', 'FIN, PSH and URG flags set — lights up like a tree.'],
      ['null', 'NULL', '-sN', 'No TCP flags set.'],
      ['sctpInit', 'SCTP INIT', '-sY', 'SCTP association scan.'],
      ['sctpCookie', 'SCTP Cookie', '-sZ', 'SCTP COOKIE-ECHO scan.'],
      ['pingSweep', 'Ping sweep', '-sn', 'Host discovery only — no port scan.'],
      ['list', 'List scan', '-sL', 'List targets without probing them.'],
      ['none', 'None', '—', 'No scan-type flag; let other options decide.']
    ];
    return '<div class="pill-row">' + types.map((t) => pill('scanType', t[0], t[1], t[2], o.scanType === t[0], t[3])).join('') + '</div>' +
      '<div class="row-hint">' + icon('shield') + '<span>SYN, UDP and several stealth probes need raw packet access. The container is expected to run with the right capabilities.</span></div>';
  }

  function portsBody(o) {
    return '<div class="pill-row">' +
      pill('ports', 'default', 'Default', 'top 1000', o.ports === 'default', 'nmap default: scan the 1000 most common TCP ports.') +
      pill('ports', 'all', 'All ports', '-p-', o.ports === 'all', 'Scan all 65535 ports. Slow on large networks.') +
      pill('ports', 'fast', 'Fast', '-F', o.ports === 'fast', 'Fast mode: top 100 ports.') +
      pill('ports', 'top', 'Top N', '--top-ports', o.ports === 'top', 'Scan the N most common ports.') +
      pill('ports', 'list', 'Custom list', '-p', o.ports === 'list', 'Comma-separated ports and ranges, e.g. 22,80,443,8000-9000.') +
      '</div>' +
      '<div class="field-grid cols-2">' +
        field({ path: 'topPorts', label: 'Top ports', flag: '--top-ports', type: 'number', cast: 'number', value: o.topPorts, min: 1, max: 65535, placeholder: '100', inputmode: 'numeric', showIf: 'ports=top', title: 'Number of most common ports to scan (--top-ports).' }) +
        field({ path: 'portList', label: 'Port list', flag: '-p', value: o.portList, placeholder: '22,80,443,8000-9000', showIf: 'ports=list', title: 'Custom port list passed to -p. Accepts ranges and comma-separated values.' }) +
      '</div>';
  }

  function pingBody(o) {
    const p = o.ping;
    return '<div class="check-row">' +
        check('ping.skip', 'Skip host discovery', '-Pn', p.skip, 'Treat all targets as online. Essential for hosts that block ping.') +
        check('ping.disableArp', 'Disable ARP ping', '--disable-arp-ping', p.disableArp, 'Skip ARP requests during local-network discovery.') +
      '</div>' +
      '<div class="field-grid cols-3">' +
        field({ path: 'ping.synPorts', label: 'TCP SYN ping', flag: '-PS', value: p.synPorts, prefix: '-PS', placeholder: '80,443', title: 'TCP SYN discovery probes to these ports (-PS).' }) +
        field({ path: 'ping.ackPorts', label: 'TCP ACK ping', flag: '-PA', value: p.ackPorts, prefix: '-PA', placeholder: '3389', title: 'TCP ACK discovery probes to these ports (-PA).' }) +
        field({ path: 'ping.udpPorts', label: 'UDP ping', flag: '-PU', value: p.udpPorts, prefix: '-PU', placeholder: '40125', title: 'UDP discovery probes to these ports (-PU).' }) +
      '</div>' +
      '<div class="check-row">' +
        check('ping.icmpEcho', 'ICMP echo', '-PE', p.icmpEcho, 'Classic ICMP echo request discovery.') +
        check('ping.icmpTimestamp', 'ICMP timestamp', '-PP', p.icmpTimestamp, 'ICMP timestamp request discovery.') +
        check('ping.icmpNetmask', 'ICMP netmask', '-PM', p.icmpNetmask, 'ICMP address-mask request discovery.') +
      '</div>' +
      '<div class="field-grid cols-2">' +
        selectField({
          path: 'ping.dns', label: 'DNS resolution', flag: '-R / -n', value: p.dns,
          title: 'Control reverse DNS resolution during the scan.',
          options: [
            { value: 'default', label: 'Default — resolve when useful' },
            { value: 'always', label: 'Always resolve (-R)' },
            { value: 'never', label: 'Never resolve (-n)' }
          ]
        }) +
      '</div>';
  }

  function versionMode(o) {
    if (o.service.light) return 'light';
    if (o.service.all) return 'all';
    return 'default';
  }

  function serviceBody(o) {
    const mode = versionMode(o);
    return '<div class="check-stack">' +
        check('service.version', 'Service / version detection', '-sV', o.service.version, 'Probe open ports to identify services, products and versions.') +
        '<div class="reveal" data-show-if="service.version">' +
          '<div class="slider-field">' +
            '<div class="slider-head"><span class="field-label">Version intensity <code>--version-intensity</code></span><span class="slider-bubble" id="intensityVal">' + esc(o.service.intensity) + '</span></div>' +
            '<input type="range" min="0" max="9" step="1" data-opt="service.intensity" data-cast="number" value="' + escAttr(o.service.intensity) + '" title="Probe intensity from 0 (light) to 9 (all probes).">' +
            '<div class="range-labels"><span>0 · light</span><span>9 · all probes</span></div>' +
          '</div>' +
          '<div class="segmented compact" role="radiogroup" aria-label="Version detection profile">' +
            '<label class="seg" title="Use a light set of probes (--version-light)."><input type="radio" name="versionMode" data-version-mode="1" value="light"' + (mode === 'light' ? ' checked' : '') + '><span>Light</span></label>' +
            '<label class="seg" title="Use the configured probe intensity."><input type="radio" name="versionMode" data-version-mode="1" value="default"' + (mode === 'default' ? ' checked' : '') + '><span>Default</span></label>' +
            '<label class="seg" title="Try every probe (--version-all)."><input type="radio" name="versionMode" data-version-mode="1" value="all"' + (mode === 'all' ? ' checked' : '') + '><span>All</span></label>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="check-stack">' +
        check('os.detect', 'OS detection', '-O', o.os.detect, 'Fingerprint the remote operating system. Requires raw privileges.') +
        '<div class="reveal" data-show-if="os.detect">' +
          check('os.guess', 'Guess OS aggressively', '--osscan-guess', o.os.guess, 'Make OS detection more aggressive when no perfect match is found.') +
        '</div>' +
        check('aggressive', 'Aggressive scan', '-A', o.aggressive, 'Enables OS detection, version detection, script scanning and traceroute.') +
      '</div>';
  }

  function scriptsBody(o) {
    const s = o.scripts;
    return '<div class="check-row">' +
        check('scripts.defaults', 'Default scripts', '-sC', s.defaults, 'Run the default NSE script category.') +
        check('scripts.trace', 'Script trace', '--script-trace', s.trace, 'Show all data sent and received by NSE scripts.') +
      '</div>' +
      '<div class="field-grid cols-2">' +
        field({ path: 'scripts.list', label: 'Scripts', flag: '--script', value: s.list, placeholder: 'vuln  ·  default,safe  ·  http-*', title: 'NSE script names, categories or expressions passed to --script.' }) +
        field({ path: 'scripts.args', label: 'Script arguments', flag: '--script-args', value: s.args, placeholder: 'vulns.showall=1', title: 'Arguments passed to NSE scripts (--script-args).' }) +
      '</div>';
  }

  function timingBody(o) {
    const t = o.timing;
    const templates = [
      ['0', 'Paranoid', 'T0 · extremely slow, for IDS evasion.'],
      ['1', 'Sneaky', 'T1 · quite slow, for IDS evasion.'],
      ['2', 'Polite', 'T2 · slower, uses less bandwidth.'],
      ['3', 'Normal', 'T3 · nmap default timing.'],
      ['4', 'Aggressive', 'T4 · fast, assumes a reliable network.'],
      ['5', 'Insane', 'T5 · very fast, may miss ports on lossy links.']
    ];
    return '<div class="segmented timing-seg" role="radiogroup" aria-label="Timing template">' + templates.map((tpl) => {
      return '<label class="seg" title="' + escAttr(tpl[2]) + '"><input type="radio" name="timing.template" data-opt="timing.template" data-cast="number" value="' + tpl[0] + '"' + (String(t.template) === tpl[0] ? ' checked' : '') + '><span><b>T' + tpl[0] + '</b><em>' + tpl[1] + '</em></span></label>';
    }).join('') + '</div>' +
      '<div class="field-grid cols-3">' +
        field({ path: 'timing.minRate', label: 'Min rate', flag: '--min-rate', value: t.minRate, placeholder: 'e.g. 100', inputmode: 'numeric', title: 'Send packets no slower than this many per second (--min-rate).' }) +
        field({ path: 'timing.maxRate', label: 'Max rate', flag: '--max-rate', value: t.maxRate, placeholder: 'e.g. 1000', inputmode: 'numeric', title: 'Send packets no faster than this many per second (--max-rate).' }) +
        field({ path: 'timing.hostTimeout', label: 'Host timeout', flag: '--host-timeout', value: t.hostTimeout, placeholder: '500ms · 2m', title: 'Give up on a host after this much time (--host-timeout).' }) +
        field({ path: 'timing.scanDelay', label: 'Scan delay', flag: '--scan-delay', value: t.scanDelay, placeholder: 'e.g. 1s', title: 'Wait at least this long between probes (--scan-delay).' }) +
        field({ path: 'timing.maxRetries', label: 'Max retries', flag: '--max-retries', value: t.maxRetries, placeholder: 'e.g. 2', inputmode: 'numeric', title: 'Cap the number of probe retransmissions (--max-retries).' }) +
      '</div>';
  }

  function firewallBody(o) {
    const f = o.firewall;
    return '<div class="check-row">' +
        check('firewall.fragment', 'Fragment packets', '-f', f.fragment, 'Fragment packets to evade simple packet filters.') +
        check('firewall.badsum', 'Bad checksum', '--badsum', f.badsum, 'Send packets with an invalid checksum to probe firewall responses.') +
      '</div>' +
      '<div class="field-grid cols-3">' +
        field({ path: 'firewall.mtu', label: 'MTU', flag: '--mtu', value: f.mtu, placeholder: 'e.g. 24', inputmode: 'numeric', title: 'Set a custom MTU for fragmented packets (must be a multiple of 8).' }) +
        field({ path: 'firewall.decoys', label: 'Decoys', flag: '-D', value: f.decoys, placeholder: 'RND:10 · 10.0.0.1,10.0.0.2', title: 'Cloak the scan with decoy source addresses (-D).' }) +
        field({ path: 'firewall.spoofSource', label: 'Spoof source', flag: '-S', value: f.spoofSource, placeholder: 'e.g. 10.0.0.5', title: 'Spoof the source address of probes (-S).' }) +
        field({ path: 'firewall.sourcePort', label: 'Source port', flag: '-g', value: f.sourcePort, placeholder: 'e.g. 53', title: 'Use a specific source port (-g).' }) +
        field({ path: 'firewall.dataLength', label: 'Data length', flag: '--data-length', value: f.dataLength, placeholder: 'e.g. 32', inputmode: 'numeric', title: 'Append random data to packets to reach this length (--data-length).' }) +
        field({ path: 'firewall.ttl', label: 'TTL', flag: '--ttl', value: f.ttl, placeholder: 'e.g. 64', inputmode: 'numeric', title: 'Set a custom IP time-to-live (--ttl).' }) +
        field({ path: 'firewall.spoofMac', label: 'Spoof MAC', flag: '--spoof-mac', value: f.spoofMac, placeholder: '0 · Apple · 00:11:22:33:44:55', title: 'Use a different MAC address (--spoof-mac).' }) +
        field({ path: 'firewall.interface', label: 'Interface', flag: '-e', value: f.interface, placeholder: 'e.g. eth0', title: 'Send packets through a specific network interface (-e).' }) +
      '</div>';
  }

  function outputBody(o) {
    const out = o.output;
    return '<div class="field-grid cols-2">' +
        '<div class="field"><span class="field-label">Verbosity <code>-v</code></span>' +
          segmented('output.verbose', [
            { value: '0', label: '0', title: 'Quiet output (no -v flags).' },
            { value: '1', label: '1', title: 'One -v flag.' },
            { value: '2', label: '2', title: 'Two -v flags.' },
            { value: '3', label: '3', title: 'Three -v flags (maximum).' }
          ], out.verbose, 'number') +
        '</div>' +
      '</div>' +
      '<div class="check-row">' +
        check('output.reason', 'Show reason', '--reason', out.reason, 'Explain why a port is in a particular state (--reason).') +
        check('output.openOnly', 'Open ports only', '--open', out.openOnly, 'Only show hosts with at least one open port (--open).') +
        check('output.packetTrace', 'Packet trace', '--packet-trace', out.packetTrace, 'Print a summary of every packet sent and received (--packet-trace).') +
        check('output.traceroute', 'Traceroute', '--traceroute', out.traceroute, 'Trace the network path to each host (--traceroute).') +
        check('output.ipv6', 'IPv6', '-6', out.ipv6, 'Use IPv6 addressing instead of IPv4 (-6).') +
      '</div>';
  }

  function buildFormHTML() {
    const f = state.form;
    const o = f.options;
    return '<section class="view form-view">' +
      '<div class="view-inner form-inner">' +
        '<header class="view-head">' +
          '<div>' +
            '<div class="eyebrow"><span class="eyebrow-dot"></span>Recon / new scan</div>' +
            '<h1>New network scan</h1>' +
            '<p class="view-sub">Discover live hosts, open ports, services and OS fingerprints with nmap.</p>' +
          '</div>' +
          '<div class="head-note">' + icon('shield') + '<span>Runs on the host network</span></div>' +
        '</header>' +

        '<div class="card target-card">' +
          '<div class="card-topline">' +
            '<label class="section-label" for="targets">Targets <span class="req">*</span></label>' +
            '<span class="target-count" id="targetCount">0 targets</span>' +
          '</div>' +
          '<div class="target-shell" id="targetWrap">' +
            '<textarea id="targets" class="target-input" rows="3" spellcheck="false" autocomplete="off" title="One or more IPs, CIDR ranges, port ranges or hostnames. Separate with spaces, commas or newlines." placeholder="192.168.1.0/24&#10;10.0.0.1-50&#10;scanme.nmap.org">' + esc(f.targets) + '</textarea>' +
          '</div>' +
          '<div class="target-hint">IPs, CIDR ranges, ranges like <code>10.0.0.1-50</code>, or hostnames — separated by spaces, commas or newlines.</div>' +
          '<div class="name-row">' +
            '<label class="inline-field"><span class="section-label">Scan name</span>' +
              '<input id="scanName" class="input input-quiet" type="text" maxlength="200" autocomplete="off" spellcheck="false" title="Optional friendly name for this scan." placeholder="Optional label, e.g. Office LAN audit" value="' + escAttr(f.name) + '">' +
            '</label>' +
          '</div>' +
        '</div>' +

        '<section class="form-section">' +
          '<div class="section-head"><h2>Profile</h2><span class="section-note">Pick a preset, or choose Custom to tune every option</span></div>' +
          '<div class="preset-track" id="presetTrack">' + presetCardsHTML() + '</div>' +
          '<div class="preset-note" id="presetNote" hidden>' + icon('lock') + '<span>Preset arguments are fixed — choose <strong>Custom</strong> to tune individual options.</span>' +
            '<button class="note-action" type="button" data-action="select-preset" data-preset="custom">Customize options →</button></div>' +
        '</section>' +

        '<fieldset class="advanced-fieldset" id="advancedFieldset">' +
          '<legend class="sr-only">Advanced scan options</legend>' +
          accordion('technique', 'Scan technique', 'Probe type and privileges', techniqueBody(o), state.formOpen.has('technique')) +
          accordion('ports', 'Ports', 'Which ports and how many', portsBody(o), state.formOpen.has('ports')) +
          accordion('ping', 'Host discovery', 'Ping, ARP and DNS behaviour', pingBody(o), state.formOpen.has('ping')) +
          accordion('service', 'Service & OS detection', 'Versions, fingerprints and aggression', serviceBody(o), state.formOpen.has('service')) +
          accordion('scripts', 'NSE scripts', 'Script categories, names and arguments', scriptsBody(o), state.formOpen.has('scripts')) +
          accordion('timing', 'Timing & performance', 'Templates, rates and timeouts', timingBody(o), state.formOpen.has('timing')) +
          accordion('firewall', 'Firewall / IDS evasion', 'Fragmentation, decoys and spoofing', firewallBody(o), state.formOpen.has('firewall')) +
          accordion('output', 'Output & misc', 'Verbosity, reasons and traceroute', outputBody(o), state.formOpen.has('output')) +
        '</fieldset>' +

        '<section class="form-section card extra-card">' +
          '<div class="section-head"><div><h2>Extra arguments</h2><p class="section-note">Full nmap power — appended verbatim after the generated flags.</p></div></div>' +
          '<input id="extraArgs" class="input mono-input" type="text" data-opt="extraArgs" autocomplete="off" spellcheck="false" placeholder="--min-hostgroup 16 --version-all" value="' + escAttr(o.extraArgs) + '" title="Raw nmap arguments appended verbatim. Quoting is honored.">' +
          '<div class="hint">Appended verbatim, e.g. <code>--min-hostgroup 16 --version-all</code>. Always enabled, even with a preset.</div>' +
        '</section>' +

        '<div class="action-bar">' +
          '<div class="action-preview"><span class="section-label">Effective command</span><code id="previewCommand">' + esc(previewText()) + '</code></div>' +
          '<div class="action-right">' +
            '<span class="action-hint">' + icon('shield') + '<span>Scans run with nmap on the host network</span></span>' +
            '<button class="btn btn-primary btn-lg" id="startScanBtn" type="button" data-action="start-scan">' + icon('radar') + '<span class="btn-label">Start scan</span><kbd>⌘↵</kbd></button>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</section>';
  }

  /* =======================================================================
   * Form behaviour
   * ==================================================================== */

  function updateTargetChip() {
    const chip = $('#targetCount');
    if (!chip) return;
    const n = parseTargets(state.form.targets).length;
    chip.textContent = n === 0 ? 'No targets' : n + ' target' + (n === 1 ? '' : 's');
    chip.classList.toggle('is-empty', n === 0);
    chip.classList.toggle('is-set', n > 0);
  }

  function syncIntensity() {
    const bubble = $('#intensityVal');
    const slider = $('input[type="range"][data-opt="service.intensity"]');
    if (!bubble || !slider) return;
    const v = clamp(state.form.options.service.intensity, 0, 9);
    bubble.textContent = String(v);
    slider.style.setProperty('--fill', (v / 9 * 100) + '%');
  }

  function updateVisibility() {
    const o = state.form.options;
    $$('[data-show-if]').forEach((el) => {
      const expr = el.getAttribute('data-show-if');
      let visible = false;
      if (expr.indexOf('=') !== -1) {
        const parts = expr.split('=');
        visible = String(getPath(o, parts[0])) === parts[1];
      } else {
        visible = !!getPath(o, expr);
      }
      el.classList.toggle('is-hidden', !visible);
    });
  }

  function syncPresetUI() {
    const custom = state.form.profile === 'custom';
    $$('#presetTrack .preset-card').forEach((card) => {
      const selected = card.getAttribute('data-preset') === state.form.profile;
      card.classList.toggle('is-selected', selected);
      card.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
    const fs = $('#advancedFieldset');
    if (fs) fs.disabled = !custom;
    const note = $('#presetNote');
    if (note) note.hidden = custom;
  }

  function previewCustomArgs() {
    const o = state.form.options;
    const a = [];
    const scanFlags = {
      syn: '-sS', connect: '-sT', udp: '-sU', ack: '-sA', window: '-sW',
      maimon: '-sM', fin: '-sF', xmas: '-sX', null: '-sN', sctpInit: '-sY',
      sctpCookie: '-sZ', pingSweep: '-sn', list: '-sL'
    };
    if (scanFlags[o.scanType]) a.push(scanFlags[o.scanType]);
    if (o.ports === 'all') a.push('-p-');
    else if (o.ports === 'fast') a.push('-F');
    else if (o.ports === 'top') a.push('--top-ports', String(o.topPorts || 100));
    else if (o.ports === 'list' && String(o.portList || '').trim()) a.push('-p', String(o.portList).trim());

    const p = o.ping || {};
    if (p.skip) a.push('-Pn');
    if (String(p.synPorts || '').trim()) a.push('-PS' + String(p.synPorts).trim());
    if (String(p.ackPorts || '').trim()) a.push('-PA' + String(p.ackPorts).trim());
    if (String(p.udpPorts || '').trim()) a.push('-PU' + String(p.udpPorts).trim());
    if (p.icmpEcho) a.push('-PE');
    if (p.icmpTimestamp) a.push('-PP');
    if (p.icmpNetmask) a.push('-PM');
    if (p.disableArp) a.push('--disable-arp-ping');
    if (p.dns === 'always') a.push('-R');
    else if (p.dns === 'never') a.push('-n');

    const svc = o.service || {};
    if (svc.version) {
      a.push('-sV');
      if (svc.light) a.push('--version-light');
      else if (svc.all) a.push('--version-all');
      else a.push('--version-intensity', String(svc.intensity == null ? 7 : svc.intensity));
    }
    const os = o.os || {};
    if (os.detect || o.aggressive) {
      a.push('-O');
      if (os.guess) a.push('--osscan-guess');
    }
    if (o.aggressive) a.push('-A');

    const s = o.scripts || {};
    if (s.defaults) a.push('-sC');
    if (String(s.list || '').trim()) a.push('--script', String(s.list).trim());
    if (String(s.args || '').trim()) a.push('--script-args', String(s.args).trim());
    if (s.trace) a.push('--script-trace');

    const t = o.timing || {};
    if (t.template !== '' && t.template != null) a.push('-T' + t.template);
    if (String(t.minRate || '').trim()) a.push('--min-rate', String(t.minRate).trim());
    if (String(t.maxRate || '').trim()) a.push('--max-rate', String(t.maxRate).trim());
    if (String(t.hostTimeout || '').trim()) a.push('--host-timeout', String(t.hostTimeout).trim());
    if (String(t.scanDelay || '').trim()) a.push('--scan-delay', String(t.scanDelay).trim());
    if (String(t.maxRetries || '').trim()) a.push('--max-retries', String(t.maxRetries).trim());

    const fw = o.firewall || {};
    if (fw.fragment) a.push('-f');
    if (String(fw.mtu || '').trim()) a.push('--mtu', String(fw.mtu).trim());
    if (String(fw.decoys || '').trim()) a.push('-D', String(fw.decoys).trim());
    if (String(fw.spoofSource || '').trim()) a.push('-S', String(fw.spoofSource).trim());
    if (String(fw.sourcePort || '').trim()) a.push('-g', String(fw.sourcePort).trim());
    if (String(fw.dataLength || '').trim()) a.push('--data-length', String(fw.dataLength).trim());
    if (String(fw.ttl || '').trim()) a.push('--ttl', String(fw.ttl).trim());
    if (String(fw.spoofMac || '').trim()) a.push('--spoof-mac', String(fw.spoofMac).trim());
    if (fw.badsum) a.push('--badsum');
    if (String(fw.interface || '').trim()) a.push('-e', String(fw.interface).trim());

    const out = o.output || {};
    const v = parseInt(out.verbose, 10) || 0;
    for (let i = 0; i < Math.min(v, 3); i++) a.push('-v');
    if (out.reason) a.push('--reason');
    if (out.openOnly) a.push('--open');
    if (out.packetTrace) a.push('--packet-trace');
    if (out.traceroute) a.push('--traceroute');
    if (out.ipv6) a.push('-6');
    if (String(o.extraArgs || '').trim()) a.push(String(o.extraArgs).trim());
    return a;
  }

  function previewText() {
    const tokens = parseTargets(state.form.targets);
    const target = tokens.length
      ? tokens.slice(0, 2).join(' ') + (tokens.length > 2 ? ' +' + (tokens.length - 2) : '')
      : '<targets>';
    let args;
    if (state.form.profile !== 'custom') {
      args = PRESET_FLAGS[state.form.profile] || '';
    } else {
      args = previewCustomArgs().join(' ');
    }
    return ('nmap ' + args + ' ' + target).replace(/\s+/g, ' ').trim();
  }

  const updatePreview = debounce(function () {
    const el = $('#previewCommand');
    if (el) el.textContent = previewText();
  }, 70);

  function updatePreviewNow() {
    const el = $('#previewCommand');
    if (el) el.textContent = previewText();
  }

  function renderFormView() {
    state.view = 'form';
    state.current = null;
    state.currentId = null;
    state.hosts = [];
    state.logLines = [];
    state.logScanId = null;
    state.openHosts = new Set();
    state.openHostsScan = null;
    state.allPorts = new Set();
    const host = $('#viewHost');
    if (!host) return;
    host.innerHTML = buildFormHTML();
    syncPresetUI();
    updateVisibility();
    updateTargetChip();
    syncIntensity();
    updatePreviewNow();
    renderHistory();
    if (state.backendOk) setConn('online', 'API online');
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  function handleOptChange(el) {
    if (!el || !el.dataset) return;
    if (el.dataset.versionMode) {
      if (!el.checked) return;
      const v = el.value;
      state.form.options.service.light = v === 'light';
      state.form.options.service.all = v === 'all';
      updateVisibility();
      updatePreview();
      return;
    }
    const path = el.dataset.opt;
    if (!path) return;
    let value;
    if (el.type === 'checkbox') {
      value = el.checked;
    } else if (el.type === 'radio') {
      if (!el.checked) return;
      value = el.value;
    } else if (el.type === 'range' || el.dataset.cast === 'number') {
      value = el.value === '' ? '' : Number(el.value);
      if (value !== '' && !isFinite(value)) value = '';
    } else {
      value = el.value;
    }
    setPath(state.form.options, path, value);
    updateVisibility();
    if (path === 'service.intensity') syncIntensity();
    updatePreview();
  }

  function validateTargets() {
    const wrap = $('#targetWrap');
    const area = $('#targets');
    const tokens = parseTargets(state.form.targets);
    if (tokens.length === 0) {
      if (wrap) {
        wrap.classList.remove('invalid');
        void wrap.offsetWidth;
        wrap.classList.add('invalid');
        setTimeout(() => wrap.classList.remove('invalid'), 650);
      }
      if (area) area.focus();
      toast('Enter at least one target — an IP, CIDR range or hostname', 'error');
      return false;
    }
    return true;
  }

  async function startScan() {
    if (state.starting || state.view !== 'form') return;
    if (!validateTargets()) return;
    const btn = $('#startScanBtn');
    const original = btn ? btn.innerHTML : '';
    state.starting = true;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.innerHTML = '<span class="spinner small"></span><span class="btn-label">Queueing…</span>';
    }
    try {
      const payload = {
        targets: state.form.targets.trim(),
        profile: state.form.profile,
        options: state.form.options
      };
      if (state.form.name.trim()) payload.name = state.form.name.trim();
      const data = await api('/api/scan', { method: 'POST', body: payload });
      if (!data || !data.id) throw new ApiError('Server did not return a scan id', 0);
      toast('Scan queued', 'success');
      state.form.targets = '';
      state.form.name = '';
      state.form.options = defaultOptions();
      state.starting = false;
      state.routeKey = null;
      location.hash = '#/scan/' + data.id;
      loadHistory({ silent: true });
    } catch (err) {
      state.starting = false;
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('is-loading');
        btn.innerHTML = original;
      }
      toast(err && err.message ? err.message : 'Could not start scan', 'error');
      if (err && err.status === 0) setBackend(false, err);
    }
  }

  /* =======================================================================
   * Routing
   * ==================================================================== */

  function parseRoute() {
    const raw = String(location.hash || '').replace(/^#\/?/, '');
    const m = /^scan\/([A-Za-z0-9_-]+)/.exec(raw);
    if (m) return { name: 'scan', id: m[1] };
    return { name: 'form' };
  }

  function teardownView() {
    closeWS();
    if (state.elapsedTimer) {
      clearInterval(state.elapsedTimer);
      state.elapsedTimer = null;
    }
    if (state.transitionTimer) {
      clearTimeout(state.transitionTimer);
      state.transitionTimer = null;
    }
    state.logQueue = [];
    if (state.logRaf) {
      cancelAnimationFrame(state.logRaf);
      state.logRaf = null;
    }
    resetAllArmed();
  }

  function closeWS() {
    if (state.wsTimer) {
      clearTimeout(state.wsTimer);
      state.wsTimer = null;
    }
    const ws = state.ws;
    state.ws = null;
    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try { ws.close(); } catch (err) { /* noop */ }
    }
  }

  async function route() {
    const r = parseRoute();
    if (r.name === 'form') {
      if (state.routeKey === 'form' && state.view === 'form') return;
      teardownView();
      state.routeKey = 'form';
      renderFormView();
      closeSidebar();
      return;
    }

    const key = 'scan:' + r.id;
    if (state.routeKey === key && (state.view === 'scan' || state.view === 'results')) return;
    teardownView();
    state.routeKey = key;
    state.currentId = r.id;
    if (state.logScanId !== r.id) {
      state.logLines = [];
      state.logScanId = r.id;
      state.openHosts = new Set();
      state.openHostsScan = null;
      state.allPorts = new Set();
    }
    closeSidebar();
    renderHistory();
    renderLoading();
    try {
      const data = await api('/api/scans/' + encodeURIComponent(r.id));
      if (state.routeKey !== key) return;
      const scan = data && data.scan;
      if (!scan) throw new ApiError('Scan not found', 404);
      state.current = scan;
      setBackend(true);
      if (scan.status === 'queued' || scan.status === 'running') {
        startLive(scan);
      } else {
        renderResultsState(scan);
      }
    } catch (err) {
      if (state.routeKey !== key) return;
      if (err.status === 0) setBackend(false, err);
      renderLoadError(err && err.message ? err.message : 'Could not load this scan');
    }
  }

  function renderLoading() {
    state.view = 'loading';
    const host = $('#viewHost');
    if (!host) return;
    host.innerHTML = '<div class="view"><div class="view-inner"><div class="loading-block"><span class="spinner"></span><p>Loading scan…</p></div></div></div>';
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  function renderLoadError(message) {
    state.view = 'error';
    const host = $('#viewHost');
    if (!host) return;
    host.innerHTML = '<div class="view"><div class="view-inner">' +
      '<div class="card notice notice-error">' +
        '<span class="notice-ico">' + icon('alert') + '</span>' +
        '<div class="notice-copy"><h2>Could not load scan</h2><p>' + esc(message || 'The scan may have been deleted.') + '</p>' +
        '<div class="notice-actions"><button class="btn btn-sm" type="button" data-action="retry-route">' + icon('refresh') + 'Retry</button>' +
        '<button class="btn btn-sm btn-ghost" type="button" data-action="new-scan">' + icon('arrowLeft') + 'Back to new scan</button></div></div>' +
      '</div>' +
    '</div></div>';
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  /* =======================================================================
   * Live scan view
   * ==================================================================== */

  function buildScanHTML(scan) {
    const status = scan.status || 'queued';
    const started = scan.startedAt || scan.queuedAt || scan.createdAt;
    return '<section class="view scan-view">' +
      '<div class="view-inner">' +
        '<div class="scan-topline">' +
          '<a class="back-link" href="#/new" data-action="new-scan">' + icon('arrowLeft') + 'New scan</a>' +
          '<span class="scan-id mono">id ' + esc(scan.id) + '</span>' +
        '</div>' +
        '<header class="scan-head">' +
          '<div class="scan-title-block">' +
            '<div class="scan-status" id="scanStatus">' + statusPill(status) + '</div>' +
            '<h1 class="scan-title">' + esc(scan.name || 'Scan ' + scan.id) + '</h1>' +
            '<div class="scan-targets mono" title="' + escAttr(scan.targets) + '">' + esc(truncate(scan.targets || '—', 180)) + '</div>' +
            '<div class="scan-meta"><span class="meta-chip">' + icon('sliders') + esc(scan.profile || 'custom') + '</span><span class="meta-chip">' + icon('clock') + 'queued ' + esc(timeAgo(scan.createdAt)) + '</span></div>' +
          '</div>' +
          '<div class="scan-timing">' +
            '<span class="section-label">Elapsed</span>' +
            '<span class="elapsed mono" id="scanElapsed">' + esc(formatClock(Date.now() - (parseDate(started) || Date.now()))) + '</span>' +
          '</div>' +
        '</header>' +

        '<div class="card progress-card" id="progressCard">' +
          '<div class="progress-top">' +
            '<div class="progress-percent mono" id="scanPercent">—</div>' +
            '<div class="progress-info">' +
              '<span class="progress-label" id="scanPhase">Queued</span>' +
              '<span class="progress-stats mono" id="scanStats">Waiting for a free worker…</span>' +
            '</div>' +
          '</div>' +
          '<div class="progress-track' + (status === 'queued' ? ' indeterminate' : '') + '" id="scanTrack"><span class="progress-fill" id="scanBar" style="width:0%"></span></div>' +
          '<div class="progress-foot">' +
            '<span class="mono progress-command" id="scanCommandPreview" title="' + escAttr(scan.command || '') + '">' + esc(scan.command || 'Command appears when the scan starts') + '</span>' +
            '<span class="progress-note" id="scanQueueNote"></span>' +
          '</div>' +
        '</div>' +

        '<div class="card terminal-card">' +
          '<div class="terminal-head">' +
            '<div class="term-title">' + icon('terminal') + '<span>Live output</span><span class="term-count" id="termCount">0 lines</span></div>' +
            '<div class="term-actions">' +
              '<label class="switch-inline" title="Follow new output automatically"><input type="checkbox" id="autoScroll"' + (state.autoScroll ? ' checked' : '') + '><span class="checkbox small" aria-hidden="true"></span><span>Auto-scroll</span></label>' +
              '<button class="icon-btn tiny" type="button" data-action="terminal-clear" title="Clear output" aria-label="Clear output">' + icon('trash') + '</button>' +
              '<button class="icon-btn tiny" type="button" data-action="terminal-copy" title="Copy all output" aria-label="Copy all output">' + icon('copy') + '</button>' +
            '</div>' +
          '</div>' +
          '<div class="terminal-body" id="termBody" aria-live="polite"><div class="term-empty" id="termEmpty">Waiting for nmap output…</div></div>' +
          '<div class="terminal-foot"><span class="term-status"><span class="live-dot"></span>websocket</span><span id="termWsState" data-state="connecting">connecting…</span></div>' +
        '</div>' +

        '<div class="scan-actions">' +
          '<button class="btn btn-danger" type="button" id="cancelScanBtn" data-action="cancel-scan">' + icon('stop') + '<span class="btn-label">Cancel scan</span></button>' +
          '<span class="hint">Cancellation is safe — nmap is stopped with SIGINT and partial output is preserved.</span>' +
        '</div>' +
      '</div>' +
    '</section>';
  }

  function startLive(scan) {
    state.view = 'scan';
    state.current = scan;
    state.currentId = scan.id;
    state.progress = { percent: 0, stats: '', known: false };
    state.queuedPosition = null;
    state.wsWasReconnect = false;
    const host = $('#viewHost');
    if (!host) return;
    host.innerHTML = buildScanHTML(scan);
    window.scrollTo({ top: 0, behavior: 'auto' });
    updateScanUI();
    updateTermWsState('connecting');
    startElapsedTimer();
    connectWS(scan.id);
    renderHistory();
  }

  function startElapsedTimer() {
    if (state.elapsedTimer) clearInterval(state.elapsedTimer);
    updateScanElapsed();
    state.elapsedTimer = setInterval(updateScanElapsed, 1000);
  }

  function updateScanElapsed() {
    const el = $('#scanElapsed');
    const scan = state.current;
    if (!el || !scan) return;
    if (['done', 'error', 'cancelled'].indexOf(scan.status) !== -1) {
      let ms = scan.durationMs;
      if (ms == null) {
        const a = parseDate(scan.startedAt);
        const b = parseDate(scan.finishedAt);
        if (a != null && b != null) ms = b - a;
      }
      el.textContent = ms == null ? formatClock(0) : formatClock(ms);
      return;
    }
    const start = parseDate(scan.startedAt) || parseDate(scan.queuedAt) || parseDate(scan.createdAt) || Date.now();
    el.textContent = formatClock(Date.now() - start);
  }

  function phaseFor(scan) {
    if (!scan) return 'Queued';
    if (scan.status === 'queued') return state.queuedPosition ? 'Queued · position ' + state.queuedPosition : 'Queued';
    if (scan.status === 'running') return 'Scanning';
    if (scan.status === 'done') return 'Complete';
    if (scan.status === 'error') return 'Failed';
    if (scan.status === 'cancelled') return 'Cancelled';
    return scan.status;
  }

  function updateProgressUI() {
    if (state.view !== 'scan' || !state.current) return;
    const scan = state.current;
    const pct = clamp(state.progress.percent || 0, 0, 100);
    const known = !!state.progress.known;
    const pctEl = $('#scanPercent');
    const bar = $('#scanBar');
    const track = $('#scanTrack');
    const phase = $('#scanPhase');
    const stats = $('#scanStats');
    const indeterminate = scan.status === 'queued' || (scan.status === 'running' && !known);
    if (phase) phase.textContent = phaseFor(scan);
    if (track) track.classList.toggle('indeterminate', indeterminate);
    if (pctEl) {
      if (scan.status === 'queued') pctEl.textContent = '—';
      else if (scan.status === 'running') pctEl.textContent = known ? Math.round(pct) + '%' : '—';
      else if (scan.status === 'done') pctEl.textContent = '100%';
      else pctEl.textContent = '—';
    }
    if (bar) {
      let width = 0;
      if (scan.status === 'done') width = 100;
      else if (scan.status === 'running' && known) width = Math.max(pct, 2);
      bar.style.width = width + '%';
    }
    if (stats) {
      if (state.progress.stats) stats.textContent = state.progress.stats;
      else if (scan.status === 'queued') stats.textContent = 'Waiting for a free worker…';
      else if (scan.status === 'running') stats.textContent = 'Scan in progress — waiting for stats…';
      else if (scan.status === 'done') stats.textContent = 'Scan complete.';
      else if (scan.status === 'error') stats.textContent = scan.error || 'Scan failed.';
      else if (scan.status === 'cancelled') stats.textContent = 'Scan cancelled.';
    }
    const note = $('#scanQueueNote');
    if (note) {
      note.textContent = scan.status === 'queued' && state.queuedPosition ? 'position ' + state.queuedPosition + ' in queue' : '';
    }
  }

  function updateScanUI() {
    const scan = state.current;
    if (!scan || state.view !== 'scan') return;
    const statusHost = $('#scanStatus');
    if (statusHost) statusHost.innerHTML = statusPill(scan.status, state.queuedPosition);
    const cmd = $('#scanCommandPreview');
    if (cmd) {
      cmd.textContent = scan.command || 'Command appears when the scan starts';
      cmd.title = scan.command || '';
    }
    const cancel = $('#cancelScanBtn');
    if (cancel) cancel.hidden = !(scan.status === 'queued' || scan.status === 'running');
    updateProgressUI();
    updateScanElapsed();
  }

  function updateTermWsState(kind, text) {
    const el = $('#termWsState');
    if (!el) return;
    const labels = {
      connecting: 'connecting…',
      live: 'live',
      reconnecting: 'reconnecting…',
      closed: 'closed',
      error: 'connection error'
    };
    el.dataset.state = kind;
    el.textContent = text || labels[kind] || kind;
  }

  function makeTermLine(line) {
    const el = document.createElement('div');
    el.className = 'term-line ' + classifyLine(line);
    el.textContent = String(line);
    return el;
  }

  function updateTermCount() {
    const count = $('#termCount');
    if (count) count.textContent = state.logLines.length + (state.logLines.length === 1 ? ' line' : ' lines');
  }

  function flushLogQueue() {
    state.logRaf = null;
    const body = $('#termBody');
    if (!body) {
      state.logQueue = [];
      return;
    }
    if (!state.logQueue.length) return;
    const empty = $('#termEmpty');
    if (empty) empty.remove();
    const frag = document.createDocumentFragment();
    state.logQueue.forEach((line) => frag.appendChild(makeTermLine(line)));
    state.logQueue = [];
    body.appendChild(frag);
    while (body.childElementCount > MAX_LOG_LINES) {
      if (body.firstElementChild) body.removeChild(body.firstElementChild);
    }
    updateTermCount();
    if (state.autoScroll) body.scrollTop = body.scrollHeight;
  }

  function appendLogLine(line) {
    if (line == null) return;
    const text = String(line);
    state.logLines.push(text);
    if (state.logLines.length > MAX_LOG_LINES) state.logLines.splice(0, state.logLines.length - MAX_LOG_LINES);
    state.logQueue.push(text);
    if (state.logQueue.length > MAX_LOG_LINES) state.logQueue = state.logQueue.slice(-MAX_LOG_LINES);
    if (!state.logRaf) state.logRaf = requestAnimationFrame(flushLogQueue);
  }

  function appendServerLine(text) {
    appendLogLine('[server] ' + text);
  }

  function clearTerminal() {
    state.logLines = [];
    state.logQueue = [];
    if (state.logRaf) {
      cancelAnimationFrame(state.logRaf);
      state.logRaf = null;
    }
    const body = $('#termBody');
    if (body) body.innerHTML = '<div class="term-empty" id="termEmpty">Output cleared.</div>';
    updateTermCount();
    toast('Output cleared', 'info', 1800);
  }

  async function cancelScan() {
    const scan = state.current;
    if (!scan || (scan.status !== 'queued' && scan.status !== 'running')) return;
    const btn = $('#cancelScanBtn');
    if (btn) {
      btn.disabled = true;
      const label = btn.querySelector('.btn-label');
      if (label) label.textContent = 'Cancelling…';
    }
    try {
      await api('/api/scans/' + encodeURIComponent(scan.id) + '/cancel', { method: 'POST' });
      toast('Cancellation requested', 'info');
    } catch (err) {
      toast(err.message || 'Could not cancel scan', 'error');
      if (btn) {
        btn.disabled = false;
        const label = btn.querySelector('.btn-label');
        if (label) label.textContent = 'Cancel scan';
      }
    }
  }

  /* =======================================================================
   * WebSocket
   * ==================================================================== */

  function wsUrl(id) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    let url = proto + '://' + location.host + '/ws/scan/' + encodeURIComponent(id);
    if (state.token) url += '?token=' + encodeURIComponent(state.token);
    return url;
  }

  function connectWS(id) {
    closeWS();
    let ws;
    try {
      ws = new WebSocket(wsUrl(id));
    } catch (err) {
      scheduleReconnect(id);
      return;
    }
    state.ws = ws;
    updateTermWsState('connecting');
    setConn('connecting', 'Connecting…');

    ws.onopen = function () {
      if (state.ws !== ws || state.currentId !== id) return;
      state.wsAttempt = 0;
      setBackend(true);
      setConn('live', 'Live connection');
      updateTermWsState('live');
      if (state.wsWasReconnect) {
        state.wsWasReconnect = false;
        appendServerLine('reconnected — earlier live output is not replayed');
      }
    };

    ws.onmessage = function (event) {
      if (state.currentId !== id) return;
      let data;
      try { data = JSON.parse(event.data); } catch (err) { return; }
      handleWsEvent(data, id);
    };

    ws.onerror = function () {
      updateTermWsState('error');
    };

    ws.onclose = function () {
      if (state.ws === ws) state.ws = null;
      if (state.currentId !== id || state.routeKey !== 'scan:' + id) return;
      const scan = state.current;
      if (!scan || scan.status === 'done' || scan.status === 'error' || scan.status === 'cancelled') {
        updateTermWsState('closed');
        if (state.backendOk) setConn('online', 'API online');
        return;
      }
      state.wsWasReconnect = true;
      setConn('reconnecting', 'Reconnecting…');
      updateTermWsState('reconnecting');
      scheduleReconnect(id);
    };
  }

  function scheduleReconnect(id) {
    if (state.wsTimer) clearTimeout(state.wsTimer);
    const delay = Math.min(15000, 800 * Math.pow(2, state.wsAttempt));
    state.wsAttempt += 1;
    state.wsTimer = setTimeout(async function () {
      state.wsTimer = null;
      if (state.currentId !== id) return;
      if (state.ws) return;
      try {
        const data = await api('/api/scans/' + encodeURIComponent(id));
        if (state.currentId !== id) return;
        const scan = data && data.scan;
        if (!scan) return;
        setBackend(true);
        if (scan.status === 'done' || scan.status === 'error' || scan.status === 'cancelled') {
          state.current = scan;
          state.progress.percent = scan.status === 'done' ? 100 : state.progress.percent;
          if (scan.status === 'done') state.progress.known = true;
          renderResultsState(scan);
          loadHistory({ silent: true });
          return;
        }
        state.current = Object.assign({}, state.current, scan);
        updateScanUI();
      } catch (err) {
        if (err.status === 401) {
          updateTermWsState('error', 'unauthorized');
          return;
        }
        if (err.status === 0) setBackend(false, err);
      }
      if (state.currentId === id && state.current && ['done', 'error', 'cancelled'].indexOf(state.current.status) === -1) {
        connectWS(id);
      }
    }, delay);
  }

  function handleWsEvent(ev, id) {
    if (!ev || state.currentId !== id) return;
    const scan = state.current;
    if (!scan) return;
    const prevStatus = scan.status;

    if (ev.type === 'queued') {
      scan.status = 'queued';
      state.queuedPosition = ev.position || null;
      updateScanUI();
      appendServerLine('queued' + (ev.position ? ' · position ' + ev.position : ''));
    } else if (ev.type === 'started') {
      scan.status = 'running';
      scan.startedAt = ev.startedAt || scan.startedAt || new Date().toISOString();
      if (ev.command) scan.command = ev.command;
      state.queuedPosition = null;
      updateScanUI();
      startElapsedTimer();
      appendServerLine('$ ' + (scan.command || 'nmap started'));
    } else if (ev.type === 'log') {
      appendLogLine(ev.line);
      if (/^Stats:|About\s+[\d.]+\s*%\s+done/i.test(String(ev.line || ''))) {
        state.progress.stats = String(ev.line);
        updateProgressUI();
      }
    } else if (ev.type === 'progress') {
      state.progress.percent = Number(ev.percent) || 0;
      state.progress.stats = ev.stats || state.progress.stats;
      state.progress.known = true;
      updateProgressUI();
    } else if (ev.type === 'done') {
      scan.status = 'done';
      scan.result = ev.result || null;
      scan.summary = ev.summary || (ev.result && ev.result.summary) || null;
      scan.exitCode = ev.exitCode == null ? scan.exitCode : ev.exitCode;
      scan.durationMs = ev.durationMs == null ? scan.durationMs : ev.durationMs;
      scan.finishedAt = ev.finishedAt || new Date().toISOString();
      state.progress.percent = 100;
      state.progress.known = true;
      state.progress.stats = 'Scan complete.';
      updateScanUI();
      updateTermWsState('closed');
      closeWS();
      setConn('online', 'API online');
      appendServerLine('scan complete');
      toast('Scan complete', 'success');
      loadHistory({ silent: true });
      if (state.transitionTimer) clearTimeout(state.transitionTimer);
      state.transitionTimer = setTimeout(function () {
        if (state.currentId === id) renderResultsState(scan);
      }, 320);
    } else if (ev.type === 'error') {
      scan.status = 'error';
      scan.error = ev.message || 'Scan failed';
      if (ev.stderrTail != null) scan.stderrTail = ev.stderrTail;
      stderrLines(ev.stderrTail).slice(-12).forEach((line) => appendLogLine(line));
      updateScanUI();
      updateTermWsState('closed');
      closeWS();
      setConn('online', 'API online');
      appendServerLine('error: ' + scan.error);
      toast(scan.error, 'error');
      loadHistory({ silent: true });
      if (state.transitionTimer) clearTimeout(state.transitionTimer);
      state.transitionTimer = setTimeout(function () {
        if (state.currentId === id) renderResultsState(scan);
      }, 320);
    } else if (ev.type === 'cancelled') {
      scan.status = 'cancelled';
      scan.exitCode = ev.exitCode == null ? scan.exitCode : ev.exitCode;
      scan.finishedAt = scan.finishedAt || new Date().toISOString();
      updateScanUI();
      updateTermWsState('closed');
      closeWS();
      setConn('online', 'API online');
      appendServerLine('scan cancelled');
      toast('Scan cancelled', 'info');
      loadHistory({ silent: true });
      if (state.transitionTimer) clearTimeout(state.transitionTimer);
      state.transitionTimer = setTimeout(function () {
        if (state.currentId === id) renderResultsState(scan);
      }, 320);
    }

    if (scan.status !== prevStatus) renderHistory();
  }

  /* =======================================================================
   * Results
   * ==================================================================== */

  function sortedHosts(scan) {
    const hosts = scan && scan.result && Array.isArray(scan.result.hosts) ? scan.result.hosts.slice() : [];
    return hosts.sort(function (a, b) {
      const sa = a.state === 'up' ? 0 : 1;
      const sb = b.state === 'up' ? 0 : 1;
      if (sa !== sb) return sa - sb;
      const pa = (a.ports && a.ports.length) || 0;
      const pb = (b.ports && b.ports.length) || 0;
      if (pa !== pb) return pb - pa;
      return String(a.address || '').localeCompare(String(b.address || ''));
    });
  }

  function summaryOf(scan) {
    if (scan && scan.summary) return scan.summary;
    if (scan && scan.result && scan.result.summary) return scan.result.summary;
    const result = scan && scan.result;
    if (!result) return {};
    const hosts = Array.isArray(result.hosts) ? result.hosts : [];
    let open = 0, closed = 0, filtered = 0;
    const services = {};
    hosts.forEach((h) => {
      (h.ports || []).forEach((p) => {
        if (p.state === 'open') open++;
        else if (p.state === 'closed') closed++;
        else if (p.state === 'filtered') filtered++;
        if (p.state === 'open' && p.service && p.service.name) {
          services[p.service.name] = (services[p.service.name] || 0) + 1;
        }
      });
    });
    return {
      hostsUp: hosts.filter((h) => h.state === 'up').length,
      hostsDown: hosts.filter((h) => h.state === 'down').length,
      openPorts: open,
      closedPorts: closed,
      filteredPorts: filtered,
      services,
      elapsed: result.runStats && result.runStats.finished ? result.runStats.finished.elapsed : '',
      exit: result.runStats && result.runStats.finished ? result.runStats.finished.exit : '',
      errormsg: result.runStats && result.runStats.finished ? result.runStats.finished.errormsg : ''
    };
  }

  function hostKey(host, index) {
    return (host && host.address ? host.address : 'host-' + index) + '#' + index;
  }

  function buildSummaryCards(scan) {
    const s = summaryOf(scan);
    const result = scan.result || {};
    const runHosts = (result.runStats && result.runStats.hosts) || {};
    const up = Number(s.hostsUp) || 0;
    const down = Number(s.hostsDown) || 0;
    const total = Number(runHosts.total) || (Array.isArray(result.hosts) ? result.hosts.length : 0) || (up + down);
    const open = Number(s.openPorts) || 0;
    const filtered = Number(s.filteredPorts) || 0;
    const duration = scan.durationMs != null ? formatDurationMs(scan.durationMs) : (s.elapsed ? s.elapsed + 's' : '—');
    const cards = [
      { key: 'up', label: 'Hosts up', value: up, sub: total + ' total', icon: 'server', tone: 'green' },
      { key: 'down', label: 'Hosts down', value: down, sub: total ? Math.round((up / total) * 100) + '% alive' : '—', icon: 'hostdown', tone: 'dim' },
      { key: 'total', label: 'Total hosts', value: total, sub: 'in scope', icon: 'target', tone: 'plain' },
      { key: 'open', label: 'Open ports', value: open, sub: 'responded open', icon: 'plug', tone: 'green' },
      { key: 'filtered', label: 'Filtered', value: filtered, sub: 'no response', icon: 'shield', tone: 'amber' },
      { key: 'duration', label: 'Duration', value: duration, sub: s.exit ? 'exit: ' + s.exit : 'wall clock', icon: 'clock', tone: 'plain' }
    ];
    return '<div class="stat-grid">' + cards.map(function (c) {
      return '<div class="card stat-card tone-' + c.tone + '">' +
        '<div class="stat-top"><span class="section-label">' + esc(c.label) + '</span><span class="stat-ico">' + icon(c.icon === 'hostdown' ? 'server' : c.icon) + '</span></div>' +
        '<div class="stat-value mono">' + esc(c.value) + '</div>' +
        '<div class="stat-sub">' + esc(c.sub) + '</div>' +
        '</div>';
    }).join('') + '</div>' +
      servicesRow(s);
  }

  function servicesRow(summary) {
    const services = summary && summary.services && typeof summary.services === 'object' ? summary.services : {};
    const entries = Object.keys(services)
      .map((name) => [name, Number(services[name]) || 0])
      .filter((e) => e[1] > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
    if (!entries.length) {
      return '<div class="services-row"><span class="section-label">Services</span><span class="hint">No open services detected.</span></div>';
    }
    return '<div class="services-row"><span class="section-label">Services</span><div class="service-chips">' +
      entries.map((e) => '<span class="chip service-chip" title="' + escAttr(e[1] + ' open ' + e[0] + ' port' + (e[1] === 1 ? '' : 's')) + '"><span class="service-name">' + esc(e[0]) + '</span><span class="service-count">×' + e[1] + '</span></span>').join('') +
      '</div></div>';
  }

  function commandCard(scan) {
    // Actions must render even when there is no command (e.g. a scan that was
    // cancelled while queued) — otherwise the scan can never be deleted.
    return '<section class="card command-card">' +
      '<div class="command-head">' +
        '<span class="section-label">Command</span>' +
        '<div class="command-actions">' +
          '<button class="btn btn-sm" type="button" data-action="copy-command" title="Copy command">' + icon('copy') + 'Copy</button>' +
          '<button class="btn btn-sm" type="button" data-action="download" data-kind="xml" title="Download nmap XML output">' + icon('download') + 'XML</button>' +
          '<button class="btn btn-sm" type="button" data-action="download" data-kind="txt" title="Download normal text output">' + icon('download') + 'TXT</button>' +
          '<button class="btn btn-sm btn-danger-ghost" type="button" data-action="delete-scan" title="Delete this scan">' + icon('trash') + '<span class="btn-label">Delete</span></button>' +
        '</div>' +
      '</div>' +
      (scan.command ? '<code class="command-line mono" id="commandLine">' + esc(scan.command) + '</code>' : '') +
      '<div class="command-foot"><span>' + icon('shield') + 'Runs on the host network</span><span class="mono dim">' + esc(scan.exitCode == null ? '' : 'exit ' + scan.exitCode) + '</span></div>' +
    '</section>';
  }

  function scriptBlock(script) {
    if (!script) return '';
    const text = script.text || script.output || '';
    const preview = firstLine(script.output || text);
    return '<details class="script-block">' +
      '<summary><code class="script-id">' + esc(script.id || 'script') + '</code>' +
      '<span class="script-preview">' + esc(truncate(preview, 110)) + '</span>' +
      '<span class="script-chev">' + icon('chevron') + '</span></summary>' +
      '<pre class="script-output">' + esc(text) + '</pre>' +
      '</details>';
  }

  function portDetailHtml(port) {
    if (!port) return '';
    const svc = port.service || {};
    const facts = [
      ['Product', svc.product],
      ['Version', svc.version],
      ['Extra info', svc.extrainfo],
      ['OS type', svc.ostype],
      ['Method', svc.method],
      ['Confidence', svc.conf ? svc.conf + '/10' : ''],
      ['Owner', port.owner]
    ].filter((f) => f[1]);
    const cpes = Array.isArray(svc.cpe) ? svc.cpe.filter(Boolean) : [];
    const scripts = (port.scripts || []).filter((s) => s && (s.id || s.text || s.output));
    const ttl = port.reason_ttl ? ' ttl ' + port.reason_ttl : '';
    return '<div class="port-detail-inner">' +
      '<div class="detail-top">' +
        '<span class="detail-port mono">' + esc(port.protocol || 'tcp') + '/' + esc(port.portid || '?') + '</span>' +
        stateChip(port.state) +
        '<span class="detail-reason mono">' + esc((port.reason || 'no reason') + ttl) + '</span>' +
      '</div>' +
      (facts.length
        ? '<div class="detail-grid">' + facts.map((f) => '<div class="detail-fact"><span class="detail-key">' + esc(f[0]) + '</span><span class="detail-val">' + esc(f[1]) + '</span></div>').join('') + '</div>'
        : '<p class="hint">No version detection data for this port — try <code>-sV</code>.</p>') +
      (cpes.length ? '<div class="cpe-row"><span class="section-label">CPE</span><div class="cpe-list">' + cpes.map((c) => '<code class="cpe">' + esc(c) + '</code>').join('') + '</div></div>' : '') +
      (scripts.length ? '<div class="scripts"><div class="section-label">Script output</div>' + scripts.map(scriptBlock).join('') + '</div>' : '') +
    '</div>';
  }

  function portsSection(host, index) {
    const ports = Array.isArray(host.ports) ? host.ports : [];
    const open = ports.filter((p) => p.state === 'open').length;
    const filtered = ports.filter((p) => p.state === 'filtered' || p.state === 'open|filtered').length;
    if (!ports.length) {
      return '<div class="host-block"><div class="host-subhead"><span class="section-label">Ports & services</span></div>' +
        '<div class="empty-inline">' + icon('plug') + '<div><strong>No ports in this result</strong><p>This may be a discovery-only scan (<code>-sn</code>) or the host did not respond.</p></div></div></div>';
    }
    const key = hostKey(host, index);
    const all = state.allPorts.has(key);
    const limit = all ? ports.length : PORT_RENDER_LIMIT;
    const shown = ports.slice(0, limit);
    const rows = shown.map(function (p, i) {
      const svc = p.service || {};
      const cpes = Array.isArray(svc.cpe) ? svc.cpe.join(', ') : '';
      const version = [svc.product, svc.version, svc.extrainfo].filter(Boolean).join(' ');
      const reason = (p.reason || '') + (p.reason_ttl ? ' ttl ' + p.reason_ttl : '');
      return '<tr class="port-row" data-action="port-toggle" data-host-index="' + index + '" data-port-index="' + i + '" tabindex="0" role="button" aria-expanded="false" title="Expand service detail for ' + escAttr((p.protocol || 'tcp') + '/' + (p.portid || '?')) + '">' +
        '<td class="port-cell"><span class="row-caret">' + icon('chevron') + '</span><span class="mono port-id">' + esc(p.portid || '?') + '</span></td>' +
        '<td class="mono proto-cell">' + esc(p.protocol || '') + '</td>' +
        '<td>' + stateChip(p.state) + '</td>' +
        '<td class="svc-cell"><span class="mono svc-name">' + esc(svc.name || 'unknown') + '</span></td>' +
        '<td class="version-cell"><span class="mono svc-version" title="' + escAttr(cpes || version || '') + '">' + esc(version || (cpes ? 'cpe available' : '—')) + '</span></td>' +
        '<td class="reason-cell mono">' + esc(reason || '—') + '</td>' +
        '</tr>';
    }).join('');
    return '<div class="host-block">' +
      '<div class="host-subhead"><span class="section-label">Ports & services</span><span class="subhead-meta">' + open + ' open · ' + filtered + ' filtered · ' + ports.length + ' scanned</span></div>' +
      (open === 0 ? '<div class="empty-inline compact">' + icon('eye') + '<div><strong>No open ports on this host</strong><p>Try <code>-p-</code>, a different scan type, or <code>-Pn</code>.</p></div></div>' : '') +
      '<div class="table-wrap"><table class="ports-table"><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Reason</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
      (!all && ports.length > limit
        ? '<div class="table-foot"><span>Showing ' + limit + ' of ' + ports.length + ' ports</span><button class="btn btn-sm" type="button" data-action="show-all-ports" data-index="' + index + '">Show all ports</button></div>'
        : '') +
      '</div>';
  }

  function osSection(host) {
    const os = host.os;
    if (!os || !Array.isArray(os.matches) || !os.matches.length) return '';
    const matches = os.matches;
    const top = matches[0] || {};
    const acc = clamp(parseInt(top.accuracy, 10) || 0, 0, 100);
    const classes = Array.isArray(top.classes) ? top.classes : [];
    const chips = [];
    classes.forEach((c) => {
      const parts = [c.vendor, c.osfamily, c.osgen, c.type].filter(Boolean);
      parts.forEach((p) => { if (chips.indexOf(p) === -1) chips.push(p); });
    });
    const used = Array.isArray(os.portsUsed) ? os.portsUsed : [];
    const rest = matches.slice(1);
    return '<div class="host-block">' +
      '<div class="host-subhead"><span class="section-label">OS detection</span><span class="subhead-meta">' + matches.length + ' match' + (matches.length === 1 ? '' : 'es') + '</span></div>' +
      '<div class="os-card">' +
        '<div class="os-top">' +
          '<div class="os-name-wrap"><span class="os-name">' + esc(top.name || 'Unknown OS') + '</span>' +
            (used.length ? '<span class="os-used mono">using ' + used.map((u) => esc((u.proto || '') + '/' + (u.portid || '') + ' ' + (u.state || ''))).join(', ') + '</span>' : '') +
          '</div>' +
          '<span class="os-acc mono">' + acc + '%</span>' +
        '</div>' +
        '<div class="accuracy-track" title="Accuracy ' + acc + '%"><span style="width:' + acc + '%"></span></div>' +
        (chips.length ? '<div class="os-classes">' + chips.map((c) => '<span class="chip os-chip">' + esc(c) + '</span>').join('') + '</div>' : '') +
        (rest.length ? '<details class="os-more"><summary>' + rest.length + ' more match' + (rest.length === 1 ? '' : 'es') + '<span class="script-chev">' + icon('chevron') + '</span></summary><div class="os-more-list">' +
          rest.map((m) => '<div class="os-more-row"><span>' + esc(m.name || 'Unknown') + '</span><span class="mono dim">' + esc(m.accuracy || '?') + '%</span></div>').join('') +
          '</div></details>' : '') +
      '</div>' +
    '</div>';
  }

  function tracerouteSection(host) {
    const traces = Array.isArray(host.traceroute) ? host.traceroute : [];
    if (!traces.length) return '';
    return '<div class="host-block">' +
      '<div class="host-subhead"><span class="section-label">Traceroute</span></div>' +
      traces.map(function (trace) {
        const hops = Array.isArray(trace.hops) ? trace.hops : [];
        const label = [trace.protocol || 'tcp', trace.port].filter(Boolean).join('/');
        return '<div class="trace-block">' +
          (label ? '<div class="trace-label mono">' + esc(label) + '</div>' : '') +
          (hops.length ? '<div class="table-wrap"><table class="trace-table"><thead><tr><th>TTL</th><th>Address</th><th>RTT</th><th>Host</th></tr></thead><tbody>' +
            hops.map((h) => '<tr><td class="mono">' + esc(h.ttl || '') + '</td><td class="mono">' + esc(h.ipaddr || '') + '</td><td class="mono">' + esc(h.rtt ? h.rtt + 's' : '—') + '</td><td class="mono dim">' + esc(h.host || '') + '</td></tr>').join('') +
            '</tbody></table></div>' : '<p class="hint">No hops recorded.</p>') +
        '</div>';
      }).join('') +
    '</div>';
  }

  function hostScriptsSection(host) {
    const scripts = Array.isArray(host.hostScripts) ? host.hostScripts.filter((s) => s && (s.id || s.text || s.output)) : [];
    if (!scripts.length) return '';
    return '<div class="host-block"><div class="host-subhead"><span class="section-label">Host scripts</span><span class="subhead-meta">' + scripts.length + '</span></div>' +
      '<div class="scripts">' + scripts.map(scriptBlock).join('') + '</div></div>';
  }

  function hostFacts(host) {
    const facts = [];
    if (host.status && host.status.reason) {
      facts.push(['Status', (host.status.state || host.state || 'unknown') + ' · ' + host.status.reason + (host.status.reason_ttl ? ' ttl ' + host.status.reason_ttl : '')]);
    }
    if (host.uptime && host.uptime.seconds) {
      facts.push(['Uptime', formatUptime(host.uptime.seconds)]);
    }
    if (host.uptime && host.uptime.lastboot) {
      facts.push(['Last boot', host.uptime.lastboot]);
    }
    if (host.distance && host.distance.value) {
      facts.push(['Distance', host.distance.value + ' hop' + (host.distance.value === '1' ? '' : 's')]);
    }
    if (!facts.length) return '';
    return '<div class="host-facts">' + facts.map((f) => '<span class="fact"><span class="fact-k">' + esc(f[0]) + '</span><span class="fact-v mono">' + esc(f[1]) + '</span></span>').join('') + '</div>';
  }

  function buildHostBody(host, index) {
    return '<div class="host-inner">' +
      hostFacts(host) +
      portsSection(host, index) +
      osSection(host) +
      tracerouteSection(host) +
      hostScriptsSection(host) +
      '</div>';
  }

  function hostHeader(host, index) {
    const openCount = (host.ports || []).filter((p) => p.state === 'open').length;
    const totalPorts = (host.ports || []).length;
    const names = Array.isArray(host.hostnames) ? host.hostnames.filter(Boolean) : [];
    const mac = host.mac ? '<span class="chip chip-mac mono" title="' + escAttr(host.mac + (host.vendor ? ' · ' + host.vendor : '')) + '">' + esc(host.mac) + (host.vendor ? '<em>' + esc(host.vendor) + '</em>' : '') + '</span>' : '';
    const osName = host.os && Array.isArray(host.os.matches) && host.os.matches[0] ? host.os.matches[0].name : '';
    const osBadge = osName ? '<span class="chip chip-os" title="' + escAttr(osName) + '">' + icon('target') + esc(truncate(osName, 30)) + '</span>' : '';
    const portBadge = '<span class="chip chip-count" title="' + totalPorts + ' scanned · ' + openCount + ' open">' + icon('plug') + openCount + ' open</span>';
    return '<button type="button" class="host-head" data-action="host-toggle" data-index="' + index + '" aria-expanded="false">' +
      '<span class="host-chev">' + icon('chevron') + '</span>' +
      '<span class="host-primary">' +
        '<span class="host-address mono">' + esc(host.address || 'unknown') + '</span>' +
        stateChip(host.state || 'unknown') +
        (names.length ? '<span class="host-names">' + esc(names.join(', ')) + '</span>' : '') +
      '</span>' +
      '<span class="host-meta">' + mac + osBadge + portBadge + '</span>' +
      '</button>';
  }

  function hostsSection(scan) {
    if (!state.hosts.length) {
      return '<section class="hosts-section"><div class="card empty-card">' +
        emptyState('radar', 'No hosts up', 'The scan found no responsive hosts. Try <code>-Pn</code> to skip discovery, a broader target range, or a slower timing template.') +
        '</div></section>';
    }
    const list = state.hosts.map(function (host, index) {
      const key = hostKey(host, index);
      const open = state.openHosts.has(key);
      const body = open ? buildHostBody(host, index) : '';
      return '<article class="card host-card' + (open ? ' open' : '') + '" data-host-key="' + escAttr(key) + '">' +
        hostHeader(host, index) +
        '<div class="host-body-wrap"><div class="host-body" data-built="' + (open ? '1' : '0') + '">' + body + '</div></div>' +
        '</article>';
    }).join('');
    const up = state.hosts.filter((h) => h.state === 'up').length;
    const down = state.hosts.filter((h) => h.state === 'down').length;
    return '<section class="hosts-section">' +
      '<div class="section-head hosts-head"><h2>Hosts</h2><span class="section-note">' + up + ' up · ' + down + ' down · ' + state.hosts.length + ' total</span></div>' +
      '<div class="host-list">' + list + '</div>' +
      '</section>';
  }

  function emptyState(iconName, title, text) {
    return '<div class="empty-state"><span class="empty-ico">' + icon(iconName) + '</span><h3>' + esc(title) + '</h3><p>' + text + '</p></div>';
  }

  function rawLogPanel() {
    if (!state.logLines.length) return '';
    return '<details class="raw-panel card">' +
      '<summary><span class="raw-title">' + icon('terminal') + 'Raw output</span><span class="raw-meta">' + state.logLines.length + (state.logLines.length === 1 ? ' line' : ' lines') + '</span><span class="raw-chev">' + icon('chevron') + '</span></summary>' +
      '<div class="raw-body">' +
        '<div class="raw-toolbar"><button class="btn btn-sm" type="button" data-action="terminal-copy">' + icon('copy') + 'Copy all</button></div>' +
        '<div class="terminal-body result-term">' + state.logLines.map((l) => '<div class="term-line ' + classifyLine(l) + '">' + esc(l) + '</div>').join('') + '</div>' +
      '</div>' +
    '</details>';
  }

  function noticeCard(kind, title, message, iconName) {
    return '<div class="card notice notice-' + kind + '">' +
      '<span class="notice-ico">' + icon(iconName || 'alert') + '</span>' +
      '<div class="notice-copy"><h2>' + esc(title) + '</h2><p>' + message + '</p></div>' +
    '</div>';
  }

  function buildResultsHTML(scan) {
    const result = scan.result;
    const status = scan.status;
    const summary = summaryOf(scan);
    const title = scan.name || 'Scan ' + scan.id;
    let html = '<section class="view results-view"><div class="view-inner">';
    html += '<div class="scan-topline"><a class="back-link" href="#/new" data-action="new-scan">' + icon('arrowLeft') + 'New scan</a><span class="scan-id mono">id ' + esc(scan.id) + '</span></div>';
    html += '<header class="results-head">' +
      '<div class="results-title-block">' +
        '<div class="eyebrow"><span class="eyebrow-dot"></span>Scan detail</div>' +
        '<div class="results-title-row"><h1>' + esc(title) + '</h1><span class="scan-status">' + statusPill(status) + '</span></div>' +
        '<div class="results-meta mono">' +
          '<span title="' + escAttr(scan.targets || '') + '">' + esc(truncate(scan.targets || '—', 120)) + '</span>' +
          '<span class="meta-sep">·</span><span>' + esc(scan.profile || 'custom') + '</span>' +
          '<span class="meta-sep">·</span><span data-ago="' + escAttr(scan.createdAt || '') + '" title="' + escAttr(absTime(scan.createdAt)) + '">' + esc(timeAgo(scan.createdAt)) + '</span>' +
          (scan.durationMs != null ? '<span class="meta-sep">·</span><span>' + esc(formatDurationMs(scan.durationMs)) + '</span>' : '') +
        '</div>' +
      '</div>' +
      '<div class="results-actions"><a class="btn" href="#/new" data-action="new-scan">' + icon('plus') + 'New scan</a></div>' +
    '</header>';

    if (status === 'error') {
      const tail = stderrLines(scan.stderrTail);
      html += noticeCard('error', 'Scan failed',
        esc(scan.error || 'nmap exited with an error.') +
        (tail.length ? '<pre class="script-output stderr-tail">' + esc(tail.join('\n')) + '</pre>' : ''), 'alert');
    } else if (status === 'cancelled') {
      html += noticeCard('info', 'Scan cancelled', 'The scan was stopped before it completed. Partial output, if any, is preserved in the raw log and output files.', 'stop');
    }

    if (result && Array.isArray(result.hosts)) {
      html += buildSummaryCards(scan);
      html += commandCard(scan);
      html += hostsSection(scan);
    } else if (status === 'done') {
      html += '<div class="card empty-card">' + emptyState('radar', 'No parsed results', 'The scan finished but did not produce host data. Check the raw output below.') + '</div>';
      html += commandCard(scan);
    } else {
      html += commandCard(scan);
    }

    if (result && result.runStats && result.runStats.finished && result.runStats.finished.summary) {
      html += '<div class="run-summary mono dim">' + esc(result.runStats.finished.summary) + '</div>';
    }

    // nmap can finish with exit "error" while still parsing (e.g. raw socket
    // warnings) — surface it prominently per the frontend contract.
    if (status === 'done' && (summary.exit === 'error' || summary.errormsg)) {
      html += noticeCard('error', 'Scan finished with errors',
        esc(summary.errormsg || 'nmap reported an error while scanning.'), 'alert');
    }

    html += rawLogPanel();
    html += '</div></section>';
    return html;
  }

  function renderResultsState(scan) {
    if (!scan) return;
    if (state.currentId && state.currentId !== scan.id) return;
    teardownView();
    state.view = 'results';
    state.current = scan;
    state.currentId = scan.id;
    state.logScanId = scan.id;
    state.hosts = sortedHosts(scan);
    if (state.openHostsScan !== scan.id) {
      state.openHosts = new Set();
      state.openHostsScan = scan.id;
      state.allPorts = new Set();
      if (state.hosts.length) {
        let pick = 0;
        for (let i = 0; i < state.hosts.length; i++) {
          if (state.hosts[i].state === 'up' && state.hosts[i].ports && state.hosts[i].ports.length) { pick = i; break; }
        }
        state.openHosts.add(hostKey(state.hosts[pick], pick));
      }
    }
    const host = $('#viewHost');
    if (!host) return;
    host.innerHTML = buildResultsHTML(scan);
    if (state.backendOk && (!state.ws || state.ws.readyState !== 1)) setConn('online', 'API online');
    renderHistory();
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  /* =======================================================================
   * Result interactions
   * ==================================================================== */

  function toggleHost(btn) {
    const card = btn.closest('.host-card');
    if (!card) return;
    const index = parseInt(btn.getAttribute('data-index'), 10);
    const host = state.hosts[index];
    if (!host) return;
    const key = hostKey(host, index);
    const body = card.querySelector('.host-body');
    const open = !card.classList.contains('open');
    card.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      state.openHosts.add(key);
      if (body && body.getAttribute('data-built') !== '1') {
        body.innerHTML = buildHostBody(host, index);
        body.setAttribute('data-built', '1');
      }
    } else {
      state.openHosts.delete(key);
    }
  }

  function togglePortRow(row) {
    if (!row) return;
    const next = row.nextElementSibling;
    if (next && next.classList.contains('port-detail')) {
      next.parentNode.removeChild(next);
      row.classList.remove('open');
      row.setAttribute('aria-expanded', 'false');
      return;
    }
    const hi = parseInt(row.getAttribute('data-host-index'), 10);
    const pi = parseInt(row.getAttribute('data-port-index'), 10);
    const host = state.hosts[hi];
    const port = host && host.ports ? host.ports[pi] : null;
    if (!port) return;
    const tr = document.createElement('tr');
    tr.className = 'port-detail';
    tr.innerHTML = '<td colspan="6">' + portDetailHtml(port) + '</td>';
    if (row.parentNode) row.parentNode.insertBefore(tr, row.nextSibling);
    row.classList.add('open');
    row.setAttribute('aria-expanded', 'true');
  }

  function showAllPorts(btn) {
    const index = parseInt(btn.getAttribute('data-index'), 10);
    const host = state.hosts[index];
    if (!host) return;
    const key = hostKey(host, index);
    state.allPorts.add(key);
    const card = btn.closest('.host-card');
    const body = card ? card.querySelector('.host-body') : null;
    if (body) {
      body.innerHTML = buildHostBody(host, index);
      body.setAttribute('data-built', '1');
    }
  }

  async function downloadOutput(id, kind) {
    const tokenQuery = state.token ? '?token=' + encodeURIComponent(state.token) : '';
    const headers = {};
    if (state.token) headers['X-Auth-Token'] = state.token;
    try {
      const res = await fetch('/api/scans/' + encodeURIComponent(id) + '/output.' + kind + tokenQuery, { headers: headers, cache: 'no-store' });
      if (!res.ok) {
        let message = 'Output file is not available';
        try { const text = await res.text(); if (text) message = truncate(text, 160); } catch (err) { /* noop */ }
        throw new Error(message);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = id + '.' + kind;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      toast('Downloaded ' + kind.toUpperCase() + ' output', 'success');
    } catch (err) {
      toast(err.message || 'Download failed', 'error');
    }
  }

  async function deleteCurrentScan() {
    const scan = state.current;
    if (!scan) return;
    try {
      const data = await api('/api/scans/' + encodeURIComponent(scan.id), { method: 'DELETE' });
      if (data && data.status === 'cancelling') {
        toast('Cancellation requested', 'info');
        loadHistory({ silent: true });
        return;
      }
      toast('Scan deleted', 'success');
      state.routeKey = null;
      state.current = null;
      state.currentId = null;
      state.logLines = [];
      state.logScanId = null;
      state.openHosts = new Set();
      state.openHostsScan = null;
      state.allPorts = new Set();
      if (location.hash === '#/new') route();
      else location.hash = '#/new';
      loadHistory({ silent: true });
    } catch (err) {
      toast(err.message || 'Could not delete scan', 'error');
    }
  }

  /* =======================================================================
   * Sidebar, dialogs & confirmations
   * ==================================================================== */

  function openSidebar() {
    document.body.classList.add('sidebar-open');
    const scrim = $('#scrim');
    if (scrim) scrim.hidden = false;
  }

  function closeSidebar() {
    document.body.classList.remove('sidebar-open');
    const scrim = $('#scrim');
    if (scrim) scrim.hidden = true;
  }

  function armConfirm(btn, armedText, onConfirm) {
    if (!btn) return;
    if (btn.dataset.armed === '1') {
      resetArmed(btn);
      onConfirm();
      return;
    }
    const label = btn.querySelector('.btn-label');
    if (label) {
      btn.dataset.origLabel = label.textContent;
      label.textContent = armedText;
    }
    btn.dataset.armed = '1';
    btn.classList.add('armed');
    const timer = setTimeout(() => resetArmed(btn), 4500);
    state.armed.set(btn, timer);
  }

  function resetArmed(btn) {
    if (!btn) return;
    const timer = state.armed.get(btn);
    if (timer) clearTimeout(timer);
    state.armed.delete(btn);
    delete btn.dataset.armed;
    btn.classList.remove('armed');
    const label = btn.querySelector('.btn-label');
    if (label && btn.dataset.origLabel != null) {
      label.textContent = btn.dataset.origLabel;
      delete btn.dataset.origLabel;
    }
  }

  function resetAllArmed() {
    Array.from(state.armed.keys()).forEach((btn) => resetArmed(btn));
  }

  function openTokenDialog() {
    const dialog = $('#tokenDialog');
    const input = $('#tokenInput');
    if (input) input.value = state.token;
    if (dialog && typeof dialog.showModal === 'function') {
      dialog.showModal();
      setTimeout(() => { if (input) input.focus(); }, 30);
    }
  }

  function saveToken(token) {
    state.token = String(token || '').trim();
    try {
      if (state.token) localStorage.setItem('nmapToken', state.token);
      else localStorage.removeItem('nmapToken');
    } catch (err) { /* localStorage may be unavailable */ }
    state.historyKey = '';
    state.routeKey = null;
    toast(state.token ? 'Access token saved' : 'Access token cleared', 'success');
    loadHealth();
    loadPresets();
    loadHistory();
    route();
  }

  function navigateNew() {
    closeSidebar();
    if (location.hash === '#/new') {
      if (state.routeKey !== 'form') {
        state.routeKey = null;
        route();
      } else {
        const area = $('#targets');
        if (area) area.focus();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } else {
      location.hash = '#/new';
    }
  }

  function openScan(id) {
    closeSidebar();
    const key = 'scan:' + id;
    if (location.hash === '#/scan/' + id) {
      // Same hash: nothing to do if we're already showing (or loading) this
      // scan — but re-route from the error state so a click retries the fetch.
      if (state.routeKey === key && (state.view === 'scan' || state.view === 'results')) return;
      if (state.routeKey === key && state.view === 'loading') return;
      state.routeKey = null;
      route();
      return;
    }
    location.hash = '#/scan/' + id;
  }

  /* =======================================================================
   * Global event wiring
   * ==================================================================== */

  function handleFormEvent(event) {
    const el = event.target;
    if (!el) return;
    if (el.id === 'historyFilter') {
      state.historyFilter = el.value;
      renderHistory();
      return;
    }
    if (el.id === 'targets') {
      state.form.targets = el.value;
      const wrap = $('#targetWrap');
      if (wrap) wrap.classList.remove('invalid');
      updateTargetChip();
      updatePreview();
      return;
    }
    if (el.id === 'scanName') {
      state.form.name = el.value;
      return;
    }
    if (el.id === 'autoScroll') {
      state.autoScroll = !!el.checked;
      return;
    }
    if (el.dataset && (el.dataset.opt || el.dataset.versionMode)) {
      handleOptChange(el);
    }
  }

  function wire() {
    document.addEventListener('input', handleFormEvent);
    document.addEventListener('change', handleFormEvent);

    document.addEventListener('click', function (event) {
      const el = event.target.closest('[data-action]');
      if (!el) return;
      const action = el.getAttribute('data-action');
      switch (action) {
        case 'new-scan':
          event.preventDefault();
          navigateNew();
          break;
        case 'open-scan':
          event.preventDefault();
          openScan(el.getAttribute('data-id'));
          break;
        case 'toggle-sidebar':
          openSidebar();
          break;
        case 'close-sidebar':
          closeSidebar();
          break;
        case 'retry':
          setBackend(true);
          setConn('connecting', 'Connecting…');
          loadHealth();
          loadPresets();
          loadHistory();
          route();
          break;
        case 'retry-route':
          state.routeKey = null;
          route();
          break;
        case 'select-preset':
          state.form.profile = el.getAttribute('data-preset') || 'custom';
          syncPresetUI();
          updatePreview();
          break;
        case 'accordion': {
          const section = el.closest('.acc');
          if (!section) break;
          const id = el.getAttribute('data-acc-id');
          const open = !section.classList.contains('open');
          section.classList.toggle('open', open);
          el.setAttribute('aria-expanded', open ? 'true' : 'false');
          if (open) state.formOpen.add(id);
          else state.formOpen.delete(id);
          break;
        }
        case 'start-scan':
          startScan();
          break;
        case 'cancel-scan':
          armConfirm(el, 'Confirm cancel', cancelScan);
          break;
        case 'terminal-clear':
          clearTerminal();
          break;
        case 'terminal-copy':
          copyText(state.logLines.join('\n'), 'Output copied to clipboard');
          break;
        case 'copy-command': {
          const command = state.current && state.current.command ? state.current.command : ($('#commandLine') ? $('#commandLine').textContent : '');
          copyText(command, 'Command copied to clipboard');
          break;
        }
        case 'download':
          if (state.current) downloadOutput(state.current.id, el.getAttribute('data-kind') || 'xml');
          break;
        case 'delete-scan':
          armConfirm(el, 'Confirm delete', deleteCurrentScan);
          break;
        case 'host-toggle':
          toggleHost(el);
          break;
        case 'port-toggle':
          togglePortRow(el);
          break;
        case 'show-all-ports':
          showAllPorts(el);
          break;
        case 'token':
          openTokenDialog();
          break;
        case 'token-clear':
          saveToken('');
          {
            const dialog = $('#tokenDialog');
            if (dialog && dialog.open) dialog.close();
          }
          break;
        default:
          break;
      }
    });

    document.addEventListener('keydown', function (event) {
      const key = event.key;
      if (key === 'Enter' && (event.metaKey || event.ctrlKey)) {
        if (state.view === 'form') {
          event.preventDefault();
          startScan();
        }
        return;
      }
      if (key === '/' && !event.metaKey && !event.ctrlKey && !event.altKey) {
        const t = event.target;
        const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
        if (!typing) {
          const filter = $('#historyFilter');
          if (filter) {
            event.preventDefault();
            filter.focus();
            filter.select();
          }
        }
        return;
      }
      if (key === 'Escape') {
        resetAllArmed();
        closeSidebar();
        return;
      }
      if ((key === 'Enter' || key === ' ') && event.target && event.target.classList && event.target.classList.contains('port-row')) {
        event.preventDefault();
        togglePortRow(event.target);
      }
    });

    document.addEventListener('submit', function (event) {
      if (event.target && event.target.id === 'tokenForm') {
        event.preventDefault();
        const input = $('#tokenInput');
        saveToken(input ? input.value : '');
        const dialog = $('#tokenDialog');
        if (dialog && dialog.open) dialog.close();
      }
    });

    window.addEventListener('hashchange', function () {
      route();
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth > 900) closeSidebar();
    });
  }

  /* =======================================================================
   * Boot
   * ==================================================================== */

  function boot() {
    if (state.booted) return;
    state.booted = true;
    try {
      state.token = localStorage.getItem('nmapToken') || '';
    } catch (err) {
      state.token = '';
    }
    const tokenForm = $('#tokenForm');
    if (tokenForm) tokenForm.setAttribute('autocomplete', 'off');
    wire();
    route();
    loadHealth();
    loadPresets();
    loadHistory();
    setInterval(function () {
      if (state.view === 'form' || state.view === 'results' || (state.current && (state.current.status === 'queued' || state.current.status === 'running'))) {
        loadHistory({ silent: true });
      }
      refreshAgo();
    }, 10000);
    setInterval(refreshAgo, 30000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
