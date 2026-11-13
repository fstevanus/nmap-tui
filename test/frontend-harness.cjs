'use strict';
const fs = require('fs');
const SRC = require('path').join(__dirname, '..', 'public', 'app.js');

// ---- minimal DOM stub ----
const captures = [];
const toastMsgs = [];
function makeEl(sel) {
  let html = '';
  const el = {
    _sel: sel, textContent: '', title: '', hidden: false, value: '', disabled: false,
    dataset: {}, style: { setProperty() {}, width: '' }, children: [],
    firstElementChild: null, scrollTop: 0, scrollHeight: 0, offsetWidth: 0,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; captures.push({ sel, html: String(v) }); },
    setAttribute() {}, getAttribute() { return null; }, removeAttribute() {},
    appendChild(c) { this.children.push(c); }, removeChild() {}, remove() {},
    focus() {}, select() {}, click() {}, addEventListener() {},
    closest() { return null; },
    querySelector(s) { const e = makeEl(sel + ' ' + s); if (s === '.toast-msg') e._rec = toastMsgs; return e; },
    querySelectorAll() { return []; },
    get parentNode() { return null; }
  };
  Object.defineProperty(el, 'textContent', {
    get() { return this._tc || ''; },
    set(v) { this._tc = String(v); if (this._rec) this._rec.push(this._tc); }
  });
  return el;
}
const els = new Map();
const getEl = (sel) => { if (!els.has(sel)) els.set(sel, makeEl(sel)); return els.get(sel); };
let rafId = 0; const rafCbs = new Map();

global.document = {
  readyState: 'loading', // boot() never runs
  addEventListener() {},
  querySelector: (s) => getEl(s),
  querySelectorAll: () => [],
  createElement: (t) => makeEl('created:' + t),
  createDocumentFragment: () => makeEl('frag'),
  body: makeEl('body'),
  execCommand() {}
};
global.window = { addEventListener() {}, scrollTo() {}, innerWidth: 1200 };
global.location = { hash: '#/scan/t1', protocol: 'http:', host: 'localhost:8080' };
global.localStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
Object.defineProperty(global, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true, writable: true });
global.Headers = class { constructor() { this.m = new Map(); } set(k, v) { this.m.set(k, v); } get(k) { return this.m.get(k); } };
global.fetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ scans: [] }) });
global.WebSocket = class { constructor() { this.readyState = 0; } close() {} };
global.requestAnimationFrame = (fn) => { const id = ++rafId; rafCbs.set(id, setTimeout(() => { rafCbs.delete(id); fn(); }, 0)); return id; };
global.cancelAnimationFrame = (id) => { const t = rafCbs.get(id); if (t) clearTimeout(t); rafCbs.delete(id); };

// ---- load app.js with internals exported ----
let src = fs.readFileSync(SRC, 'utf8');
const cut = src.lastIndexOf('\n})();');
if (cut < 0) throw new Error('IIFE end not found');
src = src.slice(0, cut) + `
  globalThis.__T = { state, esc, stderrLines, defaultOptions, buildFormHTML, buildScanHTML, buildResultsHTML,
    portDetailHtml, presetCardsHTML, renderHistory, renderLoadError, renderLoading,
    handleWsEvent, sortedHosts, hostKey, statusPill, stateChip, makeTermLine,
    renderResultsState, teardownView, commandCard };
})();` + src.slice(cut + '\n})();'.length);
eval(src);
const T = globalThis.__T;

// ---- hostile payloads ----
const IMG = '<img src=x onerror=window.__pwn=1>';
const SCR = '"><script>window.__pwn=1</script>';
const ATTR = "x\" onmouseover=\"window.__pwn=1";
let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log('PASS ' + name); } else { failures++; console.log('FAIL ' + name + (detail ? ' :: ' + detail : '')); }
}
function assertClean(name, html) {
  const bad = [/<img src=x onerror/i, /<script>window\.__pwn/i, /onmouseover="window\.__pwn/i];
  const hit = bad.find((re) => re.test(html));
  check(name + ': no unescaped payload', !hit, hit && hit + ' in output');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  // 1. esc unit
  check('esc basics', T.esc('<a "b" \'c\' &>') === '&lt;a &quot;b&quot; &#39;c&#39; &amp;&gt;');

  // 2. results view with hostile scan data
  const hostileHost = {
    address: IMG, type: 'ipv4', mac: ATTR, vendor: SCR,
    hostnames: [IMG, 'ok.example'], state: 'up',
    status: { state: 'up', reason: IMG, reason_ttl: '64' },
    ports: [{
      portid: '80', protocol: 'tcp', state: 'open', reason: IMG, reason_ttl: '64',
      service: { name: 'http', product: IMG, version: SCR, extrainfo: ATTR, ostype: '', method: 'probed', conf: '10', cpe: ['cpe:/a:' + IMG] },
      scripts: [{ id: IMG, output: SCR, text: SCR + '\nline2 ' + ATTR }],
      owner: IMG
    }],
    os: { portsUsed: [{ state: 'open', proto: 'tcp', portid: '80' }],
          matches: [{ name: IMG, accuracy: '98', classes: [{ type: IMG, vendor: SCR, osfamily: 'Linux', osgen: '5.X', accuracy: '98' }] }] },
    traceroute: [{ port: '80', protocol: 'tcp', hops: [{ ttl: '1', ipaddr: '10.0.0.1', rtt: '0.4', host: IMG }] }],
    hostScripts: [{ id: IMG, output: SCR, text: SCR }],
    uptime: { seconds: '123', lastboot: IMG }, distance: { value: '1' }
  };
  const scan = {
    id: 't1', name: IMG, targets: SCR, profile: ATTR, status: 'done',
    command: 'nmap ' + IMG, exitCode: 0, createdAt: new Date().toISOString(),
    durationMs: 1234, stderrTail: 'tail line ' + IMG,
    summary: { hostsUp: 1, hostsDown: 0, openPorts: 1, services: { [IMG]: 1 }, elapsed: '1.0', exit: 'error', errormsg: 'raw sockets: ' + IMG },
    result: {
      hosts: [hostileHost],
      runStats: { finished: { summary: 'Nmap done: ' + IMG, errormsg: 'warn ' + SCR, exit: 'error' }, hosts: { up: '1', down: '0', total: '1' } },
      summary: { hostsUp: 1, exit: 'error', errormsg: 'raw sockets: ' + IMG }
    }
  };
  T.state.currentId = null;
  T.renderResultsState(scan);
  const resHtml = getEl('#viewHost').innerHTML;
  assertClean('results view', resHtml);
  check('results: escaped payload present', resHtml.includes('&lt;img src=x onerror'));
  check('results: error banner for exit=error', resHtml.includes('Scan finished with errors'));
  check('results: banner message escaped', resHtml.includes('raw sockets: &lt;img'));
  check('results: delete action present', resHtml.includes('data-action="delete-scan"'));
  T.state.logLines = ['log ' + IMG, 'log2 ' + SCR];
  const raw = T.buildResultsHTML(scan);
  assertClean('results + raw log', raw);

  // 2b. error-status results view (stderrTail string shape from REST/WS snapshot)
  const errScan = Object.assign({}, scan, {
    status: 'error', error: 'Failed to launch nmap: ' + IMG,
    stderrTail: 'E1 ' + IMG + '\nE2', summary: null, result: null
  });
  T.state.currentId = null;
  T.renderResultsState(errScan);
  const errHtml = getEl('#viewHost').innerHTML;
  assertClean('error results', errHtml);
  check('error view: message escaped', errHtml.includes('Failed to launch nmap: &lt;img'));
  check('error view: stderrTail string rendered escaped', errHtml.includes('E1 &lt;img') && errHtml.includes('E2'));
  check('error view: delete present', errHtml.includes('data-action="delete-scan"'));

  // 3. live scan view
  const liveHtml = T.buildScanHTML({ id: 't2', name: IMG, targets: SCR, profile: ATTR, status: 'queued', command: 'nmap ' + IMG, createdAt: new Date().toISOString() });
  assertClean('scan view', liveHtml);

  // 4. form view
  T.state.form = { name: IMG, targets: SCR + '\n10.0.0.1', profile: 'custom',
    options: T.defaultOptions() };
  T.state.form.options.portList = IMG; T.state.form.options.extraArgs = SCR; T.state.form.options.scripts.list = ATTR;
  assertClean('form view', T.buildFormHTML());

  // 5. history sidebar
  T.state.history = [{ id: 't1', name: IMG, targets: SCR, status: 'done', profile: ATTR, createdAt: new Date().toISOString(), summary: { hostsUp: 1, openPorts: 2 } }];
  T.state.historyFilter = '';
  T.renderHistory();
  assertClean('history', getEl('#historyList').innerHTML);

  // 6. presets
  T.state.presets = [{ id: 'x', label: IMG, desc: SCR }];
  assertClean('presets', T.presetCardsHTML());

  // 7. port detail
  assertClean('port detail', T.portDetailHtml(scan.result.hosts[0].ports[0]));

  // 8. load error
  T.renderLoadError('failed: ' + IMG);
  assertClean('load error', getEl('#viewHost').innerHTML);

  // 9. WS events: log line, error with ARRAY stderrTail, error with STRING stderrTail
  T.state.view = 'scan'; T.state.currentId = 't3'; T.state.routeKey = 'scan:t3';
  T.state.current = { id: 't3', status: 'running', createdAt: new Date().toISOString() };
  T.handleWsEvent({ type: 'log', line: 'line ' + IMG }, 't3');
  await sleep(20);
  check('log line kept as text', T.state.logLines.includes('line ' + IMG));
  const term = getEl('#termBody');
  check('log line not injected as HTML', !/<img src=x onerror/i.test(term.innerHTML || ''));

  T.handleWsEvent({ type: 'error', message: 'boom ' + IMG, stderrTail: ['err1 ' + IMG, 'err2'] }, 't3');
  await sleep(20);
  check('error status set', T.state.current.status === 'error');
  check('array stderrTail appended', T.state.logLines.includes('err1 ' + IMG) && T.state.logLines.includes('err2'));
  T.teardownView();

  T.state.view = 'scan'; T.state.currentId = 't4'; T.state.routeKey = 'scan:t4';
  T.state.current = { id: 't4', status: 'running' };
  T.handleWsEvent({ type: 'error', message: 'snap fail ' + SCR, stderrTail: 'snapline1 ' + IMG + '\nsnapline2' }, 't4');
  await sleep(20);
  check('string stderrTail accepted (WS snapshot shape)',
    T.state.logLines.includes('snapline1 ' + IMG) && T.state.logLines.includes('snapline2'));
  check('scan.stderrTail stored', T.state.current.stderrTail === 'snapline1 ' + IMG + '\nsnapline2');
  T.teardownView();

  // 10. stderrLines helper shapes
  check('stderrLines string', T.stderrLines('a\nb').length === 2);
  check('stderrLines array', T.stderrLines(['a', '', 'b']).join(',') === 'a,b');
  check('stderrLines null', T.stderrLines(null).length === 0);

  console.log(failures ? '\n' + failures + ' FAILURES' : '\nALL PASS');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
