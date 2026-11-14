// nmap-web server: static UI + REST API + WebSocket live scan events.
// Runs nmap as a child process. Designed to run in a container with host
// networking so scans see the host's network.

import http from 'node:http';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { WebSocketServer } from 'ws';
import { PRESETS, parseTargets } from './lib/args.js';
import { ScanManager } from './lib/scanner.js';
import { Store } from './lib/store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- Config ----------
const HOST = process.env.NMAP_UI_HOST || '127.0.0.1';
const PORT = parseInt(process.env.NMAP_UI_PORT || '8787', 10);
const DATA_DIR = process.env.NMAP_UI_DATA_DIR || path.join(__dirname, 'data');
const TOKEN = process.env.NMAP_UI_TOKEN || '';
const CONCURRENCY = parseInt(process.env.NMAP_UI_CONCURRENCY || '2', 10);
const HISTORY_LIMIT = parseInt(process.env.NMAP_UI_HISTORY || '200', 10);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 2 * 1024 * 1024;

const store = new Store(DATA_DIR, { historyLimit: HISTORY_LIMIT });
const scanner = new ScanManager({ store, concurrency: CONCURRENCY });

// ---------- Process-level safety nets ----------
// An unhandled rejection / uncaught exception would otherwise terminate the
// whole process, killing every connected client and all in-flight scans.
// Log loudly and keep serving; a dead server helps nobody.
process.on('unhandledRejection', (reason) => {
  console.error('[nmap-web] FATAL(unhandledRejection) — server kept alive:',
    reason instanceof Error ? (reason.stack || reason.message) : reason);
});
process.on('uncaughtException', (err) => {
  console.error('[nmap-web] FATAL(uncaughtException) — server kept alive:',
    err instanceof Error ? (err.stack || err.message) : err);
});

// ---------- Helpers ----------
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function sendText(res, code, text, type = 'text/plain; charset=utf-8') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(text);
}

function sendFile(res, filePath, type) {
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  fsp.readFile(filePath).then((buf) => res.end(buf)).catch(() => {
    res.destroy();
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('Request body too large.'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'text/xml; charset=utf-8',
  '.woff2': 'font/woff2',
  '.map': 'application/json'
};

async function serveStatic(req, res, urlPath) {
  if (urlPath === '/' || urlPath === '') urlPath = '/index.html';
  const clean = path.normalize(urlPath).replace(/^([/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, clean);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep) && filePath !== PUBLIC_DIR) {
    return sendText(res, 403, 'Forbidden');
  }
  try {
    const st = await fsp.stat(filePath);
    if (st.isDirectory()) return sendText(res, 403, 'Forbidden');
    return sendFile(res, filePath, MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream');
  } catch {
    // SPA fallback: unknown paths serve the app shell.
    if (urlPath.startsWith('/api/')) return sendJson(res, 404, { error: 'Not found' });
    try {
      return sendFile(res, path.join(PUBLIC_DIR, 'index.html'), MIME['.html']);
    } catch {
      return sendText(res, 404, 'Not found');
    }
  }
}

// ---------- Record views ----------
// stderrTail is stored as an array in new records but older records on disk
// may hold a joined string — normalize so every consumer sees an array.
function stderrTailOf(r) {
  const v = r && r.stderrTail;
  if (Array.isArray(v)) return v;
  if (typeof v === 'string' && v.trim()) return v.split('\n');
  return null;
}

function recordMeta(r) {
  return {
    id: r.id,
    name: r.name || null,
    targets: r.targets,
    profile: r.profile,
    command: r.command || null,
    status: r.status,
    exitCode: r.exitCode ?? null,
    error: r.error || null,
    stderrTail: stderrTailOf(r),
    createdAt: r.createdAt,
    queuedAt: r.queuedAt || null,
    startedAt: r.startedAt || null,
    finishedAt: r.finishedAt || null,
    durationMs: r.durationMs || null,
    summary: r.summary || null
  };
}

async function findRecord(id) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return null;
  return store.get(id);
}

// ---------- HTTP server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Optional token gate (skip for static assets).
  if (TOKEN && !url.pathname.startsWith('/api/') && !url.pathname.startsWith('/ws/')) {
    // static allowed
  } else if (TOKEN) {
    const provided = req.headers['x-auth-token'] || url.searchParams.get('token') || '';
    if (!safeEqual(provided, TOKEN)) return sendJson(res, 401, { error: 'Unauthorized: invalid token' });
  }

  try {
    // --- REST API ---
    if (url.pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, nmapVersion: nmapVersion });
    }

    if (url.pathname === '/api/presets') {
      return sendJson(res, 200, { presets: PRESETS });
    }

    if (url.pathname === '/api/scan' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      if (typeof body.targets !== 'string' || !body.targets.trim()) {
        return sendJson(res, 400, { error: 'Targets are required.' });
      }
      let targets;
      try {
        targets = parseTargets(body.targets);
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
      if (targets.length === 0) {
        return sendJson(res, 400, { error: 'Targets are required.' });
      }
      const id = crypto.randomBytes(6).toString('hex');
      const record = {
        id,
        name: typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 200) : null,
        targets: body.targets.trim(),
        profile: typeof body.profile === 'string' ? body.profile : 'custom',
        options: body.options && typeof body.options === 'object' ? body.options : {},
        status: 'queued',
        createdAt: new Date().toISOString(),
        error: null,
        result: null,
        summary: null
      };
      await store.save(record);
      scanner.enqueue(record);
      return sendJson(res, 201, { id, status: 'queued' });
    }

    const scansMatch = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)$/);
    if (url.pathname === '/api/scans' && req.method === 'GET') {
      const list = await store.list();
      return sendJson(res, 200, { scans: list.map(recordMeta) });
    }

    if (scansMatch && req.method === 'GET') {
      const rec = await findRecord(scansMatch[1]);
      if (!rec) return sendJson(res, 404, { error: 'Scan not found' });
      return sendJson(res, 200, { scan: { ...recordMeta(rec), options: rec.options, result: rec.result } });
    }

    if (scansMatch && req.method === 'DELETE') {
      const rec = await findRecord(scansMatch[1]);
      if (!rec) return sendJson(res, 404, { error: 'Scan not found' });
      if (scanner.isActive(rec.id)) {
        await scanner.cancel(rec.id);
        return sendJson(res, 200, { id: rec.id, status: 'cancelling' });
      }
      await store.delete(rec.id);
      return sendJson(res, 200, { id: rec.id, status: 'deleted' });
    }

    const cancelMatch = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)\/cancel$/);
    if (cancelMatch && req.method === 'POST') {
      const rec = await findRecord(cancelMatch[1]);
      if (!rec) return sendJson(res, 404, { error: 'Scan not found' });
      if (!scanner.isActive(rec.id)) return sendJson(res, 409, { error: 'Scan is not active' });
      await scanner.cancel(rec.id);
      return sendJson(res, 200, { id: rec.id, status: 'cancelling' });
    }

    const outMatch = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)\/output\.(xml|txt)$/);
    if (outMatch && (req.method === 'GET' || req.method === 'HEAD')) {
      const rec = await findRecord(outMatch[1]);
      if (!rec) return sendJson(res, 404, { error: 'Scan not found' });
      const p = outMatch[2] === 'xml' ? store.xmlPath(rec.id) : store.normalPath(rec.id);
      try {
        const buf = await fsp.readFile(p);
        const type = outMatch[2] === 'xml' ? 'text/xml; charset=utf-8' : 'text/plain; charset=utf-8';
        res.writeHead(200, {
          'Content-Type': type,
          'Content-Disposition': `attachment; filename="${rec.id}.${outMatch[2]}"`,
          'Content-Length': buf.length
        });
        return res.end(buf);
      } catch {
        return sendText(res, 404, 'Output file not available yet.');
      }
    }

    if (url.pathname.startsWith('/api/')) return sendJson(res, 404, { error: 'Not found' });

    // --- Static UI ---
    return serveStatic(req, res, url.pathname);
  } catch (err) {
    if (res.headersSent) return res.destroy();
    return sendJson(res, 400, { error: err.message || 'Bad request' });
  }
});

// ---------- WebSocket ----------
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const m = url.pathname.match(/^\/ws\/scan\/([A-Za-z0-9_-]+)$/);
  if (!m) {
    socket.destroy();
    return;
  }
  if (TOKEN) {
    const provided = url.searchParams.get('token') || '';
    if (!safeEqual(provided, TOKEN)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.scanId = m[1];
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', async (ws) => {
  const id = ws.scanId;

  const onEvent = (event) => {
    if (ws.readyState === 1) ws.send(JSON.stringify(event));
  };
  const onGlobal = (sid, event) => {
    if (sid === id) onEvent(event);
  };

  // Subscribe first so no live event is missed, then snapshot the
  // current state (prefer the in-memory live record).
  scanner.on('event', onGlobal);

  const rec = scanner.getLive(id) || (await findRecord(id));
  if (!rec) {
    onEvent({ type: 'error', message: 'Scan not found' });
    ws.close();
    return;
  }

  if (rec.status === 'queued') onEvent({ type: 'queued', position: scanner.queue.indexOf(id) + 1 });
  else if (rec.status === 'running') onEvent({ type: 'started', command: rec.command, startedAt: rec.startedAt });
  else if (rec.status === 'done') onEvent({ type: 'done', result: rec.result, summary: rec.summary, exitCode: rec.exitCode, durationMs: rec.durationMs, finishedAt: rec.finishedAt });
  else if (rec.status === 'cancelled') onEvent({ type: 'cancelled', exitCode: rec.exitCode });
  else if (rec.status === 'error') onEvent({ type: 'error', message: rec.error, stderrTail: stderrTailOf(rec) });

  ws.on('close', () => {
    scanner.off('event', onGlobal);
  });
});

// ---------- Startup ----------
let nmapVersion = null;
function detectNmap() {
  return new Promise((resolve) => {
    execFile('nmap', ['--version'], { timeout: 10000 }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(stdout.split('\n')[0].trim() || 'nmap');
    });
  });
}

// Restore queued/running records after a restart -> mark them as error.
async function recoverInterrupted() {
  const all = await store.list();
  for (const r of all) {
    if (r.status === 'running' || r.status === 'queued') {
      r.status = 'error';
      r.error = 'Interrupted by server restart.';
      r.finishedAt = r.finishedAt || new Date().toISOString();
      await store.save(r);
    }
  }
}

await fsp.mkdir(DATA_DIR, { recursive: true });
await recoverInterrupted();
nmapVersion = await detectNmap();
if (!nmapVersion) {
  console.error('[nmap-web] WARNING: `nmap` binary not found on PATH. Scans will fail until nmap is installed.');
}

server.listen(PORT, HOST, () => {
  console.log(`[nmap-web] listening on http://${HOST}:${PORT}`);
  console.log(`[nmap-web] nmap: ${nmapVersion || 'NOT FOUND'}`);
  console.log(`[nmap-web] data dir: ${DATA_DIR}`);
  console.log(`[nmap-web] concurrency: ${CONCURRENCY}`);
  if (TOKEN) console.log('[nmap-web] auth token: enabled');
  else console.log(`[nmap-web] WARNING: no auth token set. Only reachable from ${HOST} — keep it on localhost if exposed to untrusted networks.`);
});
