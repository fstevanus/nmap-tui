import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function freePort() {
  return 20000 + Math.floor(Math.random() * 20000);
}

async function startServer(extraEnv = {}) {
  const dataDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-http-'));
  const port = freePort();
  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      NMAP_UI_DATA_DIR: dataDir,
      NMAP_UI_PORT: String(port),
      NMAP_UI_HOST: '127.0.0.1',
      ...extraEnv
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let out = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { out += c; });

  const base = `http://127.0.0.1:${port}`;
  const t0 = Date.now();
  // wait for listen
  for (;;) {
    if (child.exitCode !== null) throw new Error(`server exited early:\n${out}`);
    if (Date.now() - t0 > 15000) throw new Error('server did not start in time');
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) break;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { child, base, dataDir, getLogs: () => out };
}

async function stopServer(server) {
  server.child.kill('SIGTERM');
  await new Promise((resolve) => server.child.on('exit', resolve));
}

test('server serves UI, health, presets and validates input', async () => {
  const server = await startServer();
  try {
    // static UI
    const page = await fetch(`${server.base}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    assert.match(await page.text(), /NMAP/);

    for (const asset of ['/app.js', '/style.css']) {
      const r = await fetch(`${server.base}${asset}`);
      assert.equal(r.status, 200, asset);
    }

    // API
    const health = await (await fetch(`${server.base}/api/health`)).json();
    assert.equal(health.ok, true);
    const presets = await (await fetch(`${server.base}/api/presets`)).json();
    assert.ok(presets.presets.length >= 10);

    // unknown API path → JSON 404 (not the SPA fallback)
    const nf = await fetch(`${server.base}/api/nope`);
    assert.equal(nf.status, 404);

    // validation
    const bad = await fetch(`${server.base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ targets: '' })
    });
    assert.equal(bad.status, 400);

    // path traversal must never leak server source
    const trav = await fetch(`${server.base}/../lib/args.js`);
    const body = await trav.text();
    assert.ok(!body.includes('buildArgs'), 'server source must not be served');
  } finally {
    await stopServer(server);
  }
});

test('a scan request keeps the server alive even when nmap cannot spawn (regression: process crash)', async () => {
  // Force a spawn failure regardless of whether nmap exists on this machine.
  const server = await startServer({ PATH: '/nonexistent-dir' });
  try {
    const res = await fetch(`${server.base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ targets: '127.0.0.1', profile: 'quick' })
    });
    assert.equal(res.status, 201);
    const { id } = await res.json();

    // The old code exited the whole process here (~1s after the spawn
    // failure, via an unhandled rejection). The server must stay up and the
    // record must end as a clean error.
    const t0 = Date.now();
    let scan;
    for (;;) {
      assert.ok(Date.now() - t0 < 15000, 'scan never reached a terminal state');
      assert.equal(server.child.exitCode, null, 'SERVER CRASHED — regression!');
      const r = await fetch(`${server.base}/api/scans/${id}`);
      assert.equal(r.status, 200);
      scan = await r.json();
      if (['done', 'error', 'cancelled'].includes(scan.scan.status)) break;
      await new Promise((r2) => setTimeout(r2, 200));
    }
    assert.equal(scan.scan.status, 'error');
    assert.match(scan.scan.error, /Failed to launch nmap/);

    // still healthy afterwards, and no stray temp files in the data dir
    const health = await fetch(`${server.base}/api/health`);
    assert.equal(health.status, 200);
    const files = await fsp.readdir(server.dataDir);
    assert.deepEqual(files.filter((f) => f.endsWith('.tmp')), []);

    // delete works on the failed record
    const del = await fetch(`${server.base}/api/scans/${id}`, { method: 'DELETE' });
    assert.equal(del.status, 200);
    assert.equal((await fetch(`${server.base}/api/scans/${id}`)).status, 404);
  } finally {
    await stopServer(server);
  }
});

test('token auth gates API and WebSocket paths when configured', async () => {
  const server = await startServer({ NMAP_UI_TOKEN: 'sekret' });
  try {
    // static UI is reachable without a token
    assert.equal((await fetch(`${server.base}/`)).status, 200);
    // API is not
    assert.equal((await fetch(`${server.base}/api/health`)).status, 401);
    // with the header it is
    const ok = await fetch(`${server.base}/api/health`, { headers: { 'x-auth-token': 'sekret' } });
    assert.equal(ok.status, 200);
    // wrong token rejected
    const no = await fetch(`${server.base}/api/health`, { headers: { 'x-auth-token': 'wrong' } });
    assert.equal(no.status, 401);
    // ws endpoint without token is refused at upgrade
    const ws = await fetch(`${server.base}/ws/scan/abc`, { headers: { connection: 'Upgrade', upgrade: 'websocket' } });
    assert.equal(ws.status, 401);
  } finally {
    await stopServer(server);
  }
});
