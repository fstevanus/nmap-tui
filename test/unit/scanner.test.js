import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ScanManager } from '../../lib/scanner.js';
import { Store } from '../../lib/store.js';

const FAKE_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.93-fake" args="fake">
<host><status state="up" reason="mock"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports><extraports state="closed" count="99"><extrareasons reason="reset" count="99"/></extraports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="mockd" version="1.0" method="probed" conf="10"/></port>
</ports></host>
<runstats><finished time="1" elapsed="0.5" exit="success" summary="Nmap done"/>
<hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`;

/** Write a fake nmap binary: prints a stats line to stderr, XML to stdout. */
async function makeFakeNmap(dir) {
  const p = path.join(dir, 'fake-nmap');
  await fsp.writeFile(p, `#!/usr/bin/env node
const xml = ${JSON.stringify(FAKE_XML)};
setTimeout(() => {
  process.stderr.write('SYN Stealth Scan Timing: About 50.00% done; ETC: --:--\\n');
}, 50);
setTimeout(() => {
  process.stdout.write(xml, () => {
    process.exit(0);
  });
}, 200);
`);
  await fsp.chmod(p, 0o755);
  return p;
}

async function tmpManager({ nmapBin = 'nmap' } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-scan-'));
  const store = new Store(dir);
  const scanner = new ScanManager({ store, concurrency: 2, nmapBin });
  return { store, scanner, dir };
}

function collectEvents(scanner, id) {
  const events = [];
  const onEvent = (sid, ev) => { if (sid === id) events.push(ev); };
  scanner.on('event', onEvent);
  return { events, stop: () => scanner.off('event', onEvent) };
}

function waitFor(predicate, ms = 10000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() - t0 > ms) return reject(new Error('timeout waiting for condition'));
      setTimeout(tick, 20);
    };
    tick();
  });
}

test('successful scan via fake nmap: parses XML, streams progress, emits done', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-fake-'));
  const nmapBin = await makeFakeNmap(dir);
  const { store, scanner } = await tmpManager({ nmapBin });
  const record = { id: 'ok1', targets: '127.0.0.1', profile: 'regular', options: {}, status: 'queued', createdAt: new Date().toISOString() };
  await store.save(record);
  const { events } = collectEvents(scanner, 'ok1');
  scanner.enqueue(record);

  await waitFor(() => record.status === 'done');
  assert.equal(record.result.summary.openPorts, 1);
  assert.equal(record.result.summary.closedPorts, 99); // extraports counted
  assert.ok(record.command.includes('nmap'));
  assert.ok(record.command.includes('127.0.0.1'));
  assert.ok(events.some((e) => e.type === 'started'));
  assert.ok(events.some((e) => e.type === 'progress' && e.percent === 50));
  assert.ok(events.some((e) => e.type === 'done'));
  // persisted record matches
  const saved = await store.get('ok1');
  assert.equal(saved.status, 'done');
  assert.equal(saved.summary.openPorts, 1);
});

test('missing nmap binary: exactly one error finalize, server-side state stays consistent (regression: process crash)', async () => {
  const { store, scanner } = await tmpManager({ nmapBin: '/nonexistent/nmap-binary' });
  const record = { id: 'bad1', targets: '127.0.0.1', profile: 'quick', options: {}, status: 'queued', createdAt: new Date().toISOString() };
  await store.save(record);
  const { events } = collectEvents(scanner, 'bad1');
  scanner.enqueue(record);

  await waitFor(() => record.status === 'error');
  // spawn failure: clear, actionable message — not "could not be parsed"
  assert.match(record.error, /Failed to launch nmap/);
  // exactly one error event (old code double-finalized: duplicate events + ENOENT crash)
  const errorEvents = events.filter((e) => e.type === 'error');
  assert.equal(errorEvents.length, 1);
  const saved = await store.get('bad1');
  assert.equal(saved.status, 'error');
  // no bogus empty XML file written
  assert.equal(await fsp.readFile(store.xmlPath('bad1'), 'utf8').catch(() => null), null);
});

test('cancelling a queued scan marks it cancelled without starting it', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-fake-'));
  // A slow fake nmap so the concurrency slot stays occupied long enough.
  const p = path.join(dir, 'slow-nmap');
  await fsp.writeFile(p, `#!/usr/bin/env node
process.on('SIGINT', () => process.exit(130));
setInterval(() => {}, 1000);
`);
  await fsp.chmod(p, 0o755);

  const { store } = await tmpManager({ nmapBin: p });
  const s1 = new ScanManager({ store, concurrency: 1, nmapBin: p });
  const blocker = { id: 'block', targets: '127.0.0.1', profile: 'regular', options: {}, status: 'queued', createdAt: new Date().toISOString() };
  const queued = { id: 'q1', targets: '127.0.0.1', profile: 'regular', options: {}, status: 'queued', createdAt: new Date().toISOString() };
  await store.save(blocker);
  await store.save(queued);

  s1.enqueue(blocker);
  s1.enqueue(queued);
  await waitFor(() => blocker.status === 'running');
  assert.equal(queued.status, 'queued');
  assert.ok(s1.isActive('q1'));

  const cancelled = await s1.cancel('q1');
  assert.equal(cancelled.status, 'cancelled');
  assert.equal((await store.get('q1')).status, 'cancelled');
  assert.ok(!s1.isActive('q1'));

  await s1.cancel('block'); // cleanup: stop the fake nmap
  await waitFor(() => blocker.status === 'cancelled');
});

test('cancelling a running scan (fake nmap) ends it via SIGINT', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-fake-'));
  // A slow fake nmap that traps SIGINT like the real one
  const p = path.join(dir, 'slow-nmap');
  await fsp.writeFile(p, `#!/usr/bin/env node
process.stderr.write('About 10.00% done\\n');
process.on('SIGINT', () => process.exit(130));
setInterval(() => {}, 1000);
`);
  await fsp.chmod(p, 0o755);

  const { store, scanner } = await tmpManager({ nmapBin: p });
  const record = { id: 'slow1', targets: '127.0.0.1', profile: 'regular', options: {}, status: 'queued', createdAt: new Date().toISOString() };
  await store.save(record);
  scanner.enqueue(record);
  await waitFor(() => record.status === 'running');
  await scanner.cancel('slow1');
  await waitFor(() => record.status === 'cancelled');
  assert.equal((await store.get('slow1')).status, 'cancelled');
});
