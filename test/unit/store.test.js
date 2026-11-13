import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../../lib/store.js';

async function tmpStore(opts) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nmapweb-store-'));
  return { store: new Store(dir, opts), dir };
}

test('save/get roundtrip and id validation', async () => {
  const { store } = await tmpStore();
  await store.save({ id: 'abc', status: 'queued', createdAt: '2026-01-01T00:00:00Z' });
  const rec = await store.get('abc');
  assert.equal(rec.status, 'queued');
  // unsafe ids are rejected
  assert.equal(await store.get('../etc/passwd'), null);
  assert.equal(await store.get('a b'), null);
});

test('concurrent saves on the same record never race (regression: ENOENT crash)', async () => {
  const { store, dir } = await tmpStore();
  const record = { id: 'race', createdAt: new Date().toISOString(), n: 0 };
  // The old implementation used a fixed <id>.json.tmp path; parallel saves
  // renamed each other's temp file away and crashed the server with ENOENT.
  await Promise.all(
    Array.from({ length: 100 }, (_, i) => {
      record.n = i;
      return store.save(record);
    })
  );
  const final = await store.get('race');
  assert.equal(final.id, 'race');
  assert.equal(typeof final.n, 'number');
  // no temp files left behind
  const files = await fsp.readdir(dir);
  assert.deepEqual(files.filter((f) => f.endsWith('.tmp')), []);
});

test('list returns records sorted newest-first and ignores junk', async () => {
  const { store, dir } = await tmpStore();
  await store.save({ id: 'old', createdAt: '2026-01-01T00:00:00Z' });
  await store.save({ id: 'new', createdAt: '2026-02-01T00:00:00Z' });
  await fsp.writeFile(path.join(dir, 'corrupt.json'), '{not json');
  const list = await store.list();
  assert.deepEqual(list.map((r) => r.id), ['new', 'old']);
});

test('delete removes record and output files', async () => {
  const { store, dir } = await tmpStore();
  await store.save({ id: 'x', createdAt: '2026-01-01T00:00:00Z' });
  await fsp.writeFile(store.xmlPath('x'), '<x/>');
  await fsp.writeFile(store.normalPath('x'), 'out');
  await store.delete('x');
  assert.equal(await store.get('x'), null);
  for (const f of await fsp.readdir(dir)) assert.ok(!f.startsWith('x.'), `leftover ${f}`);
});

test('trim enforces the history cap but never removes active scans', async () => {
  const { store } = await tmpStore({ historyLimit: 2 });
  const mk = (id, status, t) => ({ id, status, createdAt: new Date(t).toISOString() });
  await store.save(mk('a', 'done', '2026-01-01T00:00:00Z'));
  await store.save(mk('b', 'running', '2026-02-01T00:00:00Z'));
  await store.save(mk('c', 'done', '2026-03-01T00:00:00Z'));
  await store.save(mk('d', 'done', '2026-04-01T00:00:00Z'));
  await store.trim();
  const ids = (await store.list()).map((r) => r.id).sort();
  // newest two (d, c) are within the cap; of the over-cap records the finished
  // one (a) is removed while the running one (b) is never touched
  assert.deepEqual(ids, ['b', 'c', 'd']);
});
