// Simple JSON-file-backed store for scan records (one file per scan).

import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

export class Store {
  constructor(dataDir, { historyLimit = 200 } = {}) {
    this.dataDir = dataDir;
    this.historyLimit = historyLimit;
    this._writeChains = new Map(); // record id -> promise chain (serializes writes per id)
  }

  recordPath(id) {
    return path.join(this.dataDir, `${id}.json`);
  }

  xmlPath(id) {
    return path.join(this.dataDir, `${id}.xml`);
  }

  normalPath(id) {
    return path.join(this.dataDir, `${id}.txt`);
  }

  /**
   * Atomically persist a record. Safe under concurrency: each write goes to
   * a unique temp file and writes for the same record id are serialized, so
   * two overlapping save() calls can never race on the temp file or rename
   * each other's data away. The public API is unchanged.
   */
  async save(record) {
    const prev = this._writeChains.get(record.id) || Promise.resolve();
    // Run after the previous write for this id settles (regardless of outcome).
    const run = prev.catch(() => {}).then(() => this._writeAtomic(record));
    const chained = run.catch(() => {});
    this._writeChains.set(record.id, chained);
    chained.then(() => {
      // Drop the chain entry once this write is the last one queued.
      if (this._writeChains.get(record.id) === chained) this._writeChains.delete(record.id);
    });
    return run; // propagate write failures to the caller
  }

  async _writeAtomic(record) {
    await fsp.mkdir(this.dataDir, { recursive: true });
    // Unique temp file per write: concurrent saves (even for different ids)
    // can never collide on the temp path.
    const tmp = `${this.recordPath(record.id)}.${crypto.randomUUID()}.tmp`;
    try {
      await fsp.writeFile(tmp, JSON.stringify(record), 'utf8');
      await fsp.rename(tmp, this.recordPath(record.id));
    } catch (err) {
      await fsp.rm(tmp, { force: true }).catch(() => {});
      throw err;
    }
  }

  async get(id) {
    // Allow only safe ids.
    if (!/^[A-Za-z0-9_-]+$/.test(id)) return null;
    try {
      const raw = await fsp.readFile(this.recordPath(id), 'utf8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async list() {
    let files = [];
    try {
      files = await fsp.readdir(this.dataDir);
    } catch {
      return [];
    }
    const records = [];
    for (const f of files) {
      if (!f.endsWith('.json') || f.endsWith('.tmp')) continue;
      try {
        const raw = await fsp.readFile(path.join(this.dataDir, f), 'utf8');
        const r = JSON.parse(raw);
        if (r && r.id) records.push(r);
      } catch {
        // ignore corrupt records
      }
    }
    records.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    return records;
  }

  async delete(id) {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) return;
    for (const p of [this.recordPath(id), this.xmlPath(id), this.normalPath(id), this.normalPath(id) + '.tmp']) {
      await fsp.rm(p, { force: true }).catch(() => {});
    }
    // Best-effort: sweep any temp files left behind by interrupted writes.
    try {
      const files = await fsp.readdir(this.dataDir);
      for (const f of files) {
        if (f.startsWith(`${id}.`) && f.endsWith('.tmp')) {
          await fsp.rm(path.join(this.dataDir, f), { force: true }).catch(() => {});
        }
      }
    } catch {
      // ignore
    }
  }

  /** Enforce the history cap: delete oldest finished records beyond the limit. */
  async trim() {
    const all = await this.list();
    const over = all.slice(this.historyLimit);
    for (const r of over) {
      if (r.status === 'running' || r.status === 'queued') continue;
      await this.delete(r.id);
    }
  }
}
