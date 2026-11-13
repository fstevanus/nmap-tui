// ScanManager: spawns nmap child processes, streams live progress via an
// EventEmitter per record, parses XML results and persists records.

import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fsp from 'node:fs/promises';
import { buildArgs, formatCommand } from './args.js';
import { parseNmapXml } from './parse.js';

const MAX_XML_BYTES = 256 * 1024 * 1024; // 256 MB capture cap
const PROGRESS_RE = /About\s+([0-9]+(?:\.[0-9]+)?)%\s+done/;

export class ScanManager extends EventEmitter {
  constructor({ store, concurrency = 2, nmapBin = 'nmap' }) {
    super();
    this.store = store;
    this.concurrency = Math.max(1, concurrency);
    this.nmapBin = nmapBin;
    this.running = new Map(); // id -> child
    this.live = new Map(); // id -> in-memory record (has live state)
    this.queue = []; // ids
  }

  /** In-memory record for a live (queued/running) scan, or null. */
  getLive(id) {
    return this.live.get(id) || null;
  }

  get queuedCount() {
    return this.queue.length;
  }

  get runningCount() {
    return this.running.size;
  }

  /** Enqueue a scan record; returns the record. */
  enqueue(record) {
    record.status = 'queued';
    record.queuedAt = new Date().toISOString();
    this.live.set(record.id, record);
    this.queue.push(record.id);
    this._emit(record, { type: 'queued', position: this.queue.length });
    this._pump();
    return record;
  }

  isActive(id) {
    return this.queue.includes(id) || this.running.has(id);
  }

  /** Cancel a queued or running scan. */
  async cancel(id) {
    const qi = this.queue.indexOf(id);
    if (qi !== -1) {
      this.queue.splice(qi, 1);
      const record = this.live.get(id) || (await this.store.get(id));
      if (record) {
        record.status = 'cancelled';
        record.finishedAt = new Date().toISOString();
        await this.store.save(record);
        this.live.delete(id);
        this._emit(record, { type: 'cancelled' });
      }
      return record;
    }
    const child = this.running.get(id);
    if (child && child.__cancel) child.__cancel();
    return null;
  }

  _pump() {
    while (this.queue.length > 0 && this.running.size < this.concurrency) {
      const id = this.queue.shift();
      this._start(id).catch((err) => {
        console.error('[scanner] failed to start', id, err);
      });
    }
  }

  async _start(id) {
    let record = this.live.get(id);
    if (!record) {
      record = await this.store.get(id);
      if (!record || record.status === 'cancelled') return;
      this.live.set(record.id, record);
    }

    let args;
    let targets;
    try {
      ({ args, targets } = buildArgs(record));
    } catch (err) {
      record.status = 'error';
      record.error = err.message;
      record.finishedAt = new Date().toISOString();
      await this.store.save(record);
      this._emit(record, { type: 'error', message: err.message });
      this.live.delete(id);
      this._pump();
      return;
    }

    const xmlPath = this.store.xmlPath(id);
    const normalPath = this.store.normalPath(id);
    const finalArgs = [...args, '-oX', '-', '-oN', normalPath, '--stats-every', '1s', ...targets];

    let child;
    try {
      child = spawn(this.nmapBin, finalArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      record.status = 'error';
      record.error = `Failed to launch nmap: ${err.message}`;
      record.finishedAt = new Date().toISOString();
      await this.store.save(record);
      this._emit(record, { type: 'error', message: record.error });
      this.live.delete(id);
      this._pump();
      return;
    }

    // Cancel support: assign __cancel BEFORE registering in `running` so a
    // cancel() arriving right after spawn (even before status='running' is
    // persisted) can never miss the child. SIGINT first (nmap handles it),
    // SIGKILL after 3s.
    // Declare all shared state up front so the close/error handlers (registered
    // below, before any await) can safely reference them even if they fire
    // during the store save.
    let killed = false;
    const xmlChunks = [];
    let xmlBytes = 0;
    let xmlTruncated = false;
    let stderrTail = [];
    let stderrBuf = '';
    const pushStderr = (s) => {
      stderrTail.push(s);
      if (stderrTail.length > 40) stderrTail.shift();
    };

    // Finalize each record exactly once. A spawn failure (e.g. ENOENT) makes
    // Node emit BOTH 'error' and 'close' (code -2); both handlers used to
    // save/pump/emits on the same record concurrently, racing on the store
    // temp file and delivering duplicate events. The first handler to run
    // wins (Node fires 'error' before 'close', so the spawn-failure message
    // beats the misleading "could not be parsed" one), and every rejection
    // inside the finalizer is caught so it can never escape as an
    // unhandled rejection and kill the server process.
    let finalized = false;
    const finalize = (fn) => {
      if (finalized) return;
      finalized = true;
      Promise.resolve()
        .then(fn)
        .catch((err) => {
          console.error('[scanner] failed to finalize scan', id, err);
        });
    };

    child.__cancel = () => {
      killed = true;
      try { child.kill('SIGINT'); } catch {}
      setTimeout(() => {
        try { if (child.exitCode === null) child.kill('SIGKILL'); } catch {}
      }, 3000);
    };

    // Register stdout/stderr/error/close handlers NOW, before any await, so a
    // cancel() (or a fast spawn failure) that lands during store.save can
    // never be missed.
    child.stdout.on('data', (buf) => {
      if (xmlBytes < MAX_XML_BYTES) {
        const take = Math.min(buf.length, MAX_XML_BYTES - xmlBytes);
        xmlChunks.push(buf.subarray(0, take));
        xmlBytes += take;
        if (take < buf.length) xmlTruncated = true;
      } else {
        xmlTruncated = true;
      }
    });

    child.stderr.on('data', (buf) => {
      stderrBuf += buf.toString('utf8');
      let nl;
      while ((nl = stderrBuf.indexOf('\n')) !== -1) {
        const line = stderrBuf.slice(0, nl).replace(/\r$/, '');
        stderrBuf = stderrBuf.slice(nl + 1);
        if (!line.trim()) continue;
        pushStderr(line);
        this._emit(record, { type: 'log', line, ts: Date.now() });
        const m = line.match(PROGRESS_RE);
        if (m) this._emit(record, { type: 'progress', percent: parseFloat(m[1]), stats: line });
      }
    });

    child.on('error', (err) => {
      finalize(async () => {
        pushStderr(`Failed to launch nmap: ${err.message}`);
        if (this.running.has(id)) this.running.delete(id);
        record.status = 'error';
        record.error = `Failed to launch nmap: ${err.message}`;
        record.exitCode = null;
        record.finishedAt = new Date().toISOString();
        record.stderrTail = stderrTail.slice();
        await this.store.save(record);
        this._emit(record, { type: 'error', message: record.error, stderrTail });
        this.live.delete(id);
        this._pump();
      });
    });

    child.on('close', (code, signal) => {
      // Idempotent bookkeeping, safe even if 'error' already finalized.
      if (this.running.has(id)) this.running.delete(id);
      finalize(async () => {
        this.live.delete(id);
        const wasCancelled = killed || signal === 'SIGINT' || signal === 'SIGTERM';
        record.exitCode = code;
        record.signal = signal || null;
        record.finishedAt = new Date().toISOString();
        record.durationMs = Date.parse(record.finishedAt) - Date.parse(record.startedAt);

        const xml = Buffer.concat(xmlChunks.map((c) => Buffer.from(c))).toString('utf8');
        // Only write an XML file when something was actually captured —
        // avoid leaving a bogus empty <id>.xml behind (e.g. spawn failure).
        if (xml) {
          try {
            await fsp.writeFile(xmlPath, xml, 'utf8');
          } catch (err) {
            console.error('[scanner] failed to write xml', id, err);
          }
        }
        if (xmlTruncated) {
          record.xmlTruncated = true;
          this._emit(record, { type: 'log', line: `[server] XML output exceeded ${MAX_XML_BYTES / 1024 / 1024} MB and was truncated`, ts: Date.now() });
        }

        if (wasCancelled) {
          record.status = 'cancelled';
          await this.store.save(record);
          this._emit(record, { type: 'cancelled', exitCode: code });
          this._pump();
          return;
        }

        // Try parsing the XML we captured.
        try {
          const result = parseNmapXml(xml);
          record.result = result;
          record.summary = result.summary;
          record.status = 'done';
          await this.store.save(record);
          await this.store.trim();
          this._emit(record, {
            type: 'done',
            result,
            summary: result.summary,
            exitCode: code,
            durationMs: record.durationMs,
            finishedAt: record.finishedAt
          });
        } catch (parseErr) {
          record.status = 'error';
          record.error = `Scan finished but output could not be parsed (exit code ${code}): ${parseErr.message}`;
          record.stderrTail = stderrTail.slice();
          await this.store.save(record);
          this._emit(record, { type: 'error', message: record.error, stderrTail: stderrTail });
        }
        this._pump();
      });
    });

    record.status = 'running';
    record.startedAt = new Date().toISOString();
    record.command = formatCommand(finalArgs);
    this.running.set(id, child);
    this._emit(record, { type: 'started', command: record.command, pid: child.pid, startedAt: record.startedAt });
    await this.store.save(record);
  }

  _emit(record, event) {
    this.emit('event', record.id, event);
  }
}
