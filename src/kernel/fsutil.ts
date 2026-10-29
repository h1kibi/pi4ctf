/**
 * Filesystem primitives: atomic replace (tmp -> fsync -> rename), bounded
 * short lock, sha256. Mirrors docs/kernel-design.md §2 principles.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from './error.js';

export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** rename with bounded retry: Windows can transiently EPERM/EBUSY a rename
 *  over an existing file (antivirus / indexer holding the target). */
function renameWithRetry(from: string, to: string, attempts = 5): void {
  for (let i = 0; ; i++) {
    try {
      fs.renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (i < attempts && (code === 'EPERM' || code === 'EBUSY' || code === 'EACCES')) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20 * (i + 1));
        continue;
      }
      throw err;
    }
  }
}

/** Atomic file replace: write tmp in same dir -> fsync -> rename. */
export function atomicWriteFile(filePath: string, contents: string | Buffer): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  try {
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeFileSync(fd, contents);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    renameWithRetry(tmp, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* best effort */
    }
    const message = err instanceof Error ? err.message : String(err);
    throw new KernelError('INTERNAL', `atomic write failed for ${filePath}: ${message}`);
  }
}

export function appendJsonl(filePath: string, record: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const line = JSON.stringify(record) + '\n';
  // O_APPEND writes of a single line are effectively atomic for our sizes.
  const fd = fs.openSync(filePath, 'a');
  try {
    fs.writeFileSync(fd, line);
  } finally {
    fs.closeSync(fd);
  }
}

export function readJson<T>(filePath: string): T {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new KernelError('INTERNAL', `cannot read ${filePath}: ${message}`);
  }
}

export function readJsonIfExists<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  return readJson<T>(filePath);
}

// ---------------------------------------------------------------------------
// Short lock: exclusive-create lock file with PID, bounded retry 100ms x 10,
// CONFLICT on timeout (docs/kernel-design.md §12). Stale locks (>120s) are
// broken; the lock is only held for counters/events/queue/flag writes.
// ---------------------------------------------------------------------------

const LOCK_RETRY_MS = 100;
const LOCK_RETRIES = 10;

/** Is a pid alive? process.kill(pid, 0) probes without signaling; EPERM
 *  means it exists under another user (treat as alive). */
function pidAlive(pid: number | undefined): boolean {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export class FileLock {
  private depth = 0;

  private constructor(private readonly lockPath: string) {}

  /** Per-process instance cache: one instance per lock path so nested
   *  withLock calls across Project.open() results share the reentry count. */
  private static readonly instances = new Map<string, FileLock>();

  static at(lockPath: string): FileLock {
    const normalized = path.resolve(lockPath);
    let inst = FileLock.instances.get(normalized);
    if (!inst) {
      inst = new FileLock(normalized);
      FileLock.instances.set(normalized, inst);
    }
    return inst;
  }

  /** Re-entrant per instance: nested withLock calls share one acquisition. */
  acquire(): void {
    if (this.depth > 0) {
      this.depth++;
      return;
    }
    for (let attempt = 0; attempt <= LOCK_RETRIES; attempt++) {
      if (this.tryAcquire()) {
        this.depth = 1;
        return;
      }
      // Stale lock: holder pid dead or lock too old -> break it.
      this.breakStale();
      const wait = attempt === LOCK_RETRIES ? 0 : LOCK_RETRY_MS;
      if (wait > 0) {
        const woke = Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, wait);
        if (woke !== 'timed-out') break;
      }
    }
    throw new KernelError('CONFLICT', `lock busy: ${this.lockPath}`);
  }

  private tryAcquire(): boolean {
    try {
      const fd = fs.openSync(this.lockPath, 'wx');
      try {
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, ts: Date.now() }));
      } finally {
        fs.closeSync(fd);
      }
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EEXIST') return false;
      const message = err instanceof Error ? err.message : String(err);
      throw new KernelError('INTERNAL', `lock acquire failed: ${message}`);
    }
  }

  /** Only break locks whose holder process is dead (review C6). A live
   *  holder keeps its lock no matter how old the timestamp — breaking it
   *  would destroy counter/event atomicity. */
  private breakStale(): void {
    let info: { pid?: number; ts?: number };
    try {
      info = JSON.parse(fs.readFileSync(this.lockPath, 'utf8'));
    } catch {
      return;
    }
    if (pidAlive(info.pid)) return;
    try {
      fs.unlinkSync(this.lockPath);
    } catch {
      /* raced with someone else */
    }
  }

  release(): void {
    if (this.depth > 1) {
      this.depth--;
      return;
    }
    this.depth = 0;
    try {
      fs.unlinkSync(this.lockPath);
    } catch {
      /* already gone */
    }
  }

  /** Run fn under the lock. */
  withLock<T>(fn: () => T): T {
    this.acquire();
    try {
      return fn();
    } finally {
      this.release();
    }
  }
}

/** Canonical identity of a directory for fail-closed root checks. */
export function rootIdentity(dirPath: string): string {
  const st = fs.statSync(dirPath, { bigint: true });
  return `dev:${st.dev.toString(16)}:ino:${st.ino.toString(16)}`;
}

/** Resolve p inside root; SECURITY error on escape, symlink, device names. */
export function resolveInside(root: string, rel: string): string {
  const normalizedRel = path.posix.normalize(rel.replace(/\\/g, '/'));
  if (normalizedRel === '..' || normalizedRel.startsWith('../') || path.isAbsolute(normalizedRel)) {
    throw new KernelError('SECURITY', `path escapes root: ${rel}`);
  }
  const abs = path.resolve(root, normalizedRel);
  const relBack = path.relative(root, abs);
  if (relBack.startsWith('..') || path.isAbsolute(relBack)) {
    throw new KernelError('SECURITY', `path escapes root: ${rel}`);
  }
  // Reject symlinked path segments (no-follow, per-segment).
  let cur = root;
  for (const seg of normalizedRel.split('/')) {
    if (seg === '' || seg === '.') continue;
    cur = path.join(cur, seg);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(cur);
    } catch {
      return abs; // missing final segment is fine (we create it)
    }
    if (st.isSymbolicLink()) {
      throw new KernelError('SECURITY', `symlink in path: ${cur}`);
    }
  }
  // Windows device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9).
  const base = path.basename(abs).split('.')[0].toUpperCase();
  if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(base)) {
    throw new KernelError('SECURITY', `device name rejected: ${base}`);
  }
  return abs;
}
