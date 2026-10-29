/** Oracle parsing/pinning shared by project configuration and flag validation. */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { parseTarget, targetRef } from './target.js';

export type { OracleFile } from "./types.js";
import type { OracleFile, TargetResetSpec, TargetSpec } from "./types.js";

export interface OracleRead {
  raw: Buffer;
  hash: string;
  oracle: OracleFile;
}

export function readOracle(file: string): OracleRead | null {
  if (!fs.existsSync(file)) return null;
  try {
    const raw = fs.readFileSync(file);
    const oracle = JSON.parse(raw.toString('utf8')) as OracleFile;
    return {
      raw,
      hash: crypto.createHash('sha256').update(raw).digest('hex'),
      oracle,
    };
  } catch {
    return null;
  }
}

/** Only a supported ground-truth field makes an oracle pinnable. */
export function oracleFileHash(file: string): string | null {
  const read = readOracle(file);
  if (!read) return null;
  const valid =
    (typeof read.oracle.flag === 'string' && read.oracle.flag.trim().length > 0) ||
    (typeof read.oracle.flagSha256 === 'string' && /^[0-9a-f]{64}$/i.test(read.oracle.flagSha256));
  return valid ? read.hash : null;
}

export function oracleTarget(oracle: OracleFile): TargetSpec | null {
  const direct = parseTarget(oracle.target);
  if (direct) return direct;
  if (typeof oracle.host === 'string') {
    return parseTarget({ host: oracle.host, port: oracle.port, instanceId: oracle.instanceId });
  }
  return null;
}

/**
 * Returns an error string when the oracle cannot be bound to the project
 * target; null means the context is compatible. Missing/unpinned oracles are
 * handled separately by flag validation.
 */
export function oracleBindingError(oracle: OracleFile, projectTarget: TargetSpec | null): string | null {
  if (oracle.expiresAt !== undefined) {
    const expires = typeof oracle.expiresAt === 'number' ? oracle.expiresAt : Date.parse(String(oracle.expiresAt));
    if (!Number.isFinite(expires)) return 'oracle expiresAt is invalid';
    if (Date.now() > expires) return 'oracle has expired; obtain a current-instance oracle';
  }
  const bound = oracleTarget(oracle);
  if (!projectTarget) {
    // A targetless static case may still use an unbound oracle. An oracle
    // only carrying instance metadata without the case target is ambiguous.
    if (bound?.instanceId) {
      return 'oracle is instance-bound but the case has no target/instanceId';
    }
    return null;
  }
  if (!bound) return 'oracle is not bound to the current target; add target/instanceId to the oracle';
  if (targetRef(bound) !== targetRef(projectTarget)) {
    return `oracle target ${targetRef(bound)} does not match current target ${targetRef(projectTarget)}`;
  }
  if (!projectTarget.instanceId && bound.instanceId) {
    return 'case has no instanceId but the oracle is instance-bound; set target.instanceId or remove instanceId from the oracle';
  }
  if (!projectTarget.instanceId && oracle.expiresAt === undefined) {
    return 'target has no instanceId; oracle must set expiresAt (or configure target.instanceId) to distinguish a restarted instance';
  }
  if (projectTarget.instanceId && !bound.instanceId) {
    return 'oracle is not bound to the current instance; add instanceId to the oracle';
  }
  if (bound.instanceId && projectTarget.instanceId && bound.instanceId !== projectTarget.instanceId) {
    return 'oracle instanceId does not match current instance';
  }
  return null;
}


/** Parse the optional reset hook; malformed reset metadata is ignored. */
export function oracleReset(oracle: OracleFile): TargetResetSpec | null {
  const raw = oracle.reset;
  if (!raw || typeof raw !== 'object') return null;
  const value = raw as unknown as Record<string, unknown>;
  if (typeof value.url !== 'string') return null;
  let url: URL;
  try {
    url = new URL(value.url);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const method = value.method === 'GET' || value.method === 'PUT' || value.method === 'POST' ? value.method : 'POST';
  const headers: Record<string, string> = {};
  if (value.headers && typeof value.headers === 'object' && !Array.isArray(value.headers)) {
    for (const [key, header] of Object.entries(value.headers as Record<string, unknown>)) {
      if (typeof header === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(key)) headers[key] = header.slice(0, 4096);
    }
  }
  const timeout = Number(value.timeoutMs);
  return {
    url: url.toString(),
    method,
    ...(Object.keys(headers).length ? { headers } : {}),
    ...(typeof value.body === 'string' ? { body: value.body.slice(0, 8192) } : {}),
    ...(Number.isFinite(timeout) ? { timeoutMs: Math.min(30_000, Math.max(500, timeout)) } : {}),
  };
}
