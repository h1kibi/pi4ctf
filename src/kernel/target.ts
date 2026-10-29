/** Target/instance metadata and bounded reachability checks. */
import * as net from 'node:net';
import { KernelError } from './error.js';
import type { TargetSpec } from './types.js';

const PROTOCOLS = new Set(['tcp', 'http', 'https', 'udp', 'other']);

export function isLoopbackHost(host: string): boolean {
  const value = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return value === 'localhost' || value === '::1' || value.startsWith('127.');
}

export function parseTarget(value: unknown): TargetSpec | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) return null;
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
      let u: URL;
      try {
        u = new URL(raw);
      } catch {
        throw new KernelError('INVALID_REQUEST', `invalid target URL: ${raw}`);
      }
      const protocol = u.protocol.replace(':', '').toLowerCase();
      const port = u.port ? Number(u.port) : (protocol === 'https' ? 443 : protocol === 'http' ? 80 : undefined);
      return normalizeTarget({
        host: u.hostname,
        port,
        protocol: protocol === 'https' || protocol === 'http' ? protocol : 'other',
        url: raw,
      });
    }
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw) ?? /^([^:\s]+)(?::(\d+))?$/.exec(raw);
    if (!m) throw new KernelError('INVALID_REQUEST', `invalid target: ${raw}`);
    return normalizeTarget({ host: m[1], port: m[2] ? Number(m[2]) : undefined });
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return normalizeTarget({
      host: typeof obj.host === 'string' ? obj.host : '',
      port: obj.port === undefined || obj.port === null || obj.port === '' ? undefined : Number(obj.port),
      protocol: typeof obj.protocol === 'string' ? obj.protocol as TargetSpec['protocol'] : undefined,
      instanceId: typeof obj.instanceId === 'string' ? obj.instanceId : undefined,
      url: typeof obj.url === 'string' ? obj.url : undefined,
    });
  }
  throw new KernelError('INVALID_REQUEST', 'target must be a host[:port], URL, or object');
}

export function normalizeTarget(input: TargetSpec): TargetSpec {
  const host = String(input.host ?? '').trim().replace(/^\[|\]$/g, '');
  if (!host || !/^[A-Za-z0-9_.-]+$/.test(host)) {
    throw new KernelError('INVALID_REQUEST', `invalid target host: ${host || '(empty)'}`);
  }
  let port = input.port;
  if (port !== undefined) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new KernelError('INVALID_REQUEST', `invalid target port: ${port}`);
    }
  }
  const protocol = input.protocol ?? (port === 443 ? 'https' : port === 80 ? 'http' : 'tcp');
  if (!PROTOCOLS.has(protocol)) {
    throw new KernelError('INVALID_REQUEST', `invalid target protocol: ${protocol}`);
  }
  const out: TargetSpec = { host, protocol };
  if (port !== undefined) out.port = port;
  if (input.instanceId) out.instanceId = input.instanceId.slice(0, 200);
  if (input.url) out.url = input.url.slice(0, 2048);
  return out;
}

/** Canonical comparison key used by outcomes/flags/oracles. */
export function targetRef(target: TargetSpec | null | undefined): string | null {
  if (!target) return null;
  return target.port === undefined ? target.host : `${target.host}:${target.port}`;
}

export function sameTarget(
  a: TargetSpec | null | undefined,
  b: TargetSpec | null | undefined,
): boolean {
  if (!a && !b) return true;
  if (!a || !b) return false;
  return targetRef(a) === targetRef(b) && (a.instanceId ?? '') === (b.instanceId ?? '');
}

export function targetFromEnv(env: Record<string, unknown> | undefined): TargetSpec | null {
  if (!env) return null;
  const host = env.HOST ?? env.TARGET_HOST ?? env.RHOST;
  if (typeof host !== 'string' || !host) return null;
  const rawPort = env.PORT ?? env.TARGET_PORT ?? env.RPORT;
  const port = rawPort === undefined || rawPort === '' ? undefined : Number(rawPort);
  const instanceId = env.INSTANCE_ID ?? env.CTF_INSTANCE_ID;
  return normalizeTarget({
    host,
    port,
    ...(typeof instanceId === 'string' && instanceId ? { instanceId } : {}),
  });
}

export function targetEnv(target: TargetSpec | null | undefined): Record<string, string> {
  if (!target) return {};
  const env: Record<string, string> = {
    TARGET: targetRef(target) ?? '',
  };
  if (target.host) env.HOST = target.host;
  if (target.port !== undefined) env.PORT = String(target.port);
  if (target.protocol) env.PROTOCOL = target.protocol;
  if (target.instanceId) env.INSTANCE_ID = target.instanceId;
  if (target.url) env.TARGET_URL = target.url;
  return env;
}

export function mergeEnv(
  target: TargetSpec | null | undefined,
  extra: Record<string, unknown> | undefined,
): Record<string, string> {
  const out = targetEnv(target);
  if (!extra) return out;
  for (const [key, value] of Object.entries(extra)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(key)) {
      throw new KernelError('INVALID_REQUEST', `invalid env key: ${key}`);
    }
    if (value === null || value === undefined) continue;
    const text = String(value);
    if (text.length > 8192 || text.includes('\0')) {
      throw new KernelError('LIMIT', `env ${key} is too large or contains NUL`);
    }
    out[key] = text;
  }
  return out;
}

export interface Reachability {
  checked: boolean;
  ok: boolean;
  error: string | null;
  ms: number;
}

/** TCP reachability only; it does not prove the service/protocol is healthy. */
export function checkReachable(target: TargetSpec, timeoutMs = 2000): Promise<Reachability> {
  const port = target.port;
  if (port === undefined || target.protocol === 'udp') {
    return Promise.resolve({ checked: false, ok: true, error: null, ms: 0 });
  }
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ host: target.host, port });
    const finish = (ok: boolean, error: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ checked: true, ok, error, ms: Date.now() - started });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true, null));
    socket.once('timeout', () => finish(false, 'timeout'));
    socket.once('error', (err) => finish(false, err.message));
  });
}
