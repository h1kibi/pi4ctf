/**
 * Minimal kernel-owned HTTP primitive used by run.probes.
 *
 * It is deliberately small: cookie jar, redirect control, binary body,
 * status/headers metadata, and an exact raw-socket mode. It is not a browser
 * and does not execute JavaScript.
 */
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { KernelError } from '../error.js';

export interface HttpProbeSpec {
  method?: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  bodyB64?: string;
  bodyFile?: string;
  followRedirects?: boolean;
  cookieJar?: boolean;
  raw?: boolean;
  insecure?: boolean;
  timeoutMs?: number;
}

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  setCookie: string[];
  body: Buffer;
  url: string;
  target: string;
  durationMs: number;
  timedOut: boolean;
  truncated: boolean;
  error: string | null;
}

const MAX_BODY = 8 * 1024 * 1024;
const MAX_REDIRECTS = 5;

interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  expires: number | null;
}

export class CookieJar {
  private cookies: Cookie[] = [];

  store(url: URL, setCookie: string[]): void {
    for (const raw of setCookie) {
      const parts = raw.split(';').map((p) => p.trim());
      const first = parts.shift();
      if (!first) continue;
      const eq = first.indexOf('=');
      if (eq <= 0) continue;
      const cookie: Cookie = {
        name: first.slice(0, eq),
        value: first.slice(eq + 1),
        domain: url.hostname.toLowerCase(),
        path: '/',
        secure: false,
        expires: null,
      };
      for (const attr of parts) {
        const [k, ...rest] = attr.split('=');
        const key = (k ?? '').toLowerCase();
        const value = rest.join('=');
        if (key === 'domain' && value) cookie.domain = value.replace(/^\./, '').toLowerCase();
        else if (key === 'path' && value.startsWith('/')) cookie.path = value;
        else if (key === 'secure') cookie.secure = true;
        else if (key === 'max-age' && /^-?\d+$/.test(value)) cookie.expires = Date.now() + Number(value) * 1000;
        else if (key === 'expires') {
          const t = Date.parse(value);
          if (Number.isFinite(t)) cookie.expires = t;
        }
      }
      this.cookies = this.cookies.filter((c) => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path));
      if (cookie.expires === null || cookie.expires > Date.now()) this.cookies.push(cookie);
    }
  }

  header(url: URL): string {
    const host = url.hostname.toLowerCase();
    const now = Date.now();
    return this.cookies
      .filter((c) => (c.expires === null || c.expires > now))
      .filter((c) => host === c.domain || host.endsWith(`.${c.domain}`))
      .filter((c) => url.pathname.startsWith(c.path))
      .filter((c) => !c.secure || url.protocol === 'https:')
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');
  }
}

function headerObject(input: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(value)) out[key] = value.join(', ');
    else if (value !== undefined) out[key] = value;
  }
  return out;
}

function requestOnce(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer,
  timeoutMs: number,
  insecure: boolean,
): Promise<Omit<HttpResult, 'url' | 'target' | 'durationMs'> & { location: string | null }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method, headers, rejectUnauthorized: !insecure }, (res) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let dropped = false;
      res.on('data', (chunk: Buffer) => {
        if (total >= MAX_BODY) {
          dropped = true;
          return;
        }
        const slice = chunk.subarray(0, MAX_BODY - total);
        total += slice.length;
        chunks.push(slice);
        if (slice.length < chunk.length) dropped = true;
      });
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          headers: headerObject(res.headers),
          setCookie: Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : res.headers['set-cookie'] ? [res.headers['set-cookie']] : [],
          body: Buffer.concat(chunks),
          timedOut: false,
          truncated: dropped,
          error: null,
          location: typeof res.headers.location === 'string' ? res.headers.location : null,
        });
      });
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', (err) => {
      resolve({
        status: 0,
        headers: {},
        setCookie: [],
        body: Buffer.alloc(0),
        timedOut: /timeout/i.test(err.message),
        truncated: false,
        error: err.message,
        location: null,
      });
    });
    if (body.length > 0) req.write(body);
    req.end();
    void started;
  });
}

function dechunk(buf: Buffer): Buffer {
  const out: Buffer[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd < 0) break;
    const size = parseInt(buf.subarray(offset, lineEnd).toString('ascii'), 16);
    if (!Number.isFinite(size) || size < 0) return buf;
    offset = lineEnd + 2;
    if (size === 0) break;
    out.push(buf.subarray(offset, offset + size));
    offset += size + 2;
  }
  return Buffer.concat(out);
}

function rawRequest(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer,
  timeoutMs: number,
  insecure: boolean,
): Promise<HttpResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    const secure = url.protocol === 'https:';
    const port = Number(url.port || (secure ? 443 : 80));
    const host = url.hostname;
    const lines = [
      `${method} ${url.pathname}${url.search} HTTP/1.1`,
      `Host: ${url.host}`,
      'Connection: close',
      ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      '',
      '',
    ];
    const payload = Buffer.concat([Buffer.from(lines.join('\r\n'), 'utf8'), body]);
    const socket = secure
      ? tls.connect({ host, port, servername: host, rejectUnauthorized: !insecure })
      : net.connect({ host, port });
    const chunks: Buffer[] = [];
    let done = false;
    let dropped = false;
    const finish = (timedOut: boolean, error: string | null) => {
      if (done) return;
      done = true;
      socket.destroy();
      const raw = Buffer.concat(chunks);
      const sep = raw.indexOf('\r\n\r\n');
      const head = sep >= 0 ? raw.subarray(0, sep).toString('utf8') : '';
      let responseBody: Buffer<ArrayBufferLike> = sep >= 0 ? raw.subarray(sep + 4) : Buffer.alloc(0);
      const first = head.split('\r\n')[0] ?? '';
      const status = Number(/^HTTP\/\d\.\d\s+(\d{3})/.exec(first)?.[1] ?? 0);
      const responseHeaders: Record<string, string> = {};
      for (const line of head.split('\r\n').slice(1)) {
        const idx = line.indexOf(':');
        if (idx > 0) responseHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      }
      if ((responseHeaders['transfer-encoding'] ?? '').toLowerCase().includes('chunked')) {
        responseBody = dechunk(responseBody);
      }
      resolve({
        status,
        headers: responseHeaders,
        setCookie: responseHeaders['set-cookie'] ? [responseHeaders['set-cookie']] : [],
        body: responseBody.subarray(0, MAX_BODY),
        url: url.toString(),
        target: `${host}:${port}`,
        durationMs: Date.now() - started,
        timedOut,
        truncated: dropped || responseBody.length > MAX_BODY,
        error,
      });
    };
    socket.setTimeout(timeoutMs, () => finish(true, 'timeout'));
    socket.on('data', (chunk: Buffer) => {
      const already = chunks.reduce((n, c) => n + c.length, 0);
      if (already >= MAX_BODY) {
        dropped = true;
        return;
      }
      const slice = chunk.subarray(0, MAX_BODY - already);
      if (slice.length < chunk.length) dropped = true;
      chunks.push(slice);
    });
    socket.on('error', (err) => finish(false, err.message));
    socket.on('close', () => finish(false, null));
    if (secure) socket.once('secureConnect', () => socket.write(payload));
    else socket.on('connect', () => socket.write(payload));
  });
}

export async function performHttp(spec: HttpProbeSpec, jar: CookieJar): Promise<HttpResult> {
  let current: URL;
  try {
    current = new URL(spec.url);
  } catch {
    throw new KernelError('INVALID_REQUEST', `invalid HTTP URL: ${spec.url}`);
  }
  if (current.protocol !== 'http:' && current.protocol !== 'https:') {
    throw new KernelError('INVALID_REQUEST', `unsupported HTTP scheme: ${current.protocol}`);
  }
  const timeoutMs = Math.min(600_000, Math.max(1, spec.timeoutMs ?? 30_000));
  let method = (spec.method ?? 'GET').toUpperCase();
  let requestBody = spec.bodyB64
    ? Buffer.from(spec.bodyB64, 'base64')
    : Buffer.from(spec.body ?? '', 'utf8');
  const baseHeaders: Record<string, string> = { ...(spec.headers ?? {}) };
  if (!Object.keys(baseHeaders).some((k) => k.toLowerCase() === 'user-agent')) {
    baseHeaders['User-Agent'] = 'pi4ctf-http/1';
  }
  if (requestBody.length > 0 && !Object.keys(baseHeaders).some((k) => k.toLowerCase() === 'content-length')) {
    baseHeaders['Content-Length'] = String(requestBody.length);
  }
  if (spec.raw) {
    const cookie = spec.cookieJar !== false ? jar.header(current) : '';
    if (cookie) baseHeaders.Cookie = cookie;
    const result = await rawRequest(current, method, baseHeaders, requestBody, timeoutMs, spec.insecure === true);
    if (spec.cookieJar !== false) jar.store(current, result.setCookie);
    return result;
  }

  const started = Date.now();
  let redirects = 0;
  for (;;) {
    const headers = { ...baseHeaders };
    const cookie = spec.cookieJar !== false ? jar.header(current) : '';
    if (cookie) headers.Cookie = cookie;
    const once = await requestOnce(current, method, headers, requestBody, timeoutMs, spec.insecure === true);
    if (spec.cookieJar !== false) jar.store(current, once.setCookie);
    if (spec.followRedirects && once.location && [301, 302, 303, 307, 308].includes(once.status) && redirects < MAX_REDIRECTS) {
      redirects++;
      current = new URL(once.location, current);
      if (once.status === 303 || ((once.status === 301 || once.status === 302) && method === 'POST')) {
        // Standard browser-ish behavior: 303, and POST on 301/302, become GET.
        method = 'GET';
        requestBody = Buffer.alloc(0);
        baseHeaders['Content-Length'] = '0';
      }
      continue;
    }
    return {
      status: once.status,
      headers: once.headers,
      setCookie: once.setCookie,
      body: once.body,
      url: current.toString(),
      target: `${current.hostname}:${current.port || (current.protocol === 'https:' ? '443' : '80')}`,
      durationMs: Date.now() - started,
      timedOut: once.timedOut,
      truncated: once.truncated,
      error: once.error,
    };
  }
}
