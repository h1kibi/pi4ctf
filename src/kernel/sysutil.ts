/** Small platform utilities. */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Pick a POSIX shell. On Windows, WSL's bash.exe mangles `$var` in a
 *  command-line `-c` string before it reaches Linux; prefer Git Bash when it
 *  is installed. Set PI4CTF_BASH to override (e.g. a WSL path when needed). */
export function resolveBash(): string {
  const override = process.env.PI4CTF_BASH;
  if (override) return override;
  if (process.platform === 'win32') {
    const roots = [process.env.ProgramFiles, process.env['ProgramFiles(x86)']];
    for (const root of roots) {
      if (!root) continue;
      const candidate = path.join(root, 'Git', 'bin', 'bash.exe');
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch {
        /* not installed */
      }
    }
  }
  return 'bash';
}

/** Check a command can be launched: path-like probes resolve by existence,
 *  bare names resolve via PATH lookup (cached; only fixed probe names or
 *  user-provided program names — never free-form user strings). */
const cache = new Map<string, boolean>();

export function commandExists(command: string): boolean {
  if (command === '') return false;
  // Path-like: absolute, or contains a separator (./x, ../x, sub/x).
  if (path.isAbsolute(command) || command.includes('/') || command.includes('\\')) {
    try {
      const st = fs.statSync(command);
      return st.isFile();
    } catch {
      return false;
    }
  }
  const hit = cache.get(command);
  if (hit !== undefined) return hit;
  const probe = process.platform === 'win32'
    ? spawnSync('where', [command], { stdio: 'ignore', shell: true })
    : spawnSync('which', [command], { stdio: 'ignore' });
  const found = probe.status === 0;
  cache.set(command, found);
  return found;
}

/** Environment allowlist shared by run and session (review C5): challenge
 *  processes never inherit model keys, cloud creds, proxies, etc. */
const PROXY_ENV = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'no_proxy',
];

const DEFAULT_NO_PROXY = 'localhost,127.0.0.1,::1';

function mergeNoProxy(...values: string[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    for (const raw of value.split(',')) {
      const item = raw.trim();
      if (!item) continue;
      if (item === '*') return '*';
      const key = item.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(item);
    }
  }
  return out.join(',');
}

const ENV_ALLOWLIST = [
  'PATH',
  'HOME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TERM',
  'TMP',
  'TEMP',
  'SYSTEMROOT',
  'COMSPEC',
  'PATHEXT',
  'SYSTEMDRIVE',
];

export function baseEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ENV_ALLOWLIST) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  // Keep the run channel consistent with the pi bash tool: if the host has
  // proxy variables, challenge commands (including Python) need the same
  // ones. `PI4CTF_INHERIT_PROXY=0` is the explicit strict opt-out.
  if (process.env.PI4CTF_INHERIT_PROXY !== '0') {
    for (const key of PROXY_ENV) {
      if (process.env[key] !== undefined) env[key] = process.env[key];
    }
  }
  // Always give local tools an explicit loopback bypass; an inherited
  // NO_PROXY is preserved and extended rather than overwritten.
  const mergedNoProxy = mergeNoProxy(env.NO_PROXY ?? '', env.no_proxy ?? '', DEFAULT_NO_PROXY);
  env.NO_PROXY = mergedNoProxy;
  env.no_proxy = mergedNoProxy;
  return env;
}
