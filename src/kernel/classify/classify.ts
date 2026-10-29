/**
 * Stage B classification (ADR 0002 §1): capability contract applied to shaped
 * output -> parsed fields (with span provenance) + semanticFailure.
 *
 * Contracts are kernel-owned data; the model cannot pick a weaker contract for
 * a known commandClass. Dangerous status codes (5xx/403/429/WAF) come from the
 * kernel status table, not from the model.
 */
import { KernelError } from '../error.js';
import type { Observation, ParsedField, ProcessOutcome, SemanticFailure } from '../types.js';

// ---------------------------------------------------------------------------
// commandClass derivation from argv (deterministic; not a runtime registry
// of behaviors, just a label used to select the contract).
// ---------------------------------------------------------------------------

const PROGRAM_CLASS: Record<string, string> = {
  curl: 'http-probe',
  wget: 'http-probe',
  http: 'http-probe',
  nmap: 'port-scan',
  masscan: 'port-scan',
  sqlmap: 'sqli-probe',
  ffuf: 'http-fuzz',
  gobuster: 'http-fuzz',
  dirb: 'http-fuzz',
  nikto: 'http-probe',
  nc: 'net',
  ncat: 'net',
  netcat: 'net',
  socat: 'net',
  gdb: 'debug',
  'nc.exe': 'net',
};

export function commandClassOf(argv: string[]): string {
  if (argv.length === 0) return 'generic';
  const raw = argv[0] ?? '';
  const program = (raw.split(/[\\/]/).pop() ?? '').toLowerCase().replace(/\.exe$/, '');
  const mapped = PROGRAM_CLASS[program];
  if (mapped) return mapped;
  // python/perl/ruby running a script: exec-local
  if (['python', 'python3', 'perl', 'ruby', 'node'].includes(program)) return 'exec-local';
  if (['strings', 'file', 'xxd', 'objdump', 'readelf', 'radare2', 'r2'].includes(program)) return 'binary-inspect';
  return 'generic';
}

/** Derive target host:port from argv where possible (URLs and net tools). */
export function targetOf(argv: string[]): string | null {
  // Scripts often receive HOST/PORT via env assignments in command mode.
  let envHost: string | null = null;
  let envPort: string | null = null;
  for (const token of argv) {
    const h = /^(?:HOST|TARGET_HOST|RHOST)=([A-Za-z0-9_.-]+)$/.exec(token);
    if (h?.[1]) envHost = h[1];
    const p = /^(?:PORT|TARGET_PORT|RPORT)=(\d{1,5})$/.exec(token);
    if (p?.[1]) envPort = p[1];
    const t = /^(?:TARGET|CTF_TARGET)=([A-Za-z0-9_.-]+)(?::(\d{1,5}))?$/.exec(token);
    if (t?.[1]) {
      envHost = t[1];
      if (t[2]) envPort = t[2];
    }
  }
  if (envHost) return envPort ? `${envHost}:${envPort}` : envHost;
  for (const token of argv) {
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/?#\s:]+)(?::(\d{1,5}))?/.exec(token);
    if (m) {
      const host = m[2].replace(/@.*$/, '@…');
      const port = m[3] ?? (m[1].startsWith('https') ? '443' : '80');
      return `${host}:${port}`;
    }
  }
  // nc host port
  const idx = argv.findIndex((t) => /^(nc|ncat|netcat|socat)$/i.test((t.split(/[\\/]/).pop() ?? '').toLowerCase().replace(/\.exe$/, '')));
  if (idx >= 0 && argv.length > idx + 2 && /^\d+$/.test(argv[idx + 2] ?? '')) {
    return `${argv[idx + 1]}:${argv[idx + 2]}`;
  }
  return null;
}

/**
 * Extract hosts from argv for goal-contract scope checks.
 *
 * v1 hardening rules (review C1):
 *   - URLs are scanned INSIDE every token (quoted URLs, script bodies like
 *     `node -e "fetch('http://x')"` are all covered), not just token starts;
 *   - authority userinfo is honored: host is after the LAST '@'
 *     (http://127.0.0.1:80@evil -> evil);
 *   - any token containing a `://` that yields no parsable host is treated
 *     as unparsable -> the caller fails closed.
 * String parsing cannot fully replace a network sandbox; when allowedHosts
 * is a real allowlist the durable boundary is the docker backend.
 */
const URL_IN_TEXT_RE = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#\s"'`\\]+/g;

export function extractUrlHosts(text: string): string[] {
  const hosts: string[] = [];
  for (const match of text.matchAll(URL_IN_TEXT_RE)) {
    const authority = match[0].split('://', 2)[1] ?? '';
    // strip userinfo (everything up to and including the last '@')
    let host = authority.includes('@') ? (authority.split('@').pop() ?? '') : authority;
    // ipv6 [::1]:80 -> ::1
    const v6 = /^\[(.+)\]/.exec(host);
    if (v6) host = v6[1] ?? '';
    else if (host.includes(':')) host = host.split(':', 1)[0] ?? '';
    if (host.length > 0) hosts.push(host.toLowerCase());
  }
  return hosts;
}

export function hasUnparsableUrl(text: string): boolean {
  if (!text.includes('://')) return false;
  return extractUrlHosts(text).length === 0;
}

export function hostsInArgv(argv: string[]): string[] {
  const hosts: string[] = [];
  for (const token of argv) {
    hosts.push(...extractUrlHosts(token));
  }
  // net tools: explicit host argument position
  const idx = argv.findIndex((t) => /^(nc|ncat|netcat|socat)$/i.test((t.split(/[\\/]/).pop() ?? '').toLowerCase().replace(/\.exe$/, '')));
  if (idx >= 0 && argv.length > idx + 1) {
    const host = argv[idx + 1] ?? '';
    if (/^[\w.-]+$/.test(host)) hosts.push(host.toLowerCase());
  }
  return hosts;
}

// ---------------------------------------------------------------------------
// Kernel-owned contract registry (frozen with fixtures).
// ---------------------------------------------------------------------------

export interface ContractSpec {
  id: string; // e.g. contract.http-probe@1.0.0
  commandClass: string;
  expectOutput: boolean;
  /** HTTP status codes that are semantically fine. */
  okStatus?: [number, number];
  /** Require parsed text to match a schema (e.g. JSON body). */
  expectSchema?: 'json' | 'text';
}

export const CONTRACTS: Record<string, ContractSpec> = {
  'contract.http-probe@1.0.0': {
    id: 'contract.http-probe@1.0.0',
    commandClass: 'http-probe',
    expectOutput: true,
    okStatus: [200, 399],
  },
  'contract.http-fuzz@1.0.0': {
    id: 'contract.http-fuzz@1.0.0',
    commandClass: 'http-fuzz',
    expectOutput: true,
    okStatus: [200, 399],
  },
  'contract.sqli-probe@1.0.0': {
    id: 'contract.sqli-probe@1.0.0',
    commandClass: 'sqli-probe',
    expectOutput: true,
    okStatus: [200, 399],
  },
};

export function contractFor(commandClass: string): ContractSpec | null {
  for (const spec of Object.values(CONTRACTS)) {
    if (spec.commandClass === commandClass) return spec;
  }
  return null;
}

// Kernel status table: model cannot relax (docs/design.md §4.1).
export function statusFailureClass(status: number): SemanticFailure {
  if (status >= 500 && status <= 599) return 'server-error';
  if (status === 403 || status === 429 || status === 401) return 'client-blocked';
  return null;
}

const WAF_MARKERS = [
  'cloudflare',
  'attention required',
  'access denied',
  'request blocked',
  'waf',
  'suspicious request',
];

// ---------------------------------------------------------------------------
// Stage B: classify
// ---------------------------------------------------------------------------

const HTTP_STATUS_RE = /\bHTTP\/[\d.]+\s+(\d{3})\b/;

export function classify(outcome: ProcessOutcome, shapedStdout: string, shapedStderr = ''): Observation {
  const commandClass = outcome.intentClass;
  const contract = contractFor(commandClass);
  const parsed: Record<string, ParsedField> = {};
  const shapedRef = outcome.stdout.shapedRef;

  const putField = (name: string, value: ParsedField['value'], start: number, end: number) => {
    parsed[name] = { value, shapedRef, span: { start, end } };
  };

  let semanticFailure: SemanticFailure = null;
  let semanticDetail: string | null = null;

  if (contract && (commandClass === 'http-probe' || commandClass === 'http-fuzz' || commandClass === 'sqli-probe')) {
    const m = HTTP_STATUS_RE.exec(shapedStdout);
    if (m) {
      const status = Number(m[1]);
      putField('http.status', status, m.index, m.index + m[0].length);
      const fc = statusFailureClass(status);
      if (fc) {
        semanticFailure = fc;
        semanticDetail = `http.status=${status}`;
      }
    } else if (contract.expectOutput && shapedStdout.trim().length > 0) {
      // curl -w "%{http_code}" style bare status line.
      const bare = /^\s*(\d{3})\s*$/m.exec(shapedStdout);
      if (bare) {
        const status = Number(bare[1]);
        putField('http.status', status, bare.index, bare.index + bare[0].length);
        const fc = statusFailureClass(status);
        if (fc) {
          semanticFailure = fc;
          semanticDetail = `http.status=${status}`;
        }
      }
    }
    // WAF markers in body (case-insensitive scan of shaped text).
    if (!semanticFailure) {
      const lower = shapedStdout.toLowerCase();
      for (const marker of WAF_MARKERS) {
        const idx = lower.indexOf(marker);
        if (idx >= 0) {
          semanticFailure = 'client-blocked';
          semanticDetail = `waf-marker:${marker}`;
          putField('waf.marker', marker, idx, idx + marker.length);
          break;
        }
      }
    }
    // JSON schema expectation.
    if (contract.expectSchema === 'json' && !semanticFailure && shapedStdout.trim().length > 0) {
      const trimmed = shapedStdout.trim();
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
        semanticFailure = 'schema-mismatch';
        semanticDetail = 'expected JSON body';
      }
    }
  }

  // Network failures from scripts (pwntools/socket) are not process failures
  // of the exploit route; classify them separately so the negative ledger does
  // not condemn a valid payload just because the instance was down.
  if (!semanticFailure) {
    const networkText = `${shapedStdout}\n${shapedStderr}`;
    const unreachable = [
      /connection refused/i,
      /econnrefused/i,
      /connection timed out/i,
      /connect(?:ion)? timeout/i,
      /could not connect/i,
      /failed to connect/i,
      /no route to host/i,
      /connection reset(?: by peer)?/i,
      /econnreset/i,
      /connection aborted/i,
      /remote end closed connection/i,
      /name or service not known/i,
      /temporary failure in name resolution/i,
      /nodename nor servname/i,
      /target unreachable/i,
    ].find((re) => re.test(networkText));
    if (unreachable) {
      semanticFailure = 'target-unreachable';
      semanticDetail = `network-marker:${unreachable.source}`;
    }
  }

  // A program that needs a controlling terminal fails for an environment
  // reason, not because the payload is wrong. Without this, the negative
  // ledger records it as an approach dead end and pushes the model to change
  // strategy instead of changing how it executes.
  if (!semanticFailure && (outcome.processFailure !== null || (outcome.exit ?? 0) !== 0)) {
    const ttyText = `${shapedStderr}\n${shapedStdout}`;
    const ttyMarker = [
      /not a tty/i,
      /inappropriate ioctl for device/i,
      /no tty present/i,
      /must be run from a terminal/i,
      /requires? a (?:terminal|tty)/i,
      /stdin is not a terminal/i,
    ].find((re) => re.test(ttyText));
    if (ttyMarker) {
      semanticFailure = 'tty-required';
      semanticDetail = `tty-marker:${ttyMarker.source}`;
    }
  }

  // A typo or a missing script is a local execution mistake, not evidence
  // that the exploit route is wrong. Keep it out of the route dead ends.
  if (!semanticFailure && (outcome.processFailure !== null || (outcome.exit ?? 0) !== 0)) {
    const commandText = `${shapedStderr}\n${shapedStdout}`;
    const commandMarker = [
      /command not found/i,
      /no such file or directory/i,
      /not recognized as an internal or external command/i,
    ].find((re) => re.test(commandText));
    if (commandMarker) {
      semanticFailure = 'command-not-found';
      semanticDetail = `command-marker:${commandMarker.source}`;
    }
  }

  const obs: Observation = {
    outcomeId: outcome.id,
    commandClass,
    targetReachable: outcome.targetReachable ?? null,
    contractId: contract ? contract.id : null,
    parsed,
    semanticFailure,
    semanticDetail,
  };
  return obs;
}

/** Validate quote against shaped artifact content; SECURITY on mismatch. */
export function checkQuote(quoteText: string, shapedContent: string, span: { start: number; end: number }): void {
  if (!Number.isInteger(span.start) || !Number.isInteger(span.end) || span.start < 0 || span.end < span.start) {
    throw new KernelError('INVALID_REQUEST', `invalid span ${JSON.stringify(span)}`);
  }
  const slice = shapedContent.slice(span.start, span.end);
  if (slice !== quoteText) {
    throw new KernelError(
      'INVALID_REQUEST',
      `quote does not match shaped[${span.start}:${span.end}]: expected ${JSON.stringify(slice.slice(0, 80))}, got ${JSON.stringify(quoteText.slice(0, 80))}`,
    );
  }
}
