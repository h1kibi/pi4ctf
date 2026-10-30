import type { FailureClass, NegativeEntry } from './types.js';

const TTL_TRANSIENT_MS = 10 * 60_000;
const TTL_SERVER_ERROR_MS = 60_000;
const TTL_CLIENT_BLOCKED_MS = 5 * 60_000;

export interface NegativeSpec {
  failureClass: FailureClass;
  family: 'environment' | 'approach';
  transient: boolean;
  unblockOn: NegativeEntry['unblockOn'];
  ttlMs: number | null;
}

/** Code-owned negative-entry policy for a failed outcome. */
export function negativeSpecFor(
  processFailure: string | null,
  semanticFailure: string | null,
): NegativeSpec {
  switch (semanticFailure) {
    case 'target-unreachable':
      return { failureClass: 'timeout', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
    case 'server-error':
      return { failureClass: 'server-error', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_SERVER_ERROR_MS };
    case 'client-blocked':
      return { failureClass: 'client-blocked', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_CLIENT_BLOCKED_MS };
    case 'tty-required':
      return { failureClass: 'tty-required', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
    case 'command-not-found':
      return { failureClass: 'command-not-found', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
    case 'schema-mismatch':
      return { failureClass: 'schema-mismatch', family: 'approach', transient: false, unblockOn: 'env_change', ttlMs: null };
    case 'probe-contradicted':
      return { failureClass: 'probe-contradicted', family: 'approach', transient: false, unblockOn: 'probe_version', ttlMs: null };
  }
  if (processFailure === 'timeout') {
    return { failureClass: 'timeout', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
  }
  if (processFailure === 'nonzero-exit') {
    return { failureClass: 'nonzero-exit', family: 'approach', transient: true, unblockOn: 'probe', ttlMs: TTL_TRANSIENT_MS };
  }
  if (processFailure === 'no-output-when-expected') {
    return { failureClass: 'no-output', family: 'environment', transient: true, unblockOn: 'ttl', ttlMs: TTL_TRANSIENT_MS };
  }
  return { failureClass: 'probe-contradicted', family: 'approach', transient: false, unblockOn: 'probe_version', ttlMs: null };
}
