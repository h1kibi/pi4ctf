/** Kernel error codes — mirrors docs/kernel-design.md §4.3. */
export type KernelErrorCode =
  | 'OK'
  | 'INVALID_REQUEST'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'LIMIT'
  | 'TIMEOUT'
  | 'UNSUPPORTED'
  | 'SECURITY'
  | 'ORACLE'
  | 'TARGET_UNREACHABLE'
  | 'FLAG_REJECTED'
  | 'JOB_LOST'
  | 'INTERNAL';

export const EXIT_CODES: Record<KernelErrorCode, number> = {
  OK: 0,
  INVALID_REQUEST: 2,
  NOT_FOUND: 3,
  CONFLICT: 4,
  LIMIT: 5,
  TIMEOUT: 6,
  UNSUPPORTED: 7,
  SECURITY: 8,
  ORACLE: 9,
  TARGET_UNREACHABLE: 13,
  FLAG_REJECTED: 10,
  JOB_LOST: 11,
  INTERNAL: 12,
};

export class KernelError extends Error {
  readonly code: KernelErrorCode;
  readonly details?: unknown;

  constructor(code: KernelErrorCode, message: string, details?: unknown) {
    super(message);
    this.name = 'KernelError';
    this.code = code;
    this.details = details;
  }
}

export interface ErrorResponse {
  ok: false;
  error: { code: KernelErrorCode; message: string; details?: unknown };
}

export function toErrorResponse(err: unknown): ErrorResponse {
  if (err instanceof KernelError) {
    return { ok: false, error: { code: err.code, message: err.message, details: err.details } };
  }
  const message = err instanceof Error ? err.message : String(err);
  return { ok: false, error: { code: 'INTERNAL' as KernelErrorCode, message } };
}
