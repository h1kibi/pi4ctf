import type { ErrorResponse } from '../kernel/error.js';

export interface Request {
  op: string;
  root?: string;
  input?: Record<string, unknown>;
}

export interface OkResponse {
  ok: true;
  op: string;
  data: Record<string, unknown>;
}

export type Response = OkResponse | ErrorResponse;
