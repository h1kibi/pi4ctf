import { KernelError } from '../kernel/error.js';
import { Project } from '../kernel/project.js';
import { DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS } from '../kernel/run/exec.js';
import { envContextOf } from '../providers/env/context.js';
import { commandExists } from '../kernel/sysutil.js';
import { auditState } from '../kernel/state-audit.js';
import type { FlagLayers } from '../kernel/types.js';
import { doctorTools } from '../providers/env/store.js';
import type { OkResponse, Request } from './types.js';

export const EVIDENCE_TEXT_CAP = 8 * 1024 * 1024;

export function needRoot(req: Request): Project {
  if (!req.root) throw new KernelError('INVALID_REQUEST', 'root is required');
  return Project.open(req.root);
}

export function evidenceLineMatches(text: string, pattern: string, context: number, maxMatches: number) {
  if (pattern.length > 256) throw new KernelError('LIMIT', 'grep pattern exceeds 256 characters');
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    throw new KernelError('INVALID_REQUEST', `invalid grep regex: ${pattern}`);
  }
  const lines = text.split(/\n/);
  const matches: Array<{
    line: number;
    start: number;
    end: number;
    text: string;
    matched: string;
    before: string[];
    after: string[];
  }> = [];
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const m = re.exec(line);
    if (m) {
      matches.push({
        line: i + 1,
        start: offset + (m.index ?? 0),
        end: offset + (m.index ?? 0) + m[0].length,
        text: line.slice(0, 512),
        matched: m[0].slice(0, 512),
        before: lines.slice(Math.max(0, i - context), i).map((l) => l.slice(0, 512)),
        after: lines.slice(i + 1, i + 1 + context).map((l) => l.slice(0, 512)),
      });
      if (matches.length >= maxMatches) break;
    }
    offset += line.length + 1;
  }
  return { matches, totalLines: lines.length };
}

export function evidenceHeadTail(text: string, head: number | null, tail: number | null) {
  const rawLines = text.split(/\n/);
  const lines = rawLines.length > 1 && rawLines[rawLines.length - 1] === ''
    ? rawLines.slice(0, -1)
    : rawLines;
  const totalLines = lines.length;
  const selected = head !== null
    ? lines.slice(0, head)
    : tail !== null
      ? lines.slice(Math.max(0, totalLines - tail))
      : lines;
  const joined = selected.join('\n');
  const clipped = joined.length > 16 * 1024 ? joined.slice(0, 16 * 1024) : joined;
  return { text: clipped, lines: selected.length, totalLines, truncated: clipped.length < joined.length };
}

export function ok(op: string, data: Record<string, unknown>): OkResponse {
  return { ok: true, op, data };
}

export function str(input: Record<string, unknown>, key: string, dflt?: string): string {
  const v = input[key];
  if (v === undefined || v === null) {
    if (dflt !== undefined) return dflt;
    throw new KernelError('INVALID_REQUEST', `field ${key} is required`);
  }
  return String(v);
}

export function argvOf(input: Record<string, unknown>): string[] {
  if (Array.isArray(input.argv)) return (input.argv as unknown[]).map(String);
  if (typeof input.command === 'string') return input.command.trim().split(/\s+/).filter(Boolean);
  throw new KernelError('INVALID_REQUEST', 'one of argv | command is required');
}

export function safeOpen(root: string): Project | null {
  try {
    return Project.open(root);
  } catch {
    return null;
  }
}

export function failedLayers(layers: FlagLayers, detail: Record<string, string | null>): string {
  return Object.entries(layers)
    .filter(([, pass]) => !pass)
    .map(([name]) => `${name}: ${detail[name] ?? 'failed'}`)
    .join('; ');
}

export function imageMime(buf: Buffer): string {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length >= 6 && (buf.subarray(0, 6).toString('ascii') === 'GIF87a' || buf.subarray(0, 6).toString('ascii') === 'GIF89a')) return 'image/gif';
  if (buf.length >= 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  return 'application/octet-stream';
}

export function doctor(project: Project): Record<string, unknown> {
  const file = project.file();
  const audit = auditState(project);
  const issues = [...audit.issues];
  const backendAvailable = file.backend === 'host' || commandExists('docker');
  if (!backendAvailable) issues.push(`backend ${file.backend} unavailable (docker not found)`);
  const tools = doctorTools(envContextOf(project));
  return {
    project: file.id,
    backend: file.backend,
    backendAvailable,
    artifacts: audit.artifacts,
    tools,
    toolsScope: 'env-memory',
    toolsScopeNote: 'from env_memory; use env_memory probe to refresh the current backend',
    issues,
    counters: file.counters,
    limits: { defaultTimeoutMs: DEFAULT_TIMEOUT_MS, maxTimeoutMs: MAX_TIMEOUT_MS },
  };
}
