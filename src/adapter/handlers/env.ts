import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { KernelError } from '../../kernel/error.js';
import { Project } from '../../kernel/project.js';
import { forget as forgetEnv, recall as recallEnv, remember as rememberEnv, recordNote, type RecallQuery } from '../../providers/env/store.js';
import { envSummary } from '../../providers/env/summary.js';
import { probeTools } from '../../providers/env/probe.js';
import { envContextOf, type EnvContext } from '../../providers/env/context.js';
import { projectRecords } from '../../providers/env/query.js';
import type { Request, Response } from '../types.js';
import { ok, str } from '../helpers.js';

/** Environment memory is environment-scoped, not challenge-scoped: image and
 *  rootless probes run from a shared temp dir so `docker run` never creates a
 *  workspace directory in the user's current/challenge directory. */
function envContextFor(root: string | undefined, image: string | undefined): EnvContext {
  if (!image && root && fs.existsSync(path.join(root, '.ctf', 'project.json'))) {
    return envContextOf(Project.open(root));
  }
  const ctfDir = path.join(os.tmpdir(), 'pi4ctf-env-probe');
  fs.mkdirSync(ctfDir, { recursive: true });
  const base = image ? ctfDir : path.resolve(root ?? process.cwd());
  return {
    host: { root: base, ctfDir, backend: image ? 'docker' : 'host', ...(image ? { dockerImage: image } : {}), target: null },
    origin: 'env',
    protectedRoot: base,
  };
}

export async function handleEnv(req: Request, op: string, input: Record<string, unknown>): Promise<Response> {
  switch (op) {
    case 'env.memory': {
      const image = input.image === undefined ? undefined : String(input.image);
      const ctx = envContextFor(req.root, image);
      const action = str(input, 'action');
      if (action === 'recall') {
        const query: RecallQuery = {
          id: input.id === undefined ? undefined : String(input.id),
          ids: Array.isArray(input.ids) ? (input.ids as unknown[]).map(String) : undefined,
          capability: input.capability === undefined ? undefined : String(input.capability),
          origin: input.origin === undefined ? undefined : String(input.origin),
        };
        const filtered = query.id !== undefined || query.ids !== undefined || query.capability !== undefined || query.origin !== undefined;
        const withSummary = input.includeSummary === true ? { summary: envSummary(ctx) } : {};
        if (input.records !== true && input.detailed !== true && !filtered) {
          const result = recallEnv(ctx, query);
          return ok(op, { env: result.env, envKey: result.envKey, records: result.records, summary: envSummary(ctx) });
        }
        if (input.detailed === true) {
          return ok(op, { ...recallEnv(ctx, query), ...withSummary });
        }
        const budget = Number(input.maxChars);
        const maxChars = Number.isFinite(budget)
          ? Math.min(20_000, Math.max(500, budget))
          : (input.records === true ? Number.POSITIVE_INFINITY : 2_000);
        return ok(op, { ...projectRecords(ctx, query, maxChars), ...withSummary });
      }
      if (action === 'probe' || action === 'refresh') {
        const ids = Array.isArray(input.ids) ? (input.ids as unknown[]).map(String) : undefined;
        return ok(op, { outcomes: await probeTools(ctx, ids) });
      }
      if (action === 'remember') {
        const tool = rememberEnv(ctx, {
          id: str(input, 'id'),
          path: str(input, 'path'),
          version: input.version === undefined ? null : String(input.version),
          env: input.env && typeof input.env === 'object'
            ? { JAVA_HOME: (input.env as Record<string, unknown>).JAVA_HOME ? String((input.env as Record<string, unknown>).JAVA_HOME) : undefined }
            : undefined,
        });
        return ok(op, { tool, source: 'user' });
      }
      if (action === 'forget') {
        const ids = Array.isArray(input.ids)
          ? (input.ids as unknown[]).map(String)
          : input.id === undefined
            ? (() => { throw new KernelError('INVALID_REQUEST', 'forget requires id or ids'); })()
            : [String(input.id)];
        const removedIds = ids.filter((id) => forgetEnv(ctx, id));
        return ok(op, { removed: removedIds.length > 0, removedIds });
      }
      if (action === 'note') {
        return ok(op, { note: recordNote(ctx, str(input, 'text')) });
      }
      throw new KernelError('INVALID_REQUEST', 'env.memory action must be recall/probe/remember/forget/note');
    }
    default:
      throw new KernelError('INVALID_REQUEST', `unexpected env op: ${op}`);
  }
}
