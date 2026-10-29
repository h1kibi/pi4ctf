/**
 * Allowed roots for artifact.ingest.
 *
 * Evidence produced by external tools (webhooks, browser downloads, /tmp logs)
 * must enter .ctf/artifacts, but the kernel runs on the host even for a Docker
 * case. Without a bound, ingest becomes an arbitrary host-file read: the model
 * could copy the oracle or any readable file into evidence and satisfy the
 * flag chain.
 *
 * Sources are therefore limited to the project workspace and OS temp dirs.
 * PI4CTF_INGEST_ROOTS adds explicit roots (path-list separated by the platform
 * delimiter) for harnesses that capture evidence elsewhere.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { KernelError } from '../error.js';
import type { Project } from '../project.js';

function realpathOf(file: string): string {
  try {
    return fs.realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

function configuredRoots(): string[] {
  const raw = process.env.PI4CTF_INGEST_ROOTS;
  if (!raw) return [];
  return raw.split(path.delimiter).map((root) => root.trim()).filter(Boolean);
}

/** Refuse sources outside the project workspace, OS temp, or configured roots,
 *  and never allow the case oracle or `.ctf/` state to be ingested as evidence. */
export function assertIngestSource(project: Project, source: string): string {
  const resolved = path.resolve(project.root, source);
  const real = realpathOf(resolved);
  const oracleReal = realpathOf(path.resolve(project.root, project.file().oracle.ref));
  if (real === oracleReal) {
    throw new KernelError('SECURITY', 'artifact source is the case oracle; refusing to copy ground truth into evidence');
  }
  const ctfReal = realpathOf(project.ctfDir);
  const inCtf = path.relative(ctfReal, real);
  if (inCtf === '' || (!inCtf.startsWith('..') && !path.isAbsolute(inCtf))) {
    throw new KernelError('SECURITY', 'artifact source must not be inside .ctf/');
  }
  const roots = [
    path.join(project.root, 'workspace'),
    os.tmpdir(),
    ...configuredRoots(),
  ].map(realpathOf);
  const allowed = roots.some((root) => {
    const rel = path.relative(root, real);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
  if (!allowed) {
    throw new KernelError(
      'SECURITY',
      `artifact source must be under the project workspace, the OS temp dir, or PI4CTF_INGEST_ROOTS: ${source}`,
    );
  }
  return real;
}
