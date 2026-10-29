/**
 * Guards for artifact.ingest.
 *
 * External evidence (webhook captures, downloads, temporary logs) may live
 * anywhere; ingest exists to copy it into .ctf/artifacts. Two sources are
 * refused because they are kernel-owned truth or state, not evidence: the case
 * oracle, and anything under .ctf/.
 */
import * as fs from 'node:fs';
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

export function assertIngestSource(project: Project, source: string): string {
  const real = realpathOf(path.resolve(project.root, source));
  const oracleReal = realpathOf(path.resolve(project.root, project.file().oracle.ref));
  if (real === oracleReal) {
    throw new KernelError('SECURITY', 'artifact source is the case oracle; refusing to copy ground truth into evidence');
  }
  const ctfReal = realpathOf(project.ctfDir);
  const inCtf = path.relative(ctfReal, real);
  if (inCtf === '' || (!inCtf.startsWith('..') && !path.isAbsolute(inCtf))) {
    throw new KernelError('SECURITY', 'artifact source must not be inside .ctf/');
  }
  return real;
}
