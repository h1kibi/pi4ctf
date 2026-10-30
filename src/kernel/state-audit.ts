import * as fs from 'node:fs';
import * as path from 'node:path';
import { Project } from './project.js';

export interface StateAudit {
  artifacts: { files: number; bytes: number };
  issues: string[];
}

/** Kernel-owned checks for .ctf state layout and integrity. */
export function auditState(project: Project): StateAudit {
  const issues: string[] = [];
  for (const dir of ['.', 'artifacts', 'outcomes', 'claims', 'facts', 'negatives']) {
    const abs = dir === '.' ? project.ctfDir : path.join(project.ctfDir, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs)) {
      if (name.startsWith('.tmp-')) issues.push(`stale tmp: ${dir}/${name}`);
    }
  }
  for (const dir of ['outcomes', 'claims', 'facts', 'negatives', 'items']) {
    const abs = path.join(project.ctfDir, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs)) {
      if (!name.endsWith('.json')) continue;
      try {
        JSON.parse(fs.readFileSync(path.join(abs, name), 'utf8'));
      } catch {
        issues.push(`unreadable json: ${dir}/${name}`);
      }
    }
  }
  const artifactsDir = path.join(project.ctfDir, 'artifacts');
  const artifacts = { files: 0, bytes: 0 };
  if (fs.existsSync(artifactsDir)) {
    for (const entry of fs.readdirSync(artifactsDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      artifacts.files += 1;
      artifacts.bytes += fs.statSync(path.join(artifactsDir, entry.name)).size;
    }
  }
  const lockPath = path.join(project.ctfDir, '.lock');
  if (fs.existsSync(lockPath)) {
    try {
      const info = JSON.parse(fs.readFileSync(lockPath, 'utf8')) as { pid?: number; ts?: number };
      if (typeof info.ts === 'number' && Date.now() - info.ts > 120_000) issues.push('stale lock');
    } catch {
      issues.push('unreadable lock');
    }
  }
  return { artifacts, issues };
}
