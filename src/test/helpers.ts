/** Shared test helpers: temp challenge projects with local oracle. */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Project } from '../kernel/project.js';
import type { TargetSpec } from '../kernel/types.js';

export interface TestProject {
  root: string;
  project: Project;
  oraclePath: string;
  flag: string;
  cleanup: () => void;
}

export function makeProject(opts?: {
  backend?: 'host' | 'docker';
  dockerImage?: string;
  allowedHosts?: string[];
  flag?: string;
  target?: TargetSpec;
  flagFormat?: string;
}): TestProject {
  const flag = opts?.flag ?? 'flag{t3st_r00m_gl4d}';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-'));
  // oracle lives OUTSIDE the challenge workspace (kernel-design §8)
  const oraclePath = path.join(path.dirname(root), `${path.basename(root)}-oracle.json`);
  const oracle: Record<string, unknown> = { flagSha256: crypto.createHash('sha256').update(flag).digest('hex') };
  if (opts?.target) {
    oracle.target = opts.target;
    oracle.expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  }
  fs.writeFileSync(oraclePath, JSON.stringify(oracle, null, 2));
  const project = Project.init(root, {
    id: `test-${path.basename(root)}`,
    title: 'test-challenge',
    goal: '拿到 flag 并验证',
    category: 'web',
    flagFormat: opts?.flagFormat ?? 'flag\\{[^}]+\\}',
    backend: opts?.backend ?? 'host',
    dockerImage: opts?.dockerImage,
    target: opts?.target,
    oracle: { type: 'local', ref: path.relative(root, oraclePath) },
    allowedHosts: opts?.allowedHosts ?? ['*'],
  });
  return {
    root,
    project,
    oraclePath,
    flag,
    cleanup: () => {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(oraclePath, { force: true });
    },
  };
}
