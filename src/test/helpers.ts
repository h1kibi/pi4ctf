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

export interface ContainerCase {
  container: string;
  root: string;
  id: string;
  project: Project;
  oraclePath: string;
  flag: string;
  cleanup: () => void;
}

export function makeContainerCases(opts?: {
  flag?: string;
}): { container: string; cases: ContainerCase[]; cleanup: () => void } {
  const flag = opts?.flag ?? 'flag{c0nt41n3r}';
  const container = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-container-'));
  const challenges = path.join(container, 'challenges');
  fs.mkdirSync(challenges, { recursive: true });
  const oraclePath = path.join(challenges, 'oracle.json');
  fs.writeFileSync(
    oraclePath,
    JSON.stringify({ flagSha256: crypto.createHash('sha256').update(flag).digest('hex') }, null, 2),
  );
  const ids = ['20260101-0001', '20260101-0002'];
  const cases = ids.map((id, index) => {
    const root = path.join(challenges, `case-${index + 1}`);
    fs.mkdirSync(root, { recursive: true });
    const project = Project.initCase(
      container,
      root,
      {
        id: `case-${index + 1}`,
        title: `case-${index + 1}`,
        goal: 'hold the flag',
        category: 'misc',
        flagFormat: 'flag\\{[^}]+\\}',
        backend: 'host',
        oracle: { type: 'local', ref: '../oracle.json' },
        allowedHosts: ['*'],
      },
      id,
    );
    return {
      container,
      root,
      id,
      project,
      oraclePath,
      flag,
      cleanup: () => {},
    };
  });
  return {
    container,
    cases,
    cleanup: () => fs.rmSync(container, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }),
  };
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
      // Windows may still hold a directory handle briefly after a child exits.
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
      fs.rmSync(oraclePath, { force: true, maxRetries: 10, retryDelay: 50 });
    },
  };
}
