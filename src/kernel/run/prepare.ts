/**
 * Host/Docker launch preparation (docs/design.md §4.1, ADR 0002 §1).
 *
 * This module maps a logical RunRequest to the actual argv/env/cwd used by
 * the execution engine. It does not spawn, classify, or write evidence.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { KernelError } from '../error.js';
import { resolveInside } from '../fsutil.js';
import { targetOf } from '../classify/classify.js';
import { commandExists, resolveBash } from '../sysutil.js';
import { mergeEnv } from '../target.js';
import type { TargetSpec } from '../types.js';

export interface RunRequest {
  argv?: string[];
  command?: string;
  shell?: 'bash' | 'powershell';
  cwd?: string; // relative to project root
  timeoutMs?: number;
  stdin?: string;
  /** Explicit target for attribution/scope; defaults to project.target. */
  target?: TargetSpec | null;
  /** Extra environment; merged after target-derived HOST/PORT/TARGET. */
  env?: Record<string, unknown>;
  /** Adapter TCP precheck when a target was declared; null = not checked. */
  targetReachable?: boolean | null;
  targetCheckMs?: number | null;
  /** Dry-run/experiment marker; propagated to claims/facts where possible. */
  synthetic?: boolean;
  /** Internal kernel probes may carry expectOutput from the contract. */
  actor?: string;
}

/** Minimal launch context: where to run and on which backend. Internal
 *  (non-evidence) probes need only this, not a full challenge Project. */
export interface ExecHost {
  root: string;
  ctfDir: string;
  backend: 'host' | 'docker';
  dockerImage?: string;
  target: TargetSpec | null;
}

export interface Prepared {
  /** Actual argv to spawn (may include docker/shell wrapper). */
  argv: string[];
  /** The logical user command; signature@1, target and scope derive from
   *  this — never from the wrapper (review R1). */
  userArgv: string[];
  cwd: string;
  shell: string | null;
  /** Target derived from the unstripped command (inline HOST/PORT). */
  targetHint?: string | null;
  /** Extra environment for host launches. Docker uses -e flags instead. */
  env: Record<string, string>;
  /** Temporary command script; removed after the run. */
  tempFile?: string;
}

/** Shell command mode often carries target/config as leading assignments:
 *  `HOST=... PORT=... python exp.py`. Those values belong in env/target
 *  metadata, not the route signature, otherwise the same exploit in argv mode
 *  gets a different canonicalKey. */
function stripLeadingEnvAssignments(argv: string[]): string[] {
  let i = 0;
  while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i] ?? '')) i++;
  return i === 0 ? argv : argv.slice(i);
}

export function prepareHost(host: ExecHost, req: RunRequest): Prepared {
  const root = host.root;
  let argv: string[];
  let userArgv: string[];
  let shell: string | null = null;
  let tempFile: string | undefined;
  let targetHint: string | null = null;
  if (req.argv) {
    argv = req.argv.map(String);
    userArgv = argv;
  } else if (req.command) {
    // POSIX command semantics: bash is required. PowerShell corrupts curl
    // flags (Invoke-WebRequest alias) and mis-signs the run (review R1);
    // it stays available only when explicitly requested.
    if (req.shell === 'powershell') {
      argv = ['powershell', '-NoProfile', '-NonInteractive', '-Command', req.command];
      shell = 'powershell';
    } else {
      const bash = resolveBash();
      if (!commandExists(bash)) {
        throw new KernelError(
          'UNSUPPORTED',
          'command mode requires bash on PATH (Git Bash/WSL); use argv mode or install bash',
        );
      }
      // Never put the command text on bash's argv. WSL's bash.exe expands
      // `$var` in argv before Linux sees it, so loops/heredocs silently lose
      // their variables. A temp script keeps the command byte-for-byte.
      const cwd = req.cwd ? resolveInside(root, req.cwd) : root;
      if (!fs.existsSync(cwd)) fs.mkdirSync(cwd, { recursive: true });
      const scriptPath = path.join(host.ctfDir, `.run-${randomUUID()}.sh`);
      fs.writeFileSync(scriptPath, req.command, 'utf8');
      const scriptRel = path.relative(cwd, scriptPath).split(path.sep).join('/');
      argv = [bash, '-l', scriptRel];
      tempFile = scriptPath;
      shell = 'bash';
    }
    userArgv = stripLeadingEnvAssignments(req.command.trim().split(/\s+/).filter(Boolean));
  } else {
    throw new KernelError('INVALID_REQUEST', 'one of argv | command is required');
  }
  const cwd = req.cwd ? resolveInside(root, req.cwd) : root;
  if (!fs.existsSync(cwd)) fs.mkdirSync(cwd, { recursive: true });
  return { argv, userArgv, cwd, shell, tempFile, targetHint: targetHint ?? targetOf(userArgv), env: mergeEnv(req.target ?? host.target, req.env) };
}

export function prepareDocker(host: ExecHost, req: RunRequest): Prepared {
  const image = host.dockerImage;
  if (!image) {
    throw new KernelError('UNSUPPORTED', 'docker backend requires dockerImage in project.json');
  }
  const root = host.root;
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace, { recursive: true });
  let userArgv: string[];
  let targetHint: string | null = null;
  if (req.argv) {
    userArgv = req.argv.map(String);
  } else if (req.command) {
    const rawArgv = req.command.trim().split(/\s+/).filter(Boolean);
    targetHint = targetOf(rawArgv);
    userArgv = stripLeadingEnvAssignments(rawArgv);
  } else {
    throw new KernelError('INVALID_REQUEST', 'one of argv | command is required');
  }
  // The image entrypoint is empty (sandbox/Dockerfile.kali), so argv runs
  // directly; shell commands wrap in bash inside the container.
  const inner = req.command ? ['bash', '-lc', req.command] : userArgv;
  const envFlags: string[] = [];
  for (const [key, value] of Object.entries(mergeEnv(req.target ?? host.target, req.env))) {
    envFlags.push('-e', `${key}=${value}`);
  }
  const argv = [
    'docker',
    'run',
    '--rm',
    '--network',
    'bridge',
    '--cap-add',
    'SYS_PTRACE',
    '-e',
    'TERM=xterm',
    '-e',
    'PYTHONUNBUFFERED=1',
    ...envFlags,
    '-v',
    `${root}:/challenge:ro`,
    '-v',
    `${workspace}:/challenge/workspace:rw`,
    '-w',
    '/challenge/workspace',
    image,
    ...inner,
  ];
  return { argv, userArgv, cwd: root, shell: req.command ? 'bash' : null, targetHint: targetHint ?? targetOf(userArgv), env: {} };
}
