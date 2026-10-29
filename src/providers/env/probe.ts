/** Generic, table-driven environment probing through the project backend. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KernelError } from '../../kernel/error.js';
import { runInternal } from '../../kernel/run/exec.js';
import type { EnvContext } from './context.js';
import { PROBE_TABLE, probeFor } from './table.js';
import { isToolId, loadStore, recordAbsent, recordProbe } from './store.js';

export interface ProbeOutcome {
  id: string;
  path: string;
  version: string | null;
  absent: boolean;
  requested?: string;
  actualId?: string;
  reason?: string;
  source?: 'user' | 'probe';
  pathSource?: 'user' | 'probe';
  versionSource?: 'user' | 'probe' | null;
  onPath?: boolean | null;
  declaredPathExists?: boolean | null;
  resolvedPath?: string;
  wrapperPath?: string;
  wrapperTargetMissing?: boolean;
  wrapperCwd?: string;
  wrapperSemanticsUnknown?: boolean;
  pathRepaired?: boolean;
}

interface Candidate {
  path: string;
  mode: 'direct' | 'cmd' | 'script';
  interpreter?: string;
  wrapperTargetMissing?: boolean;
  wrapperCwd?: string;
  wrapperSemanticsUnknown?: boolean;
  fromPath?: boolean;
}

function wrapperTarget(file: string): { missing: boolean; cwd?: string; semanticsUnknown: boolean } {
  try {
    const text = fs.readFileSync(file, 'utf8').slice(0, 4096);
    const match = /[A-Za-z]:\\[^"'\r\n]+?\.(?:bat|exe|cmd)/i.exec(text);
    const cd = /\bcd(?:\s+\/d)?\s+(?:"([^"]+)"|([^\r\n&]+))/i.exec(text);
    let cwd: string | undefined;
    if (cd) {
      const raw = (cd[1] ?? cd[2] ?? '').trim();
      if (raw) {
        const expanded = raw.replace(/%~dp0[\\/]?/gi, `${path.dirname(file)}${path.sep}`);
        cwd = path.resolve(path.dirname(file), expanded);
      }
    }
    const semanticsUnknown = /\b(?:set|start|pushd|popd|cd)\b/i.test(text);
    return {
      missing: match ? !fs.existsSync(match[0]) : false,
      ...(cwd ? { cwd } : {}),
      semanticsUnknown: semanticsUnknown && !cwd,
    };
  } catch {
    return { missing: false, semanticsUnknown: true };
  }
}

function wrapperCandidate(file: string, fromPath: boolean): Candidate {
  const meta = wrapperTarget(file);
  return {
    path: file,
    mode: 'cmd',
    ...(meta.missing ? { wrapperTargetMissing: true } : {}),
    ...(meta.cwd ? { wrapperCwd: meta.cwd } : {}),
    ...(meta.semanticsUnknown ? { wrapperSemanticsUnknown: true } : {}),
    fromPath,
  };
}

function extensionlessCandidate(file: string): Candidate | null {
  try {
    const first = fs.readFileSync(file, 'utf8').split(/\r?\n/, 1)[0] ?? '';
    const match = /^#!\s*(?:"([^"]+)"|(\S+))/.exec(first);
    const interpreter = match?.[1] ?? match?.[2];
    if (!interpreter) return null;
    // On Windows, POSIX shell shims are not the real tool; prefer the .bat/.cmd
    // candidate that follows in PATH.
    if (/^(?:\/bin\/|\/usr\/bin\/env(?:\s|$))/.test(interpreter)) return null;
    return { path: file, mode: 'script', interpreter };
  } catch {
    return null;
  }
}

function selectCandidates(value: string, hostWindows: boolean): Candidate[] {
  const lines = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!hostWindows) return lines.map((line) => ({ path: line, mode: 'direct' as const, fromPath: true }));
  const candidates: Candidate[] = [];
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.endsWith('.exe')) candidates.push({ path: line, mode: 'direct', fromPath: true });
    else if (lower.endsWith('.bat') || lower.endsWith('.cmd')) {
      candidates.push(wrapperCandidate(line, true));
    } else if (!lower.includes('.')) {
      const script = extensionlessCandidate(line);
      if (script) candidates.push({ ...script, fromPath: true });
    }
  }
  return candidates;
}

function candidateFromPath(file: string, hostWindows: boolean, containerPath = false): Candidate | null {
  if (!containerPath) {
    try {
      if (!fs.statSync(file).isFile()) return null;
    } catch {
      return null;
    }
  }
  if (!hostWindows) return { path: file, mode: 'direct', fromPath: false };
  const lower = file.toLowerCase();
  if (lower.endsWith('.cmd') || lower.endsWith('.bat')) {
    return wrapperCandidate(file, false);
  }
  if (lower.endsWith('.exe')) return { path: file, mode: 'direct', fromPath: false };
  const script = extensionlessCandidate(file);
  return script ? { ...script, fromPath: false } : { path: file, mode: 'direct', fromPath: false };
}

function versionArgv(candidate: Candidate, args: string[]): string[] {
  if (candidate.mode === 'cmd') return ['cmd.exe', '/d', '/s', '/c', candidate.path, ...args];
  if (candidate.mode === 'script' && candidate.interpreter) return [candidate.interpreter, candidate.path, ...args];
  return [candidate.path, ...args];
}

function versionOf(ctx: EnvContext, entry: { versionRe: RegExp }, candidate: Candidate, args: string[]): Promise<string | null> {
  return runInternal(ctx.host, { argv: versionArgv(candidate, args), timeoutMs: 5_000 }).then((run) => {
    if (run.exit !== 0) return null;
    const text = run.stdout.trim() ? run.stdout : run.stderr;
    return entry.versionRe.exec(text)?.[1] ?? null;
  }).catch(() => null);
}

function pythonModuleVersion(ctx: EnvContext, module: string, candidate: Candidate): Promise<string | null> {
  const code = `import ${module}; v=getattr(${module},"__version__",None) or getattr(${module},"version",None) or getattr(getattr(${module},"pwnlib",None),"version",None); print(getattr(v,"__version__",v) or "")`;
  return runInternal(ctx.host, { argv: versionArgv(candidate, ['-c', code]), timeoutMs: 5_000 }).then((run) => {
    if (run.exit !== 0) return null;
    return /(\d+\.\d+(?:\.\d+)?)/.exec(run.stdout)?.[1] ?? null;
  }).catch(() => null);
}

export async function probeTools(ctx: EnvContext, ids?: string[]): Promise<ProbeOutcome[]> {
  if (ids?.some((id) => !isToolId(id))) throw new KernelError('INVALID_REQUEST', 'invalid probe id');
  const selected: Array<{ entry: ReturnType<typeof probeFor>; requested?: string }> = ids && ids.length > 0
    ? ids.map((id) => ({ entry: probeFor(id), requested: id }))
    : [...new Map([
        ...PROBE_TABLE,
        ...Object.keys(loadStore(ctx).tools).map((id) => probeFor(id)),
      ].map((entry) => [entry.id, entry] as const)).values()].map((entry) => ({ entry }));

  const outcomes: ProbeOutcome[] = [];
  const storeBefore = loadStore(ctx);
  const backend = ctx.host.backend;
  const hostWindows = backend === 'host' && process.platform === 'win32';
  for (const { entry, requested } of selected) {
    const declared = requested
      ? storeBefore.tools[requested]
      : storeBefore.tools[entry.id] ?? storeBefore.tools[entry.id.split('@')[0] ?? entry.id];
    const declaredCandidate = declared ? candidateFromPath(declared.realpath, hostWindows, backend === 'docker') : null;
    const candidates: Candidate[] = declaredCandidate ? [declaredCandidate] : [];
    for (const binary of entry.binaries) {
      const result = await runInternal(ctx.host, {
        command: hostWindows ? `where ${binary}` : `command -v ${binary}`,
        timeoutMs: 3_000,
      });
      if (result.exit === 0) {
        const found = selectCandidates(result.stdout, hostWindows);
        for (const candidate of found) {
          const existing = candidates.find((value) => value.path.toLowerCase() === candidate.path.toLowerCase());
          if (existing) existing.fromPath = true;
          else candidates.push(candidate);
        }
        if (found.length > 0) break;
      }
    }
    if (candidates.length === 0) {
      const absentId = requested ?? entry.id;
      const declared = storeBefore.tools[absentId] ?? storeBefore.tools[entry.id] ?? storeBefore.tools[entry.id.split('@')[0] ?? entry.id];
      const declaredPathExists = declared
        ? (backend === 'host' ? fs.existsSync(declared.realpath) : null)
        : null;
      recordAbsent(ctx, absentId, 'not-found');
      outcomes.push({
        id: absentId,
        path: declared?.path ?? '',
        version: declared?.version ?? null,
        absent: true,
        source: declared?.source,
        pathSource: declared?.pathSource,
        versionSource: declared?.versionSource ?? (declared?.version ? declared.source : null),
        onPath: false,
        declaredPathExists,
        ...(requested ? { requested } : {}),
      });
      continue;
    }

    let chosen: Candidate | null = null;
    let version: string | null = null;
    if (entry.pythonModule) {
      for (const candidate of candidates) {
        version = await pythonModuleVersion(ctx, entry.pythonModule, candidate);
        if (version) { chosen = candidate; break; }
      }
    } else {
      for (const candidate of candidates) {
        for (const args of entry.versionArgs) {
          version = await versionOf(ctx, entry, candidate, args);
          if (version) break;
        }
        if (version) { chosen = candidate; break; }
      }
    }
    if (requested && declaredCandidate && chosen?.path !== declaredCandidate.path) {
      chosen = declaredCandidate;
      version = null;
    }
    if (!chosen) {
      chosen = candidates.find((candidate) => candidate.path.toLowerCase().endsWith('.bat')) ?? candidates[0] ?? null;
      version = null;
    }
    if (!chosen) {
      recordAbsent(ctx, requested ?? entry.id);
      outcomes.push({ id: requested ?? entry.id, path: '', version: null, absent: true, ...(requested ? { requested } : {}) });
      continue;
    }

    const first = candidates[0]!;
    const pathRepaired = chosen.path !== first.path;
    const wrapperPath = chosen.mode === 'cmd' ? chosen.path : (pathRepaired ? first.path : undefined);
    const wrapperTargetMissing = Boolean(chosen.wrapperTargetMissing || (pathRepaired && first.wrapperTargetMissing));
    const wrapperCwd = chosen.wrapperCwd ?? (pathRepaired ? first.wrapperCwd : undefined);
    const wrapperSemanticsUnknown = Boolean(chosen.wrapperSemanticsUnknown || (pathRepaired && first.wrapperSemanticsUnknown));
    const resolvedPath = chosen.path;
    const declaredPathExists = declared ? (backend === 'host' ? fs.existsSync(declared.realpath) : null) : null;
    const onPath = candidates.some((candidate) => candidate.fromPath === true && candidate.path === chosen.path);
    const major = version && entry.major ? entry.major(version) : null;
    const requestedMajor = requested && /@([0-9]+)$/.exec(requested)?.[1];
    const actualId = major ? `${entry.id}@${major}` : entry.id;
    const id = requestedMajor ? requested : actualId;
    let realpath = chosen.path;
    if (backend === 'host') {
      try {
        realpath = fs.realpathSync(chosen.path);
      } catch {
        realpath = chosen.path;
      }
    }
    const javaHome = entry.id === 'jdk' && path.basename(path.dirname(chosen.path)).toLowerCase() === 'bin'
      ? path.dirname(path.dirname(chosen.path))
      : undefined;
    if (requestedMajor && major !== null && Number(requestedMajor) !== major) {
      recordAbsent(ctx, requested, 'major-mismatch', { id, version });
      outcomes.push({
        id: requested,
        path: '',
        version: null,
        absent: true,
        requested,
        actualId,
        reason: 'major-mismatch',
      });
      continue;
    }
    const stored = recordProbe(ctx, id, {
      path: chosen.path,
      realpath,
      version,
      ...(wrapperPath ? { wrapperPath } : {}),
      ...(wrapperTargetMissing ? { wrapperTargetMissing: true } : {}),
      ...(wrapperCwd ? { wrapperCwd } : {}),
      ...(wrapperSemanticsUnknown ? { wrapperSemanticsUnknown: true } : {}),
      ...(pathRepaired ? { pathRepaired: true, resolvedPath } : {}),
      onPath,
      ...(javaHome ? { env: { JAVA_HOME: javaHome } } : {}),
      sig: backend === 'host' ? (() => {
        try {
          const st = fs.statSync(realpath);
          return { size: st.size, mtimeMs: st.mtimeMs };
        } catch {
          return null;
        }
      })() : null,
    });
    outcomes.push({
      id,
      path: stored.path,
      version: stored.version,
      absent: false,
      source: stored.source,
      pathSource: stored.pathSource,
      versionSource: stored.versionSource,
      onPath: stored.onPath,
      resolvedPath: stored.resolvedPath,
      wrapperPath: stored.wrapperPath,
      wrapperTargetMissing: stored.wrapperTargetMissing,
      wrapperCwd: stored.wrapperCwd,
      wrapperSemanticsUnknown: stored.wrapperSemanticsUnknown,
      pathRepaired: stored.pathRepaired,
      declaredPathExists,
      ...(requested ? { requested } : {}),
    });
  }
  return outcomes;
}
