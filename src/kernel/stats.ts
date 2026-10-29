/** Cross-case solve-time hints. JSONL, no database, best-effort. */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Project } from './project.js';

export interface SolveStat {
  category: string;
  runs: number;
  restarts: number;
  ts: number;
}

function statsPath(): string {
  return process.env.PI4CTF_STATS_PATH ?? path.join(os.homedir(), '.pi4ctf', 'solve-stats.jsonl');
}

function readStats(): SolveStat[] {
  try {
    const text = fs.readFileSync(statsPath(), 'utf8');
    const rows: SolveStat[] = [];
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as SolveStat;
        if (typeof parsed.category === 'string' && Number.isFinite(parsed.runs) && parsed.runs > 0) rows.push(parsed);
      } catch {
        // A torn line must not hide the rest of the baseline.
      }
    }
    return rows.slice(-200);
  } catch {
    return [];
  }
}

/** Record only a completed, flag-accepted case; failed closes are not solves. */
export function recordSolve(project: Project, flagAccepted: boolean): void {
  if (!flagAccepted) return;
  const file = project.file();
  const outcomes = path.join(project.ctfDir, 'outcomes');
  let runs = 0;
  try {
    runs = fs.readdirSync(outcomes).filter((name) => /^cmd-\d+\.json$/.test(name)).length;
  } catch {
    return;
  }
  if (runs === 0) return;
  const row: SolveStat = {
    category: file.category,
    runs,
    restarts: file.counters.restart ?? 0,
    ts: Date.now(),
  };
  try {
    const target = statsPath();
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.appendFileSync(target, JSON.stringify(row) + '\n');
  } catch {
    // Hints are optional; never fail a completed case because telemetry is unavailable.
  }
}

export function categoryMedian(category: string): { median: number; n: number } | null {
  const values = readStats()
    .filter((row) => row.category === category)
    .map((row) => row.runs)
    .sort((a, b) => a - b);
  if (values.length === 0) return null;
  const mid = Math.floor(values.length / 2);
  const median = values.length % 2 === 0
    ? Math.round(((values[mid - 1] ?? 0) + (values[mid] ?? 0)) / 2)
    : values[mid] ?? 0;
  return { median, n: values.length };
}
