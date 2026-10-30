import * as fs from 'node:fs';
import type { EventRecord, ProjectFile } from './types.js';

export interface LastFormatChange {
  ts: number;
  actor: string;
  flagFormat: string;
}

/** Append an event and update its counters on the caller's project file. */
export function appendEventRecord(
  file: ProjectFile,
  eventsPath: string,
  type: string,
  actor: string,
  payload: Record<string, unknown>,
): EventRecord {
  const seq = (file.counters.event ?? 0) + 1;
  const record: EventRecord = { seq, ts: Date.now(), type, actor, payload };
  fs.appendFileSync(eventsPath, JSON.stringify(record) + '\n');
  file.counters.event = seq;
  file.revisions.event = seq;
  return record;
}

/** Latest flagFormat reconfigure event, best effort for the flag response. */
export function lastFormatChange(eventsPath: string): LastFormatChange | null {
  if (!fs.existsSync(eventsPath)) return null;
  let last: LastFormatChange | null = null;
  for (const line of fs.readFileSync(eventsPath, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as {
        ts?: unknown;
        actor?: unknown;
        type?: unknown;
        payload?: { flagFormat?: unknown };
      };
      if (event.type !== 'project.reconfigure' || typeof event.ts !== 'number' || typeof event.payload?.flagFormat !== 'string') continue;
      last = {
        ts: event.ts,
        actor: typeof event.actor === 'string' ? event.actor : 'adapter',
        flagFormat: event.payload.flagFormat,
      };
    } catch {
      // Audit is best effort; a truncated event line must not block flag validation.
    }
  }
  return last;
}
