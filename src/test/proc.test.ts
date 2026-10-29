/** proc observation: session scoping and host backend behavior. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { SessionManager } from '../kernel/session/session.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('proc rejects unknown and malformed session ids', async () => {
  const tp = makeProject();
  try {
    const bad = await dispatch({ op: 'proc', root: tp.root, input: { session: 's9999', action: 'maps' } });
    assert.equal(bad.ok, false);
    assert.equal(!bad.ok && bad.error.code, 'NOT_FOUND');
    const malformed = await dispatch({ op: 'proc', root: tp.root, input: { session: '../x', action: 'maps' } });
    assert.equal(malformed.ok, false);
    assert.equal(!malformed.ok && malformed.error.code, 'INVALID_REQUEST');
  } finally {
    tp.cleanup();
  }
});

test('proc reads a live host session on Linux; fails cleanly on Windows', async () => {
  const tp = makeProject({ backend: 'host' });
  const mgr = new SessionManager(tp.project);
  try {
    const s = mgr.open({ argv: [NODE, '-i'] });
    const res = await dispatch({ op: 'proc', root: tp.root, input: { session: s.id, action: 'maps' } });
    if (process.platform === 'linux') {
      assert.equal(res.ok, true, JSON.stringify(res));
      assert.equal(res.ok && res.data.source, 'host');
      assert.match(res.ok ? String(res.data.text) : '', /\/usr\/|node/);
      assert.ok(fs.existsSync(path.join(tp.root, '.ctf', String(res.ok && res.data.artifact))));
    } else {
      assert.equal(res.ok, false);
      assert.equal(!res.ok && res.error.code, 'UNSUPPORTED');
    }
    // mem without an address is always rejected before touching /proc.
    const mem = await dispatch({ op: 'proc', root: tp.root, input: { session: s.id, action: 'mem' } });
    assert.equal(mem.ok, false);
    assert.equal(!mem.ok && mem.error.code, 'INVALID_REQUEST');
    mgr.close(s.id);
  } finally {
    mgr.closeAll();
    tp.cleanup();
  }
});
