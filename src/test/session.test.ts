/** Session manager tests: open/write/read increments/close, max 4. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';
import { SessionManager } from '../kernel/session/session.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

function settle(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

test('session write/read returns increments; close kills process', async () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const s = mgr.open({ argv: [NODE, '-i'] });
    mgr.write(s.id, 'console.log("one");\n');
    await settle(600);
    const r1 = await mgr.read(s.id, 800);
    assert.match(r1.data, /one/);
    // no new output -> read returns empty increment
    const r2 = await mgr.read(s.id, 300);
    assert.equal(r2.data, '');
    mgr.write(s.id, 'console.log("two");\n');
    await settle(600);
    const r3 = await mgr.read(s.id, 800);
    assert.match(r3.data, /two/);
    assert.ok(!r3.data.includes('one'), 'read must be incremental only');
    mgr.close(s.id);
    assert.throws(() => mgr.write(s.id, 'x'), /not open/);
  } finally {
    tp.cleanup();
  }
});

test('session cwd maps workspace and stays inside the selected root', async () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const s = mgr.open({
      argv: [NODE, '-e', 'console.log(process.cwd())'],
      cwd: 'workspace',
    });
    await settle(500);
    const out = await mgr.read(s.id, 800);
    assert.equal(out.data.trim(), tp.project.workspace);
    mgr.closeAll();
    assert.throws(
      () => mgr.open({ argv: [NODE, '-e', ''], cwd: 'workspace/../escape' }),
      /path escapes/,
    );
  } finally {
    tp.cleanup();
  }
});

test('session max 4 enforced', () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const ids = [];
    for (let i = 0; i < 4; i++) ids.push(mgr.open({ argv: [NODE, '-i'] }).id);
    assert.throws(() => mgr.open({ argv: [NODE, '-i'] }), /max 4 sessions/);
    mgr.close(ids[0]);
    const again = mgr.open({ argv: [NODE, '-i'] });
    assert.ok(again.id);
    mgr.closeAll();
  } finally {
    tp.cleanup();
  }
});

test('session full buffer lands in artifact', async () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const s = mgr.open({ argv: [NODE, '-i'] });
    mgr.write(s.id, 'console.log("artifact-check");\n');
    await settle(600);
    await mgr.read(s.id, 400);
    mgr.close(s.id);
    const buf = fs.readFileSync(`${tp.project.ctfDir}/${s.artifact}`, 'utf8');
    assert.match(buf, /artifact-check/);
  } finally {
    tp.cleanup();
  }
});

test('session program that does not exist -> NOT_FOUND, no crash', () => {
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    assert.throws(
      () => mgr.open({ argv: ['definitely-not-a-real-binary-xyz'] }),
      /session program not found/,
    );
    // manager stays usable afterwards
    const s = mgr.open({ argv: [NODE, '-i'] });
    mgr.close(s.id);
  } finally {
    tp.cleanup();
  }
});

test('session env does not leak host secrets (allowlist only)', async () => {
  process.env.PI4CTF_TEST_SECRET = 'super-secret-value';
  const tp = makeProject();
  try {
    const mgr = new SessionManager(tp.project);
    const s = mgr.open({ argv: [NODE, '-i'] });
    mgr.write(s.id, 'console.log("secret=" + (process.env.PI4CTF_TEST_SECRET ?? "absent"));\n');
    await settle(700);
    const r = await mgr.read(s.id, 900);
    assert.match(r.data, /secret=absent/, 'host env must not leak into sessions');
    assert.match(r.data, /CTF_PROJECT|undefined/); // allowlisted CTF_PROJECT is set
    mgr.close(s.id);
  } finally {
    delete process.env.PI4CTF_TEST_SECRET;
    tp.cleanup();
  }
});
