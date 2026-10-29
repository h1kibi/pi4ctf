/** Environment memory: host-scoped tool records, validation, and summary. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { compilePacket } from '../kernel/context/packet.js';
import { dispatch } from '../adapter/protocol.js';
import { Ledger } from '../kernel/ledger/store.js';
import { execHostOf, runInternal } from '../kernel/run/exec.js';
import { envContextOf } from '../providers/env/context.js';
import { envSummary } from '../providers/env/summary.js';
import {
  envKey,
  forget,
  recall,
  recordAbsent,
  recordNote,
  recordProbe,
  remember,
  storePath,
} from '../providers/env/store.js';
import { makeProject } from './helpers.js';

const NODE = process.execPath;

test('environment memory starts empty and remembers JDK toolchains without paths in the summary', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-home-'));
  const oldHome = process.env.PI4CTF_HOME;
  const oldNs = process.env.PI4CTF_USER_NS;
  process.env.PI4CTF_HOME = home;
  process.env.PI4CTF_USER_NS = 'test-user';
  const tp = makeProject();
  try {
    assert.deepEqual(recall(envContextOf(tp.project)).tools, []);
    assert.match(envKey(envContextOf(tp.project)), /^host\//);
    assert.ok(storePath(envContextOf(tp.project)).includes(path.join(home, 'envs', 'test-user')));

    remember(envContextOf(tp.project), { id: 'jdk@8', path: NODE, version: '1.8.0_202' });
    remember(envContextOf(tp.project), { id: 'jdk@21', path: NODE, version: '21.0.5' });
    const result = recall(envContextOf(tp.project), { capability: 'java' });
    assert.deepEqual(result.tools.map((tool) => tool.id).sort(), ['jdk@21', 'jdk@8']);
    assert.equal(result.tools[0]?.source, 'user');
    assert.equal(result.tools[0]?.status, 'unverified');

    const summary = envSummary(envContextOf(tp.project));
    assert.match(summary, /jdk@8/);
    assert.match(summary, /jdk@21/);
    assert.ok(!summary.includes(NODE), 'summary must not expose tool paths');

    const packet = compilePacket(tp.project, new Ledger(tp.project), { envSummary: summary });
    assert.match(packet.text, /## Environment memory/);
    assert.ok(!packet.text.includes(NODE), 'packet must not expose tool paths');

    const remembered = await dispatch({
      op: 'env.memory',
      root: tp.root,
      input: { action: 'remember', id: 'jdk@11', path: NODE, version: '11.0.2' },
    });
    assert.equal(remembered.ok, true, JSON.stringify(remembered));
    const recalled = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', id: 'jdk@11' } });
    assert.equal(recalled.ok, true, JSON.stringify(recalled));
    assert.match(JSON.stringify(recalled), /jdk@11/);
    const forgotten = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'forget', id: 'jdk@11' } });
    assert.equal(forgotten.ok, true, JSON.stringify(forgotten));
    assert.equal(recall(envContextOf(tp.project), { id: 'jdk' }).tools.length, 2, 'base id recall must match @major records');

    const budgetBefore = tp.project.file().counters.command;
    const probe = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['jdk'] } });
    assert.equal(probe.ok, true, JSON.stringify(probe));
    assert.equal(tp.project.file().counters.command, budgetBefore, 'probe must not consume the run budget');

    const generic = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['not-a-real-tool'] } });
    assert.equal(generic.ok, true, JSON.stringify(generic));
    const outcomes = generic.ok ? (generic.data.outcomes as Array<{ absent: boolean }>) : [];
    assert.equal(outcomes[0]?.absent, true);

    recordAbsent(envContextOf(tp.project), 'jadx');
    assert.ok(recall(envContextOf(tp.project)).absent.some((item) => item.id === 'jadx'));
    assert.equal(forget(envContextOf(tp.project), 'jdk@8'), true);
    assert.equal(recall(envContextOf(tp.project), { id: 'jdk@8' }).tools.length, 0);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    if (oldNs === undefined) delete process.env.PI4CTF_USER_NS;
    else process.env.PI4CTF_USER_NS = oldNs;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('environment memory rejects relative paths and bad JAVA_HOME', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-invalid-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    assert.throws(() => remember(envContextOf(tp.project), { id: 'jdk@8', path: 'bin/java' }), /absolute/);
    assert.throws(() => remember(envContextOf(tp.project), {
      id: 'jdk@8',
      path: NODE,
      env: { JAVA_HOME: path.join(path.dirname(NODE), 'other') },
    }), /ancestor/);
    assert.throws(() => remember(envContextOf(tp.project), { id: 'Bad Id', path: NODE }), /invalid tool id/);
    const inside = path.join(tp.root, 'tool.exe');
    fs.writeFileSync(inside, 'x');
    assert.throws(() => remember(envContextOf(tp.project), { id: 'jdk@8', path: inside }), /outside the challenge/);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('environment keys separate host and docker and internal probes do not consume a slot', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-keys-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const host = makeProject({ backend: 'host' });
  const docker = makeProject({ backend: 'docker', dockerImage: 'example:test' });
  try {
    assert.match(envKey(envContextOf(host.project)), /^host\//);
    assert.match(envKey(envContextOf(docker.project)), /^docker\/example:test$/);
    assert.notEqual(storePath(envContextOf(host.project)), storePath(envContextOf(docker.project)));

    const before = host.project.file().counters.command;
    const probe = await runInternal(execHostOf(host.project), { argv: [NODE, '-e', 'console.log("probe")'] });
    assert.equal(probe.exit, 0);
    assert.equal(host.project.file().counters.command, before, 'internal probe must not charge the budget');

    recordProbe(envContextOf(host.project), 'jdk@8', {
      path: NODE,
      realpath: NODE,
      version: '1.8.0_202',
      sig: { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs },
    });
    assert.equal(recall(envContextOf(host.project), { id: 'jdk@8' }).tools[0]?.status, 'verified');
    remember(envContextOf(host.project), { id: 'jdk@8', path: NODE, version: '1.8.0_202' });
    recordProbe(envContextOf(host.project), 'jdk@8', {
      path: NODE,
      realpath: NODE,
      version: null,
      sig: { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs },
    });
    assert.equal(recall(envContextOf(host.project), { id: 'jdk@8' }).tools[0]?.version, '1.8.0_202', 'null probe version must not erase prior version');
    assert.equal(recall(envContextOf(host.project), { id: 'jdk@8' }).tools[0]?.versionSource, 'user');
    assert.equal(typeof recall(envContextOf(host.project), { id: 'jdk@8' }).tools[0]?.declaredAt, 'number');
    assert.equal(recall(envContextOf(docker.project), { id: 'jdk@8' }).tools.length, 0, 'docker must not see host memory');
  } finally {
    host.cleanup();
    docker.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('probe absence preserves known tools; forget removes all versions', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-versions-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'jdk@8', path: NODE, version: '1.8.0_202' });
    remember(envContextOf(tp.project), { id: 'jdk@21', path: NODE, version: '21.0.5' });
    recordAbsent(envContextOf(tp.project), 'jdk');
    assert.equal(recall(envContextOf(tp.project), { id: 'jdk' }).tools.length, 2, 'probe absence must not delete known tools');
    assert.equal(recall(envContextOf(tp.project), { id: 'jdk' }).absent.length, 0, 'a known family member suppresses a base-id absent');
    recordAbsent(envContextOf(tp.project), 'zzztest');
    assert.ok(recall(envContextOf(tp.project), { id: 'zzztest' }).absent.some((item) => item.id === 'zzztest'));
    assert.equal(forget(envContextOf(tp.project), 'jdk'), true);
    assert.equal(recall(envContextOf(tp.project), { id: 'jdk' }).tools.length, 0);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('accepts compiler/uppercase ids, spaced versions, and docker POSIX paths', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-names-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const host = makeProject();
  const docker = makeProject({ backend: 'docker', dockerImage: 'example:jdk8' });
  try {
    remember(envContextOf(host.project), { id: 'g++', path: NODE, version: 'GNU g++ (GCC) 14.2.0' });
    remember(envContextOf(host.project), { id: 'ROPgadget', path: NODE, version: '7.6' });
    assert.deepEqual(recall(envContextOf(host.project), { id: 'g++' }).tools.map((t) => t.id), ['g++']);
    assert.deepEqual(recall(envContextOf(host.project), { id: 'ROPgadget' }).tools.map((t) => t.id), ['ROPgadget']);

    remember(envContextOf(docker.project), { id: 'gcc', path: '/usr/bin/gcc', version: '13.2.0' });
    const dockerPath = recall(envContextOf(docker.project), { id: 'gcc' }).tools[0]?.path;
    assert.equal(dockerPath, '/usr/bin/gcc');
    assert.ok(!dockerPath.includes('\\'), 'docker paths must not be win32-normalized');
  } finally {
    host.cleanup();
    docker.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('rootless env.memory recall works without a challenge project', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-rootless-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  try {
    const res = await dispatch({ op: 'env.memory', input: { action: 'recall' } });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && typeof res.data.summary, 'string', 'rootless recall must return the bounded summary');
    const probe = await dispatch({ op: 'env.memory', input: { action: 'probe', ids: ['not-a-real-tool'] } });
    assert.equal(probe.ok, true, JSON.stringify(probe));
    assert.equal(probe.ok && (probe.data.outcomes as Array<{ absent: boolean }>)[0]?.absent, true);
  } finally {
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('requested jdk major is not silently replaced by the default JDK', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-major-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['jdk@8'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const outcome = (res.ok ? res.data.outcomes as Array<Record<string, unknown>> : [])[0] ?? {};
    assert.equal(outcome.requested, 'jdk@8');
    if (outcome.absent === false) assert.equal(outcome.id, 'jdk@8');
    if (outcome.absent === true && outcome.actualId) assert.notEqual(outcome.actualId, 'jdk@8');
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('tool record and absent for the same id do not present a false available state', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-conflict-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'ida', path: NODE, version: '9.2' });
    recordAbsent(envContextOf(tp.project), 'ida');
    const result = recall(envContextOf(tp.project), { id: 'ida' });
    assert.equal(result.tools[0]?.status, 'unverified');
    assert.equal(result.tools[0]?.onPath, false);
    assert.equal(result.tools[0]?.discoveryFailed, false);
    assert.equal(result.absent.length, 0);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('recall defaults to summary and records is explicit', async () => {
  const tp = makeProject();
  try {
    const plain = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall' } });
    assert.equal(plain.ok, true, JSON.stringify(plain));
    assert.equal(plain.ok && typeof plain.data.summary, 'string');
    assert.equal(plain.ok && 'tools' in plain.data, false);
    const records = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', records: true } });
    assert.equal(records.ok, true, JSON.stringify(records));
    assert.equal(records.ok && Array.isArray(records.data.tools), true);
    const withSummary = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', records: true, includeSummary: true } });
    assert.equal(withSummary.ok, true, JSON.stringify(withSummary));
    assert.equal(withSummary.ok && typeof withSummary.data.summary, 'string');
  } finally {
    tp.cleanup();
  }
});


test('legacy records are normalized on read and not marked foreign', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-legacy-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    const file = storePath(envContextOf(tp.project));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({
      schema: 1,
      env: { backend: 'host', platform: process.platform, arch: process.arch },
      tools: {
        legacy: { path: NODE, realpath: NODE, version: '1.0', sig: null, source: 'user', seenAt: Date.now() },
      },
      absent: { old: { seenAt: Date.now() - 40 * 86_400_000 } },
    }));
    const result = recall(envContextOf(tp.project), { id: 'legacy' });
    assert.equal(result.tools[0]?.origin, 'legacy');
    assert.equal(result.tools[0]?.pathSource, 'user');
    assert.equal(result.tools[0]?.foreign, false);
    const legacy = JSON.parse(fs.readFileSync(file, 'utf8')) as { tools: Record<string, { origin?: string }> };
    assert.equal(legacy.tools.legacy?.origin, 'legacy', 'migration must persist');
    const expired = recall(envContextOf(tp.project), { id: 'old' }).absent[0];
    assert.equal(expired?.expired, true);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('probe reports a declared path that is not on PATH', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-declared-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'idat', path: NODE, version: '1.0' });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['idat'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const outcome = (res.ok ? res.data.outcomes as Array<Record<string, unknown>> : [])[0] ?? {};
    assert.equal(outcome.absent, false);
    assert.equal(outcome.path, NODE);
    assert.equal(outcome.onPath, false);
    assert.equal(outcome.declaredPathExists, true);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('env summary reflects a new absent result instead of a stale snapshot', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-summary-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'ida', path: NODE, version: '9.2' });
    const before = envSummary(envContextOf(tp.project));
    recordAbsent(envContextOf(tp.project), 'ida');
    const after = envSummary(envContextOf(tp.project));
    assert.notEqual(after, before);
    assert.match(after, /rule: recall before use/);
    assert.match(after, /offpath/);
    assert.match(after, /ida/);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('repaired wrapper provenance is projected by recall', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-wrapper-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    recordProbe(envContextOf(tp.project), 'ghidra', {
      path: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      realpath: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      version: '12.0.4',
      sig: null,
      wrapperPath: 'C:\\Users\\Administrator\\bin\\analyzeHeadless.cmd',
      wrapperTargetMissing: true,
      wrapperCwd: 'C:\\Tools\\ghidra\\support',
      pathRepaired: true,
      resolvedPath: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      onPath: true,
      pathSource: 'probe',
      versionSource: 'probe',
    });
    const tool = recall(envContextOf(tp.project), { id: 'ghidra' }).tools[0];
    assert.equal(tool?.status, 'repaired');
    assert.equal(tool?.needsReconfirmation, true);
    assert.equal(tool?.wrapperPath, 'C:\\Users\\Administrator\\bin\\analyzeHeadless.cmd');
    assert.equal(tool?.wrapperTargetMissing, true);
    assert.equal(tool?.pathRepaired, true);
    assert.equal(tool?.wrapperCwd, 'C:\\Tools\\ghidra\\support');
    assert.equal(tool?.resolvedPath, 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat');
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('missing one family member does not poison the other versions', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-family-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    recordProbe(envContextOf(tp.project), 'jdk@21', {
      path: NODE,
      realpath: NODE,
      version: '21.0.5',
      sig: { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs },
    });
    recordAbsent(envContextOf(tp.project), 'jdk@8');
    const present = recall(envContextOf(tp.project), { id: 'jdk@21' }).tools[0];
    assert.equal(present?.onPath, true);
    assert.equal(present?.status, 'verified');
    assert.equal(recall(envContextOf(tp.project)).absent.some((item) => item.id === 'jdk@8'), true);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('capability summary includes categories even when many verified tools exist', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-caps-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  const sig = { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs };
  try {
    const ids = ['gdb', 'pwntools', 'checksec', 'patchelf', 'jadx', 'radare2', 'sqlmap', 'ffuf', 'nmap', 'ncat', 'sage', 'binwalk', 'tshark', 'apktool', 'jdk@21', 'python', 'gcc', 'docker', 'angr', 'frida'];
    for (const [index, id] of ids.entries()) {
      recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `1.${index}`, sig });
    }
    const summary = envSummary(envContextOf(tp.project));
    assert.match(summary, /capabilities:/);
    for (const category of ['pwn:', 'reverse:', 'java:', 'android:', 'misc:']) assert.ok(summary.includes(category), category);
    for (const tool of ['jdk@21', 'python', 'gcc', 'docker', 'angr']) assert.ok(summary.includes(tool), tool);
    assert.ok(summary.length <= 700);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('summary keeps negative memory when positive capabilities fill the budget', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-neg-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  const sig = { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs };
  try {
    const ids = ['gdb', 'pwntools', 'checksec', 'patchelf', 'jadx', 'radare2', 'sqlmap', 'ffuf', 'nmap', 'ncat', 'sage', 'binwalk', 'tshark', 'apktool', 'jdk@21', 'python', 'gcc', 'docker', 'angr', 'frida'];
    for (const [index, id] of ids.entries()) {
      recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `2.${index}`, sig });
    }
    for (const id of ['netcat', 'qemu', 'z3', 'yara', 'volatility', 'x64dbg', 'radare2']) recordAbsent(envContextOf(tp.project), id);
    const summary = envSummary(envContextOf(tp.project));
    assert.match(summary, /absent:/);
    for (const tool of ['netcat', 'qemu', 'z3', 'yara', '+2']) assert.ok(summary.includes(tool), tool);
    assert.ok(summary.length <= 700);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('repaired anomaly is inlined into capabilities instead of repeated', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-inline-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    recordProbe(envContextOf(tp.project), 'ghidra', {
      path: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      realpath: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      version: '12.0.4',
      sig: null,
      wrapperPath: 'C:\\Users\\Administrator\\bin\\analyzeHeadless.cmd',
      wrapperTargetMissing: true,
      pathRepaired: true,
      resolvedPath: 'C:\\Tools\\ghidra\\support\\analyzeHeadless.bat',
      onPath: true,
      pathSource: 'probe',
      versionSource: 'probe',
    });
    const summary = envSummary(envContextOf(tp.project));
    assert.match(summary, /ghidra\(repaired/);
    assert.equal(summary.includes('- ghidra:'), false);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('capability fallback drops low-value classes before misc', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-drop-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  const sig = { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs };
  try {
    const ids = ['gdb', 'pwntools', 'checksec', 'patchelf', 'jadx', 'radare2', 'sqlmap', 'ffuf', 'nmap', 'ncat', 'sage', 'binwalk', 'tshark', 'apktool', 'jdk@21', 'python', 'gcc', 'docker', 'angr', 'frida'];
    for (const [index, id] of ids.entries()) {
      recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `3.${index}`, sig });
    }
    for (const id of ['steghide', 'foremost', 'exiftool', 'strings', 'file', 'git']) {
      recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `4.${id}`, sig });
    }
    for (const id of ['one_gadget', 'ropper', 'gmpy2', 'pwndbg', 'peda', 'readelf']) {
      recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `5.${id}`, sig: null, onPath: false });
    }
    const file = storePath(envContextOf(tp.project));
    const store = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const id of ['steghide', 'foremost', 'exiftool', 'strings', 'file', 'git']) store.tools[id].seenAt = Date.now() - 40 * 86_400_000;
    for (const id of ['one_gadget', 'ropper', 'gmpy2', 'pwndbg', 'peda', 'readelf']) store.tools[id].onPath = false;
    fs.writeFileSync(file, JSON.stringify(store));
    const summary = envSummary(envContextOf(tp.project));
    assert.match(summary, /- stale: .*steghide/);
    assert.match(summary, /misc: python, gcc, docker/);
    
    assert.ok(summary.length <= 700);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('environment notes store short non-tool facts', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-note-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'note', text: 'RTX 3060 driver 591.86 OpenCL ICD registered' } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const recalled = recall(envContextOf(tp.project));
    assert.equal(recalled.notes[0]?.text, 'RTX 3060 driver 591.86 OpenCL ICD registered');
    assert.match(envSummary(envContextOf(tp.project)), /notes: RTX 3060 driver 591\.86/);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('declared cmd wrapper records cwd and remains known off PATH', async () => {
  if (process.platform !== 'win32') return;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-cmd-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  const wrapper = path.join(os.homedir(), `.pi4ctf-test-${process.pid}-${Date.now()}.cmd`);
  try {
    fs.writeFileSync(wrapper, '@echo off\r\ncd /d "%~dp0"\r\necho idat 1.0\r\n');
    remember(envContextOf(tp.project), { id: 'idat', path: wrapper, version: '1.0' });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['idat'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const outcome = (res.ok ? res.data.outcomes as Array<Record<string, unknown>> : [])[0] ?? {};
    assert.equal(outcome.absent, false);
    assert.equal(outcome.onPath, false);
    assert.equal(outcome.wrapperPath, wrapper);
    assert.equal(outcome.wrapperCwd, path.dirname(wrapper));
  } finally {
    try { fs.rmSync(wrapper, { force: true }); } catch { /* best effort */ }
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('requested jdk major uses the declared path before PATH', async () => {
  if (process.platform !== 'win32') return;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-jdk-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  const java = path.join(os.homedir(), `.pi4ctf-jdk8-${process.pid}-${Date.now()}.cmd`);
  try {
    fs.writeFileSync(java, '@echo off\r\necho openjdk version "1.8.0_504"\r\n');
    remember(envContextOf(tp.project), { id: 'jdk@8', path: java, version: '1.8.0_504' });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'probe', ids: ['jdk@8'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const outcome = (res.ok ? res.data.outcomes as Array<Record<string, unknown>> : [])[0] ?? {};
    assert.equal(outcome.absent, false);
    assert.equal(outcome.id, 'jdk@8');
    assert.equal(outcome.version, '1.8.0_504');
    const remembered = recall(envContextOf(tp.project), { id: 'jdk@8' }).tools[0];
    assert.equal(remembered?.status, 'verified');
    assert.equal(remembered?.needsReconfirmation, false);
    assert.match(envSummary(envContextOf(tp.project)), /jdk@8/);
  } finally {
    try { fs.rmSync(java, { force: true }); } catch { /* best effort */ }
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('recall filters plural ids and origin', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-filter-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'ida', path: NODE, version: '9.2' });
    remember(envContextOf(tp.project), { id: 'idat', path: NODE, version: '9.2' });
    const file = storePath(envContextOf(tp.project));
    const store = JSON.parse(fs.readFileSync(file, 'utf8'));
    store.tools.ida.origin = 'test';
    fs.writeFileSync(file, JSON.stringify(store));
    assert.deepEqual(recall(envContextOf(tp.project), { ids: ['ida'] }).tools.map((tool) => tool.id), ['ida']);
    const viaTool = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', ids: ['ida'] } });
    assert.equal(viaTool.ok, true, JSON.stringify(viaTool));
    assert.deepEqual((viaTool.ok ? viaTool.data.tools as Array<{ id: string }> : []).map((tool) => tool.id), ['ida']);
    assert.deepEqual(recall(envContextOf(tp.project), { ids: ['idat'] }).tools.map((tool) => tool.id), ['idat']);
    assert.deepEqual(recall(envContextOf(tp.project), { origin: 'test' }).tools.map((tool) => tool.id), ['ida']);
    assert.equal(recall(envContextOf(tp.project), { origin: 'missing' }).tools.length, 0);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('legacy tools and absent for the same id are normalized apart', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-invariant-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'idat', path: NODE, version: '9.2' });
    const file = storePath(envContextOf(tp.project));
    const store = JSON.parse(fs.readFileSync(file, 'utf8'));
    store.absent.idat = { seenAt: Date.now(), reason: 'not-found' };
    fs.writeFileSync(file, JSON.stringify(store));
    const result = recall(envContextOf(tp.project), { id: 'idat' });
    assert.equal(result.tools.length, 1);
    assert.equal(result.absent.length, 0);
    const persisted = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(persisted.absent.idat, undefined);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('forget accepts plural ids and reports each removal', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-forget-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'ida', path: NODE, version: '9.2' });
    remember(envContextOf(tp.project), { id: 'idat', path: NODE, version: '9.3' });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'forget', ids: ['ida', 'idat', 'missing'] } });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.deepEqual(res.ok && res.data.removedIds, ['ida', 'idat']);
    assert.equal(recall(envContextOf(tp.project)).tools.length, 0);
    const single = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'forget', id: 'ida' } });
    assert.equal(single.ok && single.data.removed, false);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('repaired wrapper provenance is kept until the wrapper is fixed', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-rop-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    recordProbe(envContextOf(tp.project), 'ROPgadget', {
      path: 'C:\\Projects\\python\\Scripts\\ROPgadget',
      realpath: 'C:\\Projects\\python\\Scripts\\ROPgadget',
      version: '7.6',
      sig: null,
      wrapperPath: 'C:\\Tools\\ctf-bin\\ropgadget.cmd',
      wrapperTargetMissing: true,
      pathRepaired: true,
      resolvedPath: 'C:\\Tools\\ctf-bin\\ropgadget.cmd',
      onPath: true,
      pathSource: 'probe',
      versionSource: 'probe',
    });
    const tool = recall(envContextOf(tp.project), { id: 'ROPgadget' }).tools[0];
    assert.equal(tool?.status, 'repaired');
    assert.equal(tool?.wrapperPath, 'C:\\Tools\\ctf-bin\\ropgadget.cmd');
    assert.equal(tool?.resolvedPath, 'C:\\Tools\\ctf-bin\\ropgadget.cmd');
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('image parameter scopes env memory to a Docker image', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-image-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  try {
    const empty = await dispatch({ op: 'env.memory', input: { action: 'recall', image: 'example:test' } });
    assert.equal(empty.ok, true, JSON.stringify(empty));
    assert.equal(empty.ok && empty.data.envKey, 'docker/example:test');
    const remembered = await dispatch({
      op: 'env.memory',
      input: { action: 'remember', image: 'example:test', id: 'gcc', path: '/usr/bin/gcc', version: '13.2.0' },
    });
    assert.equal(remembered.ok, true, JSON.stringify(remembered));
    const recalled = await dispatch({ op: 'env.memory', input: { action: 'recall', image: 'example:test', id: 'gcc' } });
    assert.equal(recalled.ok, true, JSON.stringify(recalled));
    const tools = recalled.ok ? recalled.data.tools as Array<{ path?: string }> : [];
    assert.equal(tools[0]?.path, '/usr/bin/gcc');
  } finally {
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('compact recall uses flags and honors maxChars', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-compact-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    const ids = ['gdb', 'pwndbg', 'patchelf', 'python', 'radare2', 'rizin', 'nmap', 'ncat', 'sqlmap', 'binwalk'];
    const sig = { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs };
    for (const [index, id] of ids.entries()) recordProbe(envContextOf(tp.project), id, { path: NODE, realpath: NODE, version: `1.${index}`, sig });
    for (let index = 0; index < 3; index++) recordNote(envContextOf(tp.project), `${'note '.repeat(20)}${index}`);
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', records: true, maxChars: 500 } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const tools = res.ok ? res.data.tools as Array<Record<string, unknown>> : [];
    assert.ok(tools.length > 0 && tools.length < 10);
    assert.equal(res.ok && res.data.truncated, true);
    assert.equal('versionSource' in (tools[0] ?? {}), false);
    assert.equal('verifiedAt' in (tools[0] ?? {}), false);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('capability=pwn expands to the policy group, not just provides', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-cap-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'gdb', path: NODE, version: '1.0' });
    remember(envContextOf(tp.project), { id: 'pwntools', path: NODE, version: '2.0' });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', capability: 'pwn' } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const ids = res.ok ? (res.data.tools as Array<{ id: string }>).map((tool) => tool.id) : [];
    assert.ok(ids.includes('gdb'));
    assert.ok(ids.includes('pwntools'));
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('filtered recall keeps matching notes without hiding the selected tool', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-filter-notes-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    remember(envContextOf(tp.project), { id: 'gdb', path: NODE, version: '1.0' });
    recordNote(envContextOf(tp.project), 'gdb lives under the debugger toolchain');
    recordNote(envContextOf(tp.project), 'unrelated note one');
    recordNote(envContextOf(tp.project), 'unrelated note two');
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', ids: ['gdb'], maxChars: 500 } });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && (res.data.tools as unknown[]).length, 1);
    assert.ok(res.ok && (res.data.notes as Array<{ text: string }>).length <= 2);
    assert.ok(res.ok && (res.data.notes as Array<{ text: string }>).some((note) => note.text.includes('gdb')));
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});


test('records folds unverified user versions and keeps verified tools', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-fold-'));
  const oldHome = process.env.PI4CTF_HOME;
  process.env.PI4CTF_HOME = home;
  const tp = makeProject();
  try {
    for (const [index, id] of ['jdk@7', 'jdk@11', 'jdk@17', 'jdk@24', 'jdk@25'].entries()) {
      remember(envContextOf(tp.project), { id, path: NODE, version: `1.${index}` });
    }
    const sig = { size: fs.statSync(NODE).size, mtimeMs: fs.statSync(NODE).mtimeMs };
    recordProbe(envContextOf(tp.project), 'gdb', { path: NODE, realpath: NODE, version: '16.3', sig });
    const res = await dispatch({ op: 'env.memory', root: tp.root, input: { action: 'recall', records: true, maxChars: 1200 } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const tools = res.ok ? res.data.tools as Array<{ id: string }> : [];
    const groups = res.ok ? res.data.unverifiedUser as Array<{ ids: string[]; count: number }> : [];
    assert.equal(tools.some((tool) => tool.id === 'gdb'), true);
    assert.equal(tools.some((tool) => tool.id.startsWith('jdk@')), false);
    assert.equal(groups[0]?.count, 5);
  } finally {
    tp.cleanup();
    if (oldHome === undefined) delete process.env.PI4CTF_HOME;
    else process.env.PI4CTF_HOME = oldHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});
