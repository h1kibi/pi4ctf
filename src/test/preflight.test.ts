/** Preflight metadata and backend reconfiguration regressions. */
import * as assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { compilePacket } from '../kernel/context/packet.js';
import { Ledger } from '../kernel/ledger/store.js';
import { makeProject } from './helpers.js';

const LOCAL_FIXTURES = path.resolve('challenges', 'ctftiny-babyboi');

/** Preflight fixtures are CTFTiny challenge data (GPL, and large), so they are
 *  not committed. Use the local copy when present; otherwise build an
 *  equivalent ELF on an ELF host. Windows cannot produce ELF with gcc. */
function syntheticFixtures(): string | null {
  if (process.platform === 'win32') return null;
  const dir = path.join(os.tmpdir(), 'pi4ctf-preflight-fixtures');
  const binary = path.join(dir, 'baby_boi');
  if (fs.existsSync(binary)) return dir;
  try {
    fs.mkdirSync(dir, { recursive: true });
    const src = path.join(dir, 'fixture.c');
    fs.writeFileSync(src, '#include <stdio.h>\nint main(void) { puts("fixture"); return 0; }\n');
    execFileSync('gcc', [
      '-no-pie', '-fno-stack-protector',
      '-Wl,-z,relro', '-Wl,-z,lazy', '-Wl,--build-id=sha1',
      '-o', binary, src,
    ], { stdio: 'ignore' });
    fs.writeFileSync(
      path.join(dir, 'libc-2.27.so'),
      Buffer.concat([
        fs.readFileSync(binary),
        Buffer.from('\nGNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.\n'),
      ]),
    );
    return dir;
  } catch {
    return null;
  }
}

const FIXTURES = (fs.existsSync(path.join(LOCAL_FIXTURES, 'baby_boi'))
  ? LOCAL_FIXTURES
  : syntheticFixtures()) ?? path.join(os.tmpdir(), 'pi4ctf-preflight-fixtures-missing');
const SKIP = FIXTURES.endsWith('-missing')
  ? 'preflight fixtures unavailable: no local challenge data and no gcc'
  : false;

test('preflight writes ELF/libc metadata and packet digest', { skip: SKIP }, async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    fs.copyFileSync(path.join(FIXTURES, 'baby_boi'), path.join(tp.root, 'baby_boi'));
    fs.copyFileSync(path.join(FIXTURES, 'libc-2.27.so'), path.join(tp.root, 'libc-2.27.so'));
    const res = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(res.ok, true, JSON.stringify(res));
    const files = res.ok ? (res.data.files as Array<{ path: string; elf: Record<string, unknown> }>) : [];
    assert.equal(files.length, 2);
    const binary = files.find((f) => f.path === 'baby_boi');
    assert.ok(binary);
    assert.equal(binary?.elf.pie, false);
    assert.equal(binary?.elf.canary, false);
    assert.equal(binary?.elf.nx, true);
    assert.equal(binary?.elf.relro, 'partial');
    assert.match(String(binary?.elf.buildId), /^[0-9a-f]{40}$/);
    assert.ok(Array.isArray(binary?.elf.needed) && (binary?.elf.needed as string[]).includes('libc.so.6'));
    const libc = res.ok ? (res.data.libc as Array<{ version: string; buildId: string }>) : [];
    assert.equal(libc.length, 1);
    assert.equal(libc[0]?.version, '2.27');
    assert.match(libc[0]?.buildId ?? '', /^[0-9a-f]{40}$/);
    assert.ok(fs.existsSync(path.join(tp.root, '.ctf', 'chal.json')));
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /## Challenge metadata/);
    assert.match(packet.text, /baby_boi: 64-bit executable no-PIE no-canary NX RELRO:partial/);
    assert.match(packet.text, /libc libc-2\.27\.so: version=2\.27/);
  } finally {
    tp.cleanup();
  }
});

test('case.configure moves backend host -> docker and pins image', async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    const res = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { backend: 'docker', dockerImage: 'example:pwn' },
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.ok && res.data.backend, 'docker');
    assert.equal(tp.project.file().backend, 'docker');
    assert.equal(tp.project.file().dockerImage, 'example:pwn');
    const bad = await dispatch({
      op: 'case.configure',
      root: tp.root,
      input: { backend: 'docker', dockerImage: '' },
    });
    // Empty image must fail rather than silently producing an unusable backend.
    assert.equal(bad.ok, false);
    assert.equal(tp.project.file().dockerImage, 'example:pwn');
  } finally {
    tp.cleanup();
  }
});


test('preflight skips core dumps, archives, workspace and .ctfignore entries', { skip: SKIP }, async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    const src = path.join(FIXTURES, 'baby_boi');
    fs.copyFileSync(src, path.join(tp.root, 'baby_boi'));
    fs.copyFileSync(src, path.join(tp.root, 'core.129'));
    fs.copyFileSync(src, path.join(tp.root, 'x.zip'));
    fs.copyFileSync(src, path.join(tp.root, 'ignored.elf'));
    fs.mkdirSync(path.join(tp.root, 'workspace'), { recursive: true });
    fs.copyFileSync(src, path.join(tp.root, 'workspace', 'nested.elf'));
    fs.writeFileSync(path.join(tp.root, '.ctfignore'), 'ignored.elf\n');
    const res = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(res.ok, true, JSON.stringify(res));
    const files = res.ok ? (res.data.files as Array<{ path: string }>) : [];
    assert.deepEqual(files.map((f) => f.path), ['baby_boi']);
    const notes = res.ok ? (res.data.notes as string[]) : [];
    assert.ok(notes.some((n) => n.includes('core.129')));
    assert.ok(notes.some((n) => n.includes('x.zip')));
    assert.ok(notes.some((n) => n.includes('ignored.elf')));
  } finally {
    tp.cleanup();
  }
});

test('preflight records the project endpoint in chal.json and packet', { skip: SKIP }, async () => {
  const tp = makeProject({ backend: 'host', target: { host: '127.0.0.1', port: 4444, instanceId: 'inst-1' } });
  try {
    fs.copyFileSync(path.join(FIXTURES, 'baby_boi'), path.join(tp.root, 'baby_boi'));
    const res = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(res.ok, true);
    assert.deepEqual(res.ok && res.data.endpoint, { host: '127.0.0.1', port: 4444, protocol: 'tcp', instanceId: 'inst-1' });
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /endpoint: tcp:\/\/127\.0\.0\.1:4444 instance=inst-1/);
  } finally {
    tp.cleanup();
  }
});


test('packet marks a preflight endpoint stale after target switch', { skip: SKIP }, async () => {
  const tp = makeProject({ backend: 'host', target: { host: '127.0.0.1', port: 4444 } });
  try {
    fs.copyFileSync(path.join(FIXTURES, 'baby_boi'), path.join(tp.root, 'baby_boi'));
    await dispatch({ op: 'case.preflight', root: tp.root });
    fs.writeFileSync(tp.oraclePath, JSON.stringify({
      flagSha256: (await import('node:crypto')).createHash('sha256').update(tp.flag).digest('hex'),
      target: { host: '127.0.0.1', port: 5555 },
      expiresAt: Date.now() + 60_000,
    }, null, 2));
    tp.project.reconfigure({ target: { host: '127.0.0.1', port: 5555 }, oracleRef: path.relative(tp.root, tp.oraclePath) });
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /preflight endpoint \(stale\): tcp:\/\/127\.0\.0\.1:4444/);
    assert.match(packet.text, /current target: tcp:\/\/127\.0\.0\.1:5555/);
  } finally {
    tp.cleanup();
  }
});


test('preflight keeps late root attachments and ignores workspace by default', { skip: SKIP }, async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    const src = path.join(FIXTURES, 'baby_boi');
    fs.copyFileSync(src, path.join(tp.root, 'baby_boi'));
    fs.writeFileSync(path.join(tp.root, 'notes.txt'), 'challenge notes\n');
    const first = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(first.ok, true);
    const firstOthers = first.ok ? (first.data.otherFiles as Array<{ path: string; format: string }>) : [];
    assert.ok(firstOthers.some((f) => f.path === 'notes.txt' && f.format === 'text'));

    // A late extraction into the root is attachment material, not generated.
    fs.copyFileSync(src, path.join(tp.root, 'late.so'));
    const second = await dispatch({ op: 'case.preflight', root: tp.root });
    const secondFiles = second.ok ? (second.data.files as Array<{ path: string }>) : [];
    assert.deepEqual(secondFiles.map((f) => f.path).sort(), ['baby_boi', 'late.so']);
    assert.ok((secondFiles.find((f) => f.path === 'late.so') as { generated?: boolean } | undefined)?.generated !== true);

    // Agent-generated output belongs in workspace/ and is ignored by default.
    fs.mkdirSync(path.join(tp.root, 'workspace'), { recursive: true });
    fs.copyFileSync(src, path.join(tp.root, 'workspace', 'generated.so'));
    const third = await dispatch({ op: 'case.preflight', root: tp.root });
    const thirdFiles = third.ok ? (third.data.files as Array<{ path: string }>) : [];
    assert.deepEqual(thirdFiles.map((f) => f.path).sort(), ['baby_boi', 'late.so']);

    const included = await dispatch({ op: 'case.preflight', root: tp.root, input: { includeWorkspace: true } });
    const includedFiles = included.ok ? (included.data.files as Array<{ path: string }>) : [];
    assert.deepEqual(includedFiles.map((f) => f.path).sort(), ['baby_boi', 'late.so', 'workspace/generated.so']);
    assert.equal((includedFiles.find((f) => f.path === 'workspace/generated.so') as { generated?: boolean } | undefined)?.generated, true);

    fs.mkdirSync(path.join(tp.root, 'build'), { recursive: true });
    fs.copyFileSync(src, path.join(tp.root, 'build', 'compiled.so'));
    const buildDefault = await dispatch({ op: 'case.preflight', root: tp.root });
    const buildDefaultFiles = buildDefault.ok ? (buildDefault.data.files as Array<{ path: string }>) : [];
    assert.ok(!buildDefaultFiles.some((f) => f.path === 'build/compiled.so'));
    const buildIncluded = await dispatch({ op: 'case.preflight', root: tp.root, input: { includeBuild: true } });
    const buildIncludedFiles = buildIncluded.ok ? (buildIncluded.data.files as Array<{ path: string; generated?: boolean }>) : [];
    assert.equal(buildIncludedFiles.find((f) => f.path === 'build/compiled.so')?.generated, true);
    const partitioned = await dispatch({ op: 'case.preflight', root: tp.root, input: { includeWorkspace: true, includeBuild: true } });
    assert.equal(partitioned.ok, true);
    assert.ok(partitioned.ok && (partitioned.data.rootFiles as string[]).includes('baby_boi'));
    assert.ok(partitioned.ok && (partitioned.data.rootFiles as string[]).includes('late.so'));
    assert.ok(partitioned.ok && (partitioned.data.generated as string[]).includes('workspace/generated.so'));
    assert.ok(partitioned.ok && (partitioned.data.generated as string[]).includes('build/compiled.so'));
    const packet = compilePacket(tp.project, new Ledger(tp.project));
    assert.match(packet.text, /- root files \(ELF\+non-ELF, unclassified\): \d+ \(/);
    assert.match(packet.text, /- generated \(workspace\/build\): \d+ \(/);
  } finally {
    tp.cleanup();
  }
});


test('preflight detects gzip magic and does not emit dead imports fields', async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    fs.writeFileSync(path.join(tp.root, 'archive.bin'), Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]));
    const res = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(res.ok, true, JSON.stringify(res));
    const others = res.ok ? (res.data.otherFiles as Array<Record<string, unknown>>) : [];
    const gzip = others.find((f) => f.path === 'archive.bin');
    assert.equal(gzip?.format, 'gzip');
    assert.equal(Object.prototype.hasOwnProperty.call(gzip, 'imports'), false);
    const chal = JSON.parse(fs.readFileSync(path.join(tp.root, '.ctf', 'chal.json'), 'utf8')) as Record<string, unknown>;
    assert.equal(Object.prototype.hasOwnProperty.call(chal, 'version'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(chal, 'generatedAt'), false);
  } finally {
    tp.cleanup();
  }
});


test('preflight detects Java class major version and new root files', async () => {
  const tp = makeProject({ backend: 'host' });
  try {
    fs.writeFileSync(path.join(tp.root, 'Main.class'), Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34]));
    const first = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(first.ok, true, JSON.stringify(first));
    const others = first.ok ? (first.data.otherFiles as Array<{ path: string; format: string; details?: string }>) : [];
    const cls = others.find((f) => f.path === 'Main.class');
    assert.equal(cls?.format, 'Java class');
    assert.match(cls?.details ?? '', /major=52 \(JDK8-compatible\)/);

    fs.writeFileSync(path.join(tp.root, 'pwned-marker.txt'), 'agent artifact');
    const second = await dispatch({ op: 'case.preflight', root: tp.root });
    assert.equal(second.ok, true, JSON.stringify(second));
    assert.match(JSON.stringify(second), /new root file\(s\) since last preflight: pwned-marker.txt/);
  } finally {
    tp.cleanup();
  }
});
