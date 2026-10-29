/** Auto-init detection: filesystem guards and init-spec derivation. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import {
  autoInitSpec,
  findOracle,
  hasProject,
  oracleLooksValid,
  scanChallenge,
  shouldAutoInit,
} from '../adapter/autoinit.js';

function tempDir(label: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `pi4ctf-${label}-`));
}

test('scanChallenge detects ELF and a challenge marker but not plain notes', () => {
  const root = tempDir('scan');
  try {
    fs.writeFileSync(path.join(root, 'notes.txt'), 'not a challenge');
    assert.deepEqual(scanChallenge(root), { hasElf: false, hasMarker: false });
    fs.writeFileSync(path.join(root, 'chall.elf'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
    assert.deepEqual(scanChallenge(root), { hasElf: true, hasMarker: true });
    fs.rmSync(path.join(root, 'chall.elf'));
    fs.writeFileSync(path.join(root, 'app.jar'), 'PK');
    assert.deepEqual(scanChallenge(root), { hasElf: false, hasMarker: true });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('auto-init guards empty, home, package source and disabled directories', () => {
  const root = tempDir('guards');
  const home = tempDir('home');
  const packageRoot = tempDir('pkg');
  try {
    assert.equal(shouldAutoInit(root, { homeDir: home, packageRoot }), false);
    fs.writeFileSync(path.join(root, 'chall.zip'), 'x');
    assert.equal(shouldAutoInit(root, { homeDir: home, packageRoot }), true);
    assert.equal(shouldAutoInit(root, { homeDir: home, packageRoot, env: { PI4CTF_AUTO_INIT: '0' } }), false);
    fs.mkdirSync(path.join(packageRoot, 'src'));
    fs.writeFileSync(path.join(packageRoot, 'src', 'main.ts'), 'x');
    assert.equal(shouldAutoInit(path.join(packageRoot, 'src'), { homeDir: home, packageRoot }), false);
    fs.writeFileSync(path.join(home, 'chall.zip'), 'x');
    assert.equal(shouldAutoInit(home, { homeDir: home, packageRoot }), false);
    const forced = tempDir('forced');
    try {
      fs.writeFileSync(path.join(forced, 'README.md'), 'x');
      assert.equal(shouldAutoInit(forced, { homeDir: home, packageRoot, env: { PI4CTF_AUTO_INIT: '1' } }), true);
    } finally {
      fs.rmSync(forced, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('findOracle derives target/flag format and rejects an invalid target', () => {
  const root = tempDir('oracle-root');
  const candidate = tempDir('oracle-parent');
  const challenge = path.join(candidate, 'web1');
  fs.mkdirSync(challenge);
  try {
    const oracle = path.join(candidate, 'web1-oracle.json');
    fs.writeFileSync(oracle, JSON.stringify({
      flag: 'flag{auto_init}',
      target: { host: '127.0.0.1', port: 31337 },
    }));
    const found = findOracle(challenge);
    assert.equal(found.ref, '../web1-oracle.json');
    assert.equal(found.flag, 'flag{auto_init}');
    assert.deepEqual(found.target, { host: '127.0.0.1', port: 31337, protocol: 'tcp' });
    const spec = autoInitSpec(challenge, { env: {}, dockerAvailable: () => false });
    assert.equal(spec.backend, 'host');
    assert.deepEqual(spec.target, { host: '127.0.0.1', port: 31337, protocol: 'tcp' });
    assert.equal(spec.flagFormat, 'flag\\{[^}]+\\}');
    assert.equal(oracleLooksValid(oracle), true);

    fs.writeFileSync(oracle, JSON.stringify({ flag: 'flag{bad}', target: { host: 'bad host', port: 80 } }));
    assert.equal(findOracle(challenge).target, null);

    fs.writeFileSync(oracle, JSON.stringify({ flagSha256: 'a'.repeat(64) }));
    assert.equal(oracleLooksValid(oracle), true);
    assert.equal(hasProject(challenge), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(candidate, { recursive: true, force: true });
  }
});
