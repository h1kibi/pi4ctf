/** signature@1 tests (ADR 0002 §3: normalization is its own frozen spec). */
import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalKey, signature } from '../kernel/shape/signature.js';

test('program and flags stay literal; path values become payload slots', () => {
  const r = signature(['curl', '-s', '-o', '/dev/null']);
  // /dev/null contains "/" which is not in the simple charset -> payload slot
  assert.deepEqual(r.argvTemplate, ['curl', '-s', '-o', '<v:1>']);
});

test('payload slots numbered by first appearance; same value reuses slot', () => {
  const r = signature(['curl', '-s', 'http://host/', "id=1' AND 1=1", "id=1' AND 1=1"]);
  assert.equal(r.slots, 1);
  assert.equal(r.argvTemplate[3], '<v:1>');
  assert.equal(r.argvTemplate[4], '<v:1>');
});

test('URL keeps scheme://host stable, query becomes payload', () => {
  const r = signature(['curl', 'http://10.0.0.1:8080/admin?id=1']);
  assert.equal(r.argvTemplate[1], 'http://10.0.0.1:8080/admin<v:1>');
});

test('short simple values stay literal', () => {
  const r = signature(['nc', 'localhost', '4444']);
  assert.deepEqual(r.argvTemplate, ['nc', 'localhost', '4444']);
});

test('long opaque value becomes payload', () => {
  const r = signature(['echo', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']);
  assert.equal(r.argvTemplate[1], '<v:1>');
});

test('canonicalKey composes class + signature + shaped hash', () => {
  const key = canonicalKey('http-probe', 'curl -s http://host/<v:1>', 'abc123');
  assert.equal(key, 'http-probe|signature@1:curl -s http://host/<v:1>|shaped:sha256:abc123');
});

test('same command shape with different payloads yields same signature', () => {
  const a = signature(['curl', '-s', 'http://h/', 'payload-AAAAAAAAAAAAAAAAAAAAAAAA']);
  const b = signature(['curl', '-s', 'http://h/', 'payload-BBBBBBBBBBBBBBBBBBBBBBBBB']);
  assert.equal(a.signature, b.signature);
});
