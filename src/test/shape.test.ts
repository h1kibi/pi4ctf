/** shape@1 golden + property tests (docs/design.md §5.4 acceptance). */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { collapseRepeats, shape } from '../kernel/shape/shape.js';

const FIXTURES = path.resolve(import.meta.dirname, '..', '..', 'fixtures', 'shape');

test('shape@1 golden fixture: ansi + crlf + repeats', () => {
  const raw = fs.readFileSync(path.join(FIXTURES, 'ansi-noise.txt'));
  const result = shape(raw);
  const expected = fs.readFileSync(path.join(FIXTURES, 'ansi-noise.expected.txt'), 'utf8');
  assert.equal(result.shaped, expected);
  assert.equal(result.encoding, 'utf8');
});

test('shape@1 is idempotent: shape(shape(x)) == shape(x)', () => {
  const cases = [
    fs.readFileSync(path.join(FIXTURES, 'ansi-noise.txt')),
    fs.readFileSync(path.join(FIXTURES, 'random.bin')),
    Buffer.from('plain text\n'),
    Buffer.from(''),
    Buffer.from('no trailing newline'),
    Buffer.from('\n\n\n\n\n\n\n\n'),
    Buffer.from('a\r\nb\rc\n'),
    // 4 MiB+ of varied lines -> triggers windowing
    Buffer.from(Array.from({ length: 800_000 }, (_, i) => `line-${i}`).join('\n')),
  ];
  for (const buf of cases) {
    const once = shape(buf);
    const twice = shape(Buffer.from(once.shaped, once.encoding === 'hex' ? 'utf8' : 'utf8'));
    assert.equal(twice.shaped, once.shaped, `idempotence failed for ${buf.length} bytes`);
  }
});

test('shape@1 binary detection -> hex preview', () => {
  const bin = Buffer.concat([Buffer.from([0x00, 0x01, 0x02]), fs.readFileSync(path.join(FIXTURES, 'random.bin'))]);
  const result = shape(bin);
  assert.equal(result.encoding, 'hex');
  assert.match(result.shaped, /\[BINARY \d+ bytes/);
  assert.match(result.shaped, /^[0-9a-f]{8}  /m);
  assert.equal(result.shaped.includes('\u0000'), false);
});

test('shape@1 large output windowing: head + [TRUNCATED] + tail', () => {
  const lines = Array.from({ length: 800_000 }, (_, i) => `L${i}`);
  const big = lines.join('\n');
  assert.ok(big.length > 4 * 1024 * 1024);
  const result = shape(Buffer.from(big));
  assert.match(result.shaped, /\[TRUNCATED\]/);
  assert.ok(result.omittedChars > 0);
  assert.ok(result.shaped.startsWith('L0\nL1\n'));
  assert.ok(result.shaped.endsWith('\nL799999'));
});

test('collapseRepeats keeps 3 and marks the rest', () => {
  assert.equal(collapseRepeats('x\nx\nx'), 'x\nx\nx');
  assert.equal(collapseRepeats('x\nx\nx\nx\nx'), 'x\nx\nx\n[REPEATED 2 identical lines OMITTED]');
  // collapse is stable (idempotent) on its own output
  const once = collapseRepeats('x\nx\nx\nx\nx\nx\nx');
  assert.equal(collapseRepeats(once), once);
});

test('shape@1 strips OSC with BEL and ST terminators', () => {
  const out = shape(Buffer.from('\x1b]0;win-title\x07ok\x1b]8;;http://x\x1b\\link')).shaped;
  assert.equal(out, 'oklink');
});
