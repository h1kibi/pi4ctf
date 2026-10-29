/** Kernel HTTP primitive: cookie jar, redirects, binary body, raw socket. */
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { after, before, test } from 'node:test';
import { dispatch } from '../adapter/protocol.js';
import { Ledger } from '../kernel/ledger/store.js';
import { makeProject } from './helpers.js';

let server: http.Server;
let port = 0;

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/set') {
      res.writeHead(200, { 'Set-Cookie': 'sid=abc; Path=/' });
      res.end('set');
      return;
    }
    if (req.url === '/echo') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`cookie=${req.headers.cookie ?? ''}`);
      return;
    }
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: '/ok' });
      res.end('redirect');
      return;
    }
    if (req.url === '/binary') {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(Buffer.from([0, 1, 2, 255, 254]));
      return;
    }
    if (req.url === '/fail') {
      res.writeHead(500);
      res.end('boom');
      return;
    }
    if (req.url === '/echo-body') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(Buffer.from(c)));
      req.on('end', () => res.end(Buffer.concat(chunks)));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('x'.repeat(req.url === '/long' ? 40 : 10));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as import('node:net').AddressInfo).port;
});

after(() => server.close());

function httpProbe(url: string, extra: Record<string, unknown> = {}) {
  return { label: url, http: { url, ...extra } };
}

test('http probes: status/body item, no redirect by default, follow optional', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          httpProbe(`http://127.0.0.1:${port}/redirect`),
          httpProbe(`http://127.0.0.1:${port}/redirect`, { followRedirects: true }),
          httpProbe(`http://127.0.0.1:${port}/binary`),
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const ledger = new Ledger(tp.project);
    const redirect = ledger.getEvidence('cmd-0001.0001').item!;
    const followed = ledger.getEvidence('cmd-0001.0002').item!;
    const binary = ledger.getEvidence('cmd-0001.0003').item!;
    assert.equal(redirect.status, 302);
    assert.equal(followed.status, 200);
    assert.equal(binary.kind, 'http');
    assert.equal(binary.encoding, 'base64');
    assert.equal(fs.readFileSync(path.join(tp.project.ctfDir, binary.stdout.rawRef)).length, 5);
  } finally {
    tp.cleanup();
  }
});

test('http probes: cookie jar carries Set-Cookie across probes', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          httpProbe(`http://127.0.0.1:${port}/set`),
          httpProbe(`http://127.0.0.1:${port}/echo`),
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const echo = new Ledger(tp.project).getEvidence('cmd-0001.0002').item!;
    assert.match(fs.readFileSync(path.join(tp.project.ctfDir, echo.stdout.rawRef), 'utf8'), /sid=abc/);
  } finally {
    tp.cleanup();
  }
});

test('http probes: raw socket and item-level 500 negative', async () => {
  const tp = makeProject();
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [
          httpProbe(`http://127.0.0.1:${port}/ok`, { raw: true }),
          httpProbe(`http://127.0.0.1:${port}/fail`),
        ],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const items = [new Ledger(tp.project).getEvidence('cmd-0001.0001').item!, new Ledger(tp.project).getEvidence('cmd-0001.0002').item!];
    assert.equal(items[0]?.status, 200);
    assert.equal(items[1]?.status, 500);
    assert.ok(new Ledger(tp.project).listNegatives().some((n) => n.failureClass === 'server-error'));
  } finally {
    tp.cleanup();
  }
});


test('http probe bodyFile reads a project file and hashes it into the route', async () => {
  const tp = makeProject({ allowedHosts: ['127.0.0.1'] });
  try {
    fs.writeFileSync(path.join(tp.root, 'payload.bin'), 'body-from-file');
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [{
          label: 'body-file',
          http: { method: 'POST', url: `http://127.0.0.1:${port}/echo-body`, bodyFile: 'payload.bin' },
        }],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const items = run.ok ? (run.data.items as Array<{ excerpt: string }>) : [];
    assert.match(items[0]?.excerpt ?? '', /body-from-file/);
    const child = fs.readdirSync(path.join(tp.root, '.ctf', 'items'))[0];
    const item = JSON.parse(fs.readFileSync(path.join(tp.root, '.ctf', 'items', child), 'utf8')) as { routeSignature: string };
    assert.match(item.routeSignature, /signature@1:http POST .*<v:/);
  } finally {
    tp.cleanup();
  }
});


test('http bodyFile cannot escape the project root', async () => {
  const tp = makeProject({ allowedHosts: ['127.0.0.1'] });
  try {
    const run = await dispatch({
      op: 'run',
      root: tp.root,
      input: {
        probes: [{
          label: 'escape',
          http: { method: 'POST', url: `http://127.0.0.1:${port}/echo-body`, bodyFile: '../outside.txt' },
        }],
      },
    });
    assert.equal(run.ok, true, JSON.stringify(run));
    const errors = run.ok ? (run.data.errors as Array<{ message: string }>) : [];
    assert.match(errors[0]?.message ?? '', /bodyFile must stay inside/);
  } finally {
    tp.cleanup();
  }
});
