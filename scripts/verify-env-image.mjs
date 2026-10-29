import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { dispatch } from '../dist/adapter/protocol.js';

const image = process.argv[2] || process.env.PI4CTF_TEST_DOCKER_IMAGE;
if (!image) {
  console.error('usage: node scripts/verify-env-image.mjs <docker-image>');
  process.exit(2);
}
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pi4ctf-env-image-'));
const oldHome = process.env.PI4CTF_HOME;
process.env.PI4CTF_HOME = home;
try {
  const remembered = await dispatch({
    op: 'env.memory',
    input: { action: 'remember', image, id: 'gcc', path: '/usr/bin/gcc', version: '13.3.0' },
  });
  if (!remembered.ok) throw new Error(JSON.stringify(remembered));
  const probed = await dispatch({ op: 'env.memory', input: { action: 'probe', image, ids: ['gcc'] } });
  if (!probed.ok) throw new Error(JSON.stringify(probed));
  const outcome = probed.data.outcomes?.[0];
  if (!outcome || outcome.absent || outcome.path !== '/usr/bin/gcc' || !outcome.version) {
    throw new Error(`unexpected image probe: ${JSON.stringify(outcome)}`);
  }
  console.log(JSON.stringify({ image, outcome }, null, 2));
} finally {
  if (oldHome === undefined) delete process.env.PI4CTF_HOME;
  else process.env.PI4CTF_HOME = oldHome;
  fs.rmSync(home, { recursive: true, force: true });
}
