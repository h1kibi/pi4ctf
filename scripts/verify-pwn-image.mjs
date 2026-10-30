import { spawnSync } from 'node:child_process';

const image = process.argv[2] || process.env.PI4CTF_PWN_IMAGE || 'ctf-swarm-pi-pwn:0.3.0-rc.1';
const required = ['python3', 'pwntools', 'gdb'];
const checks = {
  gdb: 'command -v gdb && gdb --version | head -1',
  python3: 'command -v python3 && python3 --version',
  pwntools: "python3 -c 'import pwn; print(pwn.__file__)'",
  checksec: 'command -v checksec',
  patchelf: 'command -v patchelf',
};
const results = {};
for (const [name, command] of Object.entries(checks)) {
  const res = spawnSync('docker', ['run', '--rm', '--entrypoint', 'sh', image, '-c', command], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  results[name] = res.status === 0
    ? { ok: true, detail: (res.stdout || res.stderr).trim().split(/\r?\n/)[0] }
    : { ok: false, detail: (res.stderr || res.stdout).trim().slice(0, 300) };
}
const missing = required.filter((name) => !results[name]?.ok);
console.log(JSON.stringify({ image, results, missing }, null, 2));
if (missing.length > 0) {
  console.error(`missing required pwn tools: ${missing.join(', ')}`);
  process.exit(1);
}
