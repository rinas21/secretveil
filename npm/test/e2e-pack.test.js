import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getSecretVeilDirectory } from '../src/secrets/store.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TARBALL_NAME = 'rinas21-secretveil-1.0.0.tgz';

function run(cmd, args, opts) {
  return spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: opts.timeout || 60000,
    cwd: opts.cwd,
    input: opts.input,
    env: opts.env
  });
}

describe('Installed package E2E', { timeout: 180000 }, () => {
  let work;
  let home;
  let prefix;
  let bin;

  let savedHome;
  let savedProfile;

  before(() => {
    work = mkdtempSync(join(tmpdir(), 'sv-e2e-work-'));
    home = mkdtempSync(join(tmpdir(), 'sv-e2e-home-'));
    prefix = mkdtempSync(join(tmpdir(), 'sv-e2e-prefix-'));
    savedHome = process.env.HOME;
    savedProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const packed = run('npm', ['pack', '--pack-destination', work], { cwd: ROOT, timeout: 60000 });
    assert.strictEqual(packed.status, 0, packed.stderr);
    const tgz = join(work, TARBALL_NAME);
    assert.ok(existsSync(tgz), `missing ${tgz}`);
    const installed = run('npm', ['install', '--prefix', prefix, tgz], { cwd: work, timeout: 120000 });
    assert.strictEqual(installed.status, 0, installed.stderr);
    bin = join(prefix, 'node_modules', '.bin', 'secretveil');
    assert.ok(existsSync(bin), 'installed secretveil bin missing');
  });

  after(() => {
    process.env.HOME = savedHome;
    process.env.USERPROFILE = savedProfile;
    try { rmSync(work, { recursive: true, force: true }); } catch (_) {}
    try { rmSync(home, { recursive: true, force: true }); } catch (_) {}
    try { rmSync(prefix, { recursive: true, force: true }); } catch (_) {}
  });

  function cli(args, input = '', timeout = 60000) {
    return run(process.execPath, [bin, ...args], {
      cwd: work,
      input,
      timeout,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SECRETVEIL_TEST_KEYCHAIN: join(home, '.secretveil-test-keychain.json')
      }
    });
  }

  it('init + run injects all .env vars and persists credentials via global store', () => {
    writeFileSync(join(work, '.env'), [
      '# comment only',
      'API_KEY=sk-test-key-with#hash',
      'DB_PASSWORD="p@ss=word"',
      "JWT_SECRET='jwt#secret=value'",
      'APP_NAME=MyApp',
      'NODE_ENV=development',
      'PORT=8080',
      'DATABASE_URL=postgres://user:pass@localhost:5432/db',
      'SPECIAL_VALUE=abc!@#$%^&*()',
      'QUOTED_VALUE="hello world"',
      'EMPTY_VALUE='
    ].join('\n'));
    const init = cli(['init'], 'e2e-pack-pass\ne2e-pack-pass\n', 90000);
    assert.strictEqual(init.status, 0, init.stdout + init.stderr);
    writeFileSync(join(work, 'dump.js'), [
      'const keys = ["API_KEY","DB_PASSWORD","JWT_SECRET","APP_NAME","NODE_ENV","PORT","DATABASE_URL","SPECIAL_VALUE","QUOTED_VALUE","EMPTY_VALUE"];',
      'const out = {};',
      'for (const k of keys) out[k] = process.env[k];',
      'console.log(JSON.stringify(out));'
    ].join('\n'));
    const first = cli(['run', 'node', 'dump.js'], '');
    assert.strictEqual(first.status, 0, first.stdout + first.stderr);
    const dumped = JSON.parse(first.stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop());
    assert.strictEqual(dumped.API_KEY, 'sk-test-key-with#hash');
    assert.strictEqual(dumped.DB_PASSWORD, 'p@ss=word');
    assert.strictEqual(dumped.JWT_SECRET, 'jwt#secret=value');
    assert.strictEqual(dumped.APP_NAME, 'MyApp');
    assert.strictEqual(dumped.NODE_ENV, 'development');
    assert.strictEqual(dumped.PORT, '8080');
    assert.strictEqual(dumped.DATABASE_URL, 'postgres://user:pass@localhost:5432/db');
    assert.strictEqual(dumped.SPECIAL_VALUE, 'abc!@#$%^&*()');
    assert.strictEqual(dumped.QUOTED_VALUE, 'hello world');
    assert.strictEqual(dumped.EMPTY_VALUE, '');

    const credPath = join(home, '.secretveil', 'credentials.json');
    assert.ok(existsSync(credPath));
    const raw = readFileSync(credPath, 'utf8');
    assert.ok(!raw.includes('e2e-pack-pass'));
    const record = Object.values(JSON.parse(raw).projects)[0];
    assert.strictEqual(record.backend, 'keychain');
    assert.ok(!record.slots);
    assert.ok(!existsSync(join(home, '.secretveil', 'vault.key')));
    assert.ok(!existsSync(join(work, '.secretveil')));
    const storeDir = getSecretVeilDirectory(work);
    assert.ok(existsSync(join(storeDir, 'config.json')));
    assert.ok(!readFileSync(join(storeDir, 'config.json'), 'utf8').includes('e2e-pack-pass'));
    assert.ok(!readFileSync(join(storeDir, 'secrets.enc'), 'utf8').includes('e2e-pack-pass'));

    const restart = cli(['run', 'node', 'dump.js'], '');
    assert.strictEqual(restart.status, 0, restart.stdout + restart.stderr);
    assert.ok(restart.stdout.includes('sk-test-key-with#hash'));
    assert.ok(restart.stdout.includes('Using stored credential.'));
  });
});
