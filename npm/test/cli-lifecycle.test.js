import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnvString } from '../src/secrets/parser.js';
import { redactEnvContent, restoreEnvContent, formatEnvValue } from '../src/commands/init.js';
import { detectPlaintextSecrets, getSecretKeys } from '../src/utils/helpers.js';
import { getSecretVeilDirectory } from '../src/secrets/store.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'secretveil.js');
function storeDir(projectDir) { return getSecretVeilDirectory(projectDir); }

function runCli(dir, args, input, timeoutMs = 25000, homeDir) {
  return spawnSync(process.execPath, [BIN, ...args], {
    cwd: dir,
    input,
    timeout: timeoutMs,
    encoding: 'utf8',
    env: homeDir
      ? {
          ...process.env,
          HOME: homeDir,
          USERPROFILE: homeDir,
          SECRETVEIL_TEST_KEYCHAIN: join(homeDir, '.secretveil-test-keychain.json')
        }
      : process.env
  });
}

function makeDir() {
  return mkdtempSync(join(tmpdir(), 'sv-lifecycle-'));
}

function cleanDir(dir) {
  try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

describe('Parser syntax audit', () => {
  it('strips export prefix from keys', () => {
    assert.deepStrictEqual(parseEnvString('export API_KEY=abc123'), { API_KEY: 'abc123' });
    assert.deepStrictEqual(parseEnvString('export\tAPI_KEY=abc123'), { API_KEY: 'abc123' });
    assert.deepStrictEqual(parseEnvString('export   DB_PASSWORD=x'), { DB_PASSWORD: 'x' });
  });

  it('does not strip lone quote characters', () => {
    assert.deepStrictEqual(parseEnvString('Q="'), { Q: '"' });
    assert.deepStrictEqual(parseEnvString("Q='"), { Q: "'" });
  });

  it('preserves # inside quoted values', () => {
    assert.deepStrictEqual(parseEnvString('S1="abc#def"'), { S1: 'abc#def' });
    assert.deepStrictEqual(parseEnvString("S2='abc#def'"), { S2: 'abc#def' });
  });

  it('handles CRLF line endings', () => {
    assert.deepStrictEqual(parseEnvString('PORT=8080\r\nAPI_KEY=x\r\n'), { PORT: '8080', API_KEY: 'x' });
  });

  it('last duplicate key wins without dropping the variable', () => {
    assert.deepStrictEqual(parseEnvString('K=first\nK=second'), { K: 'second' });
  });

  it('preserves empty values exactly', () => {
    assert.deepStrictEqual(parseEnvString('E='), { E: '' });
    assert.deepStrictEqual(parseEnvString('E2=""'), { E2: '' });
    assert.deepStrictEqual(parseEnvString("E3=''"), { E3: '' });
  });

  it('keeps = inside values and skips malformed lines', () => {
    assert.deepStrictEqual(parseEnvString('URL=a=b=c'), { URL: 'a=b=c' });
    assert.deepStrictEqual(parseEnvString('no-equals\nK=v'), { K: 'v' });
    assert.deepStrictEqual(parseEnvString('=v'), {});
    assert.deepStrictEqual(parseEnvString('# comment\n\nK2=v'), { K2: 'v' });
  });
});

describe('redactEnvContent', () => {
  it('redacts secrets and preserves everything else byte-identically', () => {
    const original = [
      '# leading comment',
      '',
      'API_KEY=TEST_API_123456',
      'DB_PASSWORD="TEST_DB_789012"',
      'APP_NAME="My Test Application"',
      "SPECIAL_2='value with spaces and \"double quotes\"'",
      'EMPTY_VALUE=""',
      'PORT=8080',
      'not a var line'
    ].join('\n');
    const redacted = redactEnvContent(original, ['API_KEY', 'DB_PASSWORD']);
    const lines = redacted.split('\n');
    assert.strictEqual(lines[0], '# leading comment');
    assert.strictEqual(lines[1], '');
    assert.strictEqual(lines[2], 'API_KEY=<encrypted>');
    assert.strictEqual(lines[3], 'DB_PASSWORD=<encrypted>');
    assert.strictEqual(lines[4], 'APP_NAME="My Test Application"');
    assert.strictEqual(lines[5], "SPECIAL_2='value with spaces and \"double quotes\"'");
    assert.strictEqual(lines[6], 'EMPTY_VALUE=""');
    assert.strictEqual(lines[7], 'PORT=8080');
    assert.strictEqual(lines[8], 'not a var line');
  });

  it('preserves export prefix on redacted secrets', () => {
    const out = redactEnvContent('export API_KEY=abc123\nPORT=1', ['API_KEY']);
    assert.strictEqual(out, 'export API_KEY=<encrypted>\nPORT=1');
  });
});

describe('restoreEnvContent', () => {
  it('restores placeholders while preserving comments, order, and non-secrets', () => {
    const redacted = [
      '# keep me',
      '',
      'API_KEY=<encrypted>',
      'export DB_PASSWORD=<encrypted>',
      'APP_NAME="My App"',
      'PORT=8080',
      'port=9090'
    ].join('\n');
    const restored = restoreEnvContent(redacted, {
      API_KEY: { value: 'sk#hash', quote: 'double' },
      DB_PASSWORD: { value: 'p=ass word', quote: 'double' }
    });
    const lines = restored.split('\n');
    assert.strictEqual(lines[0], '# keep me');
    assert.strictEqual(lines[1], '');
    assert.strictEqual(lines[2], 'API_KEY="sk#hash"');
    assert.strictEqual(lines[3], 'export DB_PASSWORD="p=ass word"');
    assert.strictEqual(lines[4], 'APP_NAME="My App"');
    assert.strictEqual(lines[5], 'PORT=8080');
    assert.strictEqual(lines[6], 'port=9090');
    const parsed = parseEnvString(restored);
    assert.strictEqual(parsed.API_KEY, 'sk#hash');
    assert.strictEqual(parsed.DB_PASSWORD, 'p=ass word');
    assert.strictEqual(parsed.APP_NAME, 'My App');
    assert.strictEqual(parsed.port, '9090');
  });

  it('round-trips awkward values through formatEnvValue', () => {
    const values = {
      HASH: 'abc#def',
      EQ: 'a=b=c',
      SPACE: 'hello world',
      DQ: 'say "hi"',
      SQ: "say 'hi'",
      EMPTY: '',
      URL: 'postgres://u:p@h/db',
      SPECIAL: 'abc!@#$%^&*()'
    };
    for (const [k, v] of Object.entries(values)) {
      const line = `${k}=${formatEnvValue(v)}`;
      assert.strictEqual(parseEnvString(line)[k], v, `mismatch for ${k}`);
    }
    assert.strictEqual(formatEnvValue('real_test_api_123', 'double'), '"real_test_api_123"');
    assert.strictEqual(formatEnvValue('', 'double'), '""');
  });
});

describe('Secret identification heuristic', () => {
  it('matches documented substring policy case-insensitively', () => {
    const keys = getSecretKeys({ API_KEY: 'a', DB_PASSWORD: 'b', JWT_SECRET: 'c', MY_TOKEN_X: 'd', APP_NAME: 'e', PORT: 'f', DATABASE_URL: 'g', EMPTY_VALUE: 'h' });
    assert.deepStrictEqual(keys.sort(), ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET', 'MY_TOKEN_X'].sort());
  });

  it('detectPlaintextSecrets handles export-prefixed lines', () => {
    const config = { secretKeys: ['API_KEY'] };
    assert.strictEqual(detectPlaintextSecrets('export API_KEY=realvalue', config), true);
    assert.strictEqual(detectPlaintextSecrets('export API_KEY=<encrypted>', config), false);
  });
});

describe('CLI process lifecycle (spawn regression)', () => {
  let dir;
  let home;
  let savedHome;
  let savedProfile;
  beforeEach(() => {
    dir = makeDir();
    home = mkdtempSync(join(tmpdir(), 'sv-lifecycle-home-'));
    savedHome = process.env.HOME;
    savedProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
  });
  afterEach(() => {
    process.env.HOME = savedHome;
    process.env.USERPROFILE = savedProfile;
    cleanDir(dir);
    cleanDir(home);
  });
  const run = (args, input, timeoutMs) => runCli(dir, args, input, timeoutMs, home);

  it('status exits naturally without prompts', () => {
    const r = run(['status'], '');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Initialized: no'));
  });

  it('init with piped passwords exits, creates v2 store, redacts .env', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=TEST_API_123456\nDB_PASSWORD="TEST_DB_789012"\nPORT=8080\n');
    const r = run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000);
    assert.strictEqual(r.error, undefined, 'init must exit (hang regression)');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('SecretVeil initialized successfully.'));
    assert.ok(r.stdout.includes('SecretVeil Recovery Key'));
    assert.ok(existsSync(join(storeDir(dir), 'config.json')));
    assert.ok(!existsSync(join(dir, '.secretveil')));
    const config = JSON.parse(readFileSync(join(storeDir(dir), 'config.json'), 'utf8'));
    assert.strictEqual(config.version, 2);
    assert.ok(config.keyEncryption.password && config.keyEncryption.recovery);
    const env = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(env.includes('API_KEY=<encrypted>'));
    assert.ok(env.includes('PORT=8080'));
  });

  it('init rejects mismatched passwords and leaves no store', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    const r = run(['init'], 'aaa\nbbb\n');
    assert.strictEqual(r.error, undefined);
    assert.notStrictEqual(r.status, 0);
    assert.ok(!existsSync(join(storeDir(dir), 'config.json')));
  });

  it('init rejects empty password and leaves no store', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    const r = run(['init'], '\n\n');
    assert.strictEqual(r.error, undefined);
    assert.notStrictEqual(r.status, 0);
    assert.ok(!existsSync(join(storeDir(dir), 'config.json')));
  });

  it('repeated init exits cleanly without touching the store', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    const first = run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000);
    assert.strictEqual(first.status, 0);
    const before = readFileSync(join(storeDir(dir), 'config.json'), 'utf8');
    const second = run(['init'], 'other\nother\n');
    assert.strictEqual(second.error, undefined);
    assert.strictEqual(second.status, 0);
    assert.ok(second.stdout.includes('already initialized'));
    assert.strictEqual(readFileSync(join(storeDir(dir), 'config.json'), 'utf8'), before);
  });

  it('deleted then recreated project path can init fresh', () => {
    const projectPath = dir;
    writeFileSync(join(projectPath, '.env'), 'API_KEY=first-secret\nDB_PASSWORD=db1\nJWT_SECRET=jwt1\nPORT=1\n');
    const first = run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000);
    assert.strictEqual(first.status, 0, first.stdout + first.stderr);
    assert.ok(first.stdout.includes('SecretVeil initialized successfully.'));
    assert.ok(existsSync(join(storeDir(projectPath), 'config.json')));
    const binding = JSON.parse(readFileSync(join(storeDir(projectPath), 'config.json'), 'utf8')).projectBinding;
    assert.ok(binding);
    assert.ok(binding.ino != null);
    assert.ok(readFileSync(join(projectPath, '.env'), 'utf8').includes('API_KEY=<encrypted>'));

    writeFileSync(join(projectPath, 'dump.js'), 'console.log(process.env.API_KEY);');
    const runOk = run(['run', 'node', 'dump.js'], '');
    assert.strictEqual(runOk.status, 0, runOk.stdout + runOk.stderr);
    assert.ok(runOk.stdout.includes('first-secret'));

    rmSync(projectPath, { recursive: true, force: true });
    mkdirSync(projectPath, { recursive: true });
    writeFileSync(join(projectPath, '.env'), 'API_KEY=second-secret\nDB_PASSWORD=db2\nJWT_SECRET=jwt2\nPORT=2\nAPP_NAME=Fresh\n');

    const second = run(['init'], 'lifecycle-pass-2\nlifecycle-pass-2\n', 60000);
    assert.strictEqual(second.status, 0, second.stdout + second.stderr);
    assert.ok(second.stdout.includes('SecretVeil'));
    assert.ok(second.stdout.includes('Found .env'));
    assert.ok(second.stdout.includes('Detected 3 secret(s)'));
    assert.ok(second.stdout.includes('SecretVeil initialized successfully.'));
    assert.ok(!second.stdout.includes('already initialized'));

    const env2 = readFileSync(join(projectPath, '.env'), 'utf8');
    assert.ok(env2.includes('API_KEY=<encrypted>'));
    assert.ok(env2.includes('APP_NAME=Fresh'));
    assert.ok(env2.includes('PORT=2'));
    assert.ok(!env2.includes('second-secret'));

    writeFileSync(join(projectPath, 'dump.js'), 'console.log(process.env.API_KEY+"|"+process.env.PORT+"|"+process.env.APP_NAME);');
    const run2 = run(['run', 'node', 'dump.js'], '');
    assert.strictEqual(run2.status, 0, run2.stdout + run2.stderr);
    assert.ok(run2.stdout.includes('second-secret|2|Fresh'));
    assert.ok(!run2.stdout.includes('first-secret'));

    assert.ok(!existsSync(join(home, '.secretveil', 'vault.key')));
    const credRaw = readFileSync(join(home, '.secretveil', 'credentials.json'), 'utf8');
    assert.ok(!credRaw.includes('lifecycle-pass-2'));
    assert.ok(!credRaw.includes('second-secret'));
  });

  it('two separate projects coexist with independent stores', () => {
    const other = makeDir();
    try {
      writeFileSync(join(dir, '.env'), 'API_KEY=proj-a-key\nPORT=1\n');
      writeFileSync(join(other, '.env'), 'API_KEY=proj-b-key\nPORT=2\n');
      assert.strictEqual(runCli(dir, ['init'], 'pass-a\npass-a\n', 60000, home).status, 0);
      assert.strictEqual(runCli(other, ['init'], 'pass-b\npass-b\n', 60000, home).status, 0);
      assert.notStrictEqual(storeDir(dir), storeDir(other));
      assert.ok(existsSync(join(storeDir(dir), 'config.json')));
      assert.ok(existsSync(join(storeDir(other), 'config.json')));
      writeFileSync(join(dir, 'dump.js'), 'console.log(process.env.API_KEY);');
      writeFileSync(join(other, 'dump.js'), 'console.log(process.env.API_KEY);');
      const a = runCli(dir, ['run', 'node', 'dump.js'], '', 25000, home);
      const b = runCli(other, ['run', 'node', 'dump.js'], '', 25000, home);
      assert.strictEqual(a.status, 0, a.stdout + a.stderr);
      assert.strictEqual(b.status, 0, b.stdout + b.stderr);
      assert.ok(a.stdout.includes('proj-a-key'));
      assert.ok(b.stdout.includes('proj-b-key'));
      assert.ok(!a.stdout.includes('proj-b-key'));
      assert.ok(!b.stdout.includes('proj-a-key'));
    } finally {
      cleanDir(other);
    }
  });

  it('run with wrong password fails with safe error and exits', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    assert.strictEqual(run(['credential', 'remove'], '').status, 0);
    writeFileSync(join(dir, 'v.js'), 'console.log(1);');
    const r = run(['run', 'node', 'v.js'], 'wrong-password\n');
    assert.strictEqual(r.error, undefined);
    assert.notStrictEqual(r.status, 0);
    const combined = (r.stdout || '') + (r.stderr || '');
    assert.ok(combined.includes('Failed to decrypt'));
    assert.ok(!combined.includes('lifecycle-pass-1'));
  });

  it('recover with wrong typed key fails without corrupting the store', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    assert.strictEqual(run(['credential', 'remove'], '').status, 0);
    const before = readFileSync(join(storeDir(dir), 'config.json'), 'utf8');
    const r = run(['recover'], 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nnewpw\nnewpw\n');
    assert.strictEqual(r.error, undefined);
    assert.notStrictEqual(r.status, 0);
    assert.ok((r.stdout + r.stderr).includes('Invalid recovery key'));
    assert.strictEqual(readFileSync(join(storeDir(dir), 'config.json'), 'utf8'), before);
    const ok = run(['unlock'], 'lifecycle-pass-1\n');
    assert.strictEqual(ok.status, 0);
  });

  it('recover uses the stored recovery credential when present', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    const r = run(['recover'], 'reset-pw-9\nreset-pw-9\n');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Using stored recovery credential'));
    assert.strictEqual(run(['credential', 'remove'], '').status, 0);
    const oldFails = run(['unlock'], 'lifecycle-pass-1\n');
    assert.notStrictEqual(oldFails.status, 0);
    const ok = run(['unlock'], 'reset-pw-9\n');
    assert.strictEqual(ok.status, 0);
  });

  it('migrate command is registered', () => {
    const r = run(['--help'], '');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('migrate'));
    assert.ok(r.stdout.includes('recover'));
    assert.ok(r.stdout.includes('password'));
    assert.ok(r.stdout.includes('decrypt'));
    assert.ok(r.stdout.includes('encrypt'));
    assert.ok(r.stdout.includes('Encrypt plaintext secrets in .env'));
  });

  it('decrypt restores secrets to .env without printing values', () => {
    const envText = [
      '# leading comment',
      'API_KEY="real_test_api_123"',
      'DB_PASSWORD="p@ss=word"',
      "JWT_SECRET='jwt#secret=value'",
      'APP_NAME=MyApp',
      'PORT=8080',
      'EMPTY_SECRET=""',
      'QUOTED_VALUE="hello world"',
      'SPECIAL_VALUE=abc!@#$%^&*()',
      'port=9090',
      'mixedCase=KeepMe',
      ''
    ].join('\n');
    writeFileSync(join(dir, '.env'), envText);
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    const redacted = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(redacted.includes('API_KEY=<encrypted>'));
    assert.ok(redacted.includes('# leading comment'));
    assert.ok(redacted.includes('PORT=8080'));
    assert.ok(redacted.includes('APP_NAME=MyApp'));

    const cancelled = run(['decrypt'], 'n\n');
    assert.strictEqual(cancelled.status, 0);
    assert.ok(cancelled.stdout.includes('Continue? (y/N):'));
    assert.ok(cancelled.stdout.includes('Decrypt cancelled. .env left unchanged.'));
    assert.ok(!cancelled.stdout.includes('Decrypting secrets...'));
    assert.strictEqual(readFileSync(join(dir, '.env'), 'utf8'), redacted);

    const cancelledEnter = run(['decrypt'], '\n');
    assert.strictEqual(cancelledEnter.status, 0);
    assert.ok(cancelledEnter.stdout.includes('Decrypt cancelled. .env left unchanged.'));
    assert.ok(!cancelledEnter.stdout.includes('Decrypting secrets...'));
    assert.strictEqual(readFileSync(join(dir, '.env'), 'utf8'), redacted);

    const r = run(['decrypt'], 'y\n');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Warning: plaintext secrets'));
    assert.ok(r.stdout.includes('Continue? (y/N):'));
    assert.ok(r.stdout.includes('Decrypting secrets...'));
    assert.ok(r.stdout.includes('Restoring .env...'));
    assert.ok(r.stdout.includes('Decrypted'));
    assert.ok(r.stdout.includes('Successfully restored plaintext secrets to .env.'));
    assert.ok(!r.stdout.includes('real_test_api_123'));
    assert.ok(!r.stdout.includes('p@ss=word'));
    assert.ok(!r.stdout.includes('jwt#secret=value'));
    assert.ok(!r.stderr.includes('real_test_api_123'));

    const restored = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(restored.includes('# leading comment'));
    assert.ok(restored.includes('API_KEY="real_test_api_123"'));
    assert.ok(restored.includes('DB_PASSWORD="p@ss=word"'));
    assert.ok(restored.includes("JWT_SECRET='jwt#secret=value'"));
    assert.ok(restored.includes('APP_NAME=MyApp'));
    assert.ok(restored.includes('PORT=8080'));
    assert.ok(restored.includes('port=9090'));
    assert.ok(restored.includes('mixedCase=KeepMe'));
    assert.ok(!restored.includes('<encrypted>'));
    const parsed = parseEnvString(restored);
    assert.strictEqual(parsed.API_KEY, 'real_test_api_123');
    assert.strictEqual(parsed.DB_PASSWORD, 'p@ss=word');
    assert.strictEqual(parsed.JWT_SECRET, 'jwt#secret=value');
    assert.strictEqual(parsed.APP_NAME, 'MyApp');
    assert.strictEqual(parsed.PORT, '8080');
    assert.strictEqual(parsed.EMPTY_SECRET, '');
    assert.strictEqual(parsed.QUOTED_VALUE, 'hello world');
    assert.strictEqual(parsed.SPECIAL_VALUE, 'abc!@#$%^&*()');
    assert.strictEqual(parsed.port, '9090');
    assert.strictEqual(parsed.mixedCase, 'KeepMe');
  });

  it('decrypt round-trips encrypted .env back to original secret values', () => {
    const original = [
      '# keep',
      '',
      'API_KEY="real_test_api_123"',
      'DB_PASSWORD="p@ss=word"',
      "JWT_SECRET='jwt value'",
      'APP_NAME=MyApp',
      'PORT=8080',
      'EMPTY_SECRET=""',
      'WITH_HASH="abc#def"',
      'WITH_EQ=a=b=c'
    ].join('\n');
    writeFileSync(join(dir, '.env'), original);
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    const redacted = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(redacted.includes('API_KEY=<encrypted>'));
    assert.ok(redacted.includes('APP_NAME=MyApp'));
    assert.ok(redacted.includes('PORT=8080'));

    const r = run(['decrypt'], 'yes\n');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Successfully restored plaintext secrets to .env.'));
    const restored = readFileSync(join(dir, '.env'), 'utf8');
    assert.strictEqual(restored, original);
    assert.ok(!r.stdout.includes('real_test_api_123'));
  });

  it('encrypt round-trips decrypt → encrypt without losing values', () => {
    const original = [
      '# keep',
      '',
      'API_KEY="real_test_api_123"',
      'DB_PASSWORD="p@ss=word"',
      "JWT_SECRET='jwt#secret=value'",
      'APP_NAME=MyApp',
      'PORT=8080',
      'NODE_ENV=development',
      'EMPTY_SECRET=""',
      'WITH_HASH="abc#def"',
      'WITH_EQ=a=b=c',
      'SPECIAL_VALUE=abc!@#$%^&*()',
      'QUOTED_VALUE="hello world"'
    ].join('\n');
    writeFileSync(join(dir, '.env'), original);
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    const afterInit = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(afterInit.includes('API_KEY=<encrypted>'));
    assert.ok(afterInit.includes('APP_NAME=MyApp'));
    assert.ok(afterInit.includes('PORT=8080'));
    assert.ok(afterInit.includes('NODE_ENV=development'));
    assert.ok(!afterInit.includes('real_test_api_123'));

    assert.strictEqual(run(['decrypt'], 'y\n').status, 0);
    const afterDecrypt = readFileSync(join(dir, '.env'), 'utf8');
    assert.strictEqual(afterDecrypt, original);

    const cancelled = run(['encrypt'], 'n\n');
    assert.strictEqual(cancelled.status, 0);
    assert.ok(cancelled.stdout.includes('Continue? (y/N):'));
    assert.ok(cancelled.stdout.includes('Encrypt cancelled. .env left unchanged.'));
    assert.strictEqual(readFileSync(join(dir, '.env'), 'utf8'), original);

    const enc = run(['encrypt'], 'y\n');
    assert.strictEqual(enc.error, undefined);
    assert.strictEqual(enc.status, 0, enc.stdout + enc.stderr);
    assert.ok(enc.stdout.includes('Warning: plaintext secrets will be encrypted and protected.'));
    assert.ok(enc.stdout.includes('Continue? (y/N):'));
    assert.ok(enc.stdout.includes('Encrypting secrets...'));
    assert.ok(enc.stdout.includes('Using stored credential.'));
    assert.ok(enc.stdout.includes('Updating .env...'));
    assert.ok(enc.stdout.includes('Encrypted'));
    assert.ok(enc.stdout.includes('Successfully protected secrets in .env.'));
    assert.ok(!enc.stdout.includes('real_test_api_123'));
    assert.ok(!enc.stdout.includes('p@ss=word'));
    assert.ok(!enc.stderr.includes('real_test_api_123'));

    const afterEncrypt = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(afterEncrypt.includes('API_KEY=<encrypted>'));
    assert.ok(afterEncrypt.includes('DB_PASSWORD=<encrypted>'));
    assert.ok(afterEncrypt.includes('JWT_SECRET=<encrypted>'));
    assert.ok(afterEncrypt.includes('APP_NAME=MyApp'));
    assert.ok(afterEncrypt.includes('PORT=8080'));
    assert.ok(afterEncrypt.includes('NODE_ENV=development'));
    assert.ok(afterEncrypt.includes('# keep'));
    assert.ok(!afterEncrypt.includes('real_test_api_123'));

    const again = run(['encrypt'], 'y\n');
    assert.strictEqual(again.status, 0);
    assert.ok(again.stdout.includes('No plaintext secrets to encrypt'));

    writeFileSync(join(dir, 'dump.js'), [
      'const keys = ["API_KEY","DB_PASSWORD","JWT_SECRET","APP_NAME","PORT","NODE_ENV","EMPTY_SECRET","WITH_HASH","WITH_EQ","SPECIAL_VALUE","QUOTED_VALUE"];',
      'const out = {};',
      'for (const k of keys) out[k] = process.env[k];',
      'console.log(JSON.stringify(out));'
    ].join('\n'));
    const runOut = run(['run', 'node', 'dump.js'], '');
    assert.strictEqual(runOut.status, 0, runOut.stdout + runOut.stderr);
    const dumped = JSON.parse(runOut.stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop());
    assert.strictEqual(dumped.API_KEY, 'real_test_api_123');
    assert.strictEqual(dumped.DB_PASSWORD, 'p@ss=word');
    assert.strictEqual(dumped.JWT_SECRET, 'jwt#secret=value');
    assert.strictEqual(dumped.APP_NAME, 'MyApp');
    assert.strictEqual(dumped.PORT, '8080');
    assert.strictEqual(dumped.NODE_ENV, 'development');
    assert.strictEqual(dumped.EMPTY_SECRET, '');
    assert.strictEqual(dumped.WITH_HASH, 'abc#def');
    assert.strictEqual(dumped.WITH_EQ, 'a=b=c');
    assert.strictEqual(dumped.SPECIAL_VALUE, 'abc!@#$%^&*()');
    assert.strictEqual(dumped.QUOTED_VALUE, 'hello world');

    assert.strictEqual(run(['decrypt'], 'y\n').status, 0);
    assert.strictEqual(readFileSync(join(dir, '.env'), 'utf8'), original);
  });

  it('decrypt wrong password leaves .env unchanged', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY="keep-secret"\nPORT=9\n');
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    assert.strictEqual(run(['credential', 'remove'], '').status, 0);
    const before = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(before.includes('API_KEY=<encrypted>'));
    const r = run(['decrypt'], 'y\nwrong-password\n');
    assert.notStrictEqual(r.status, 0);
    assert.ok((r.stdout + r.stderr).includes('Failed to decrypt'));
    assert.ok(!(r.stdout + r.stderr).includes('keep-secret'));
    assert.strictEqual(readFileSync(join(dir, '.env'), 'utf8'), before);
  });

  it('decrypt asks for password when stored credentials are removed', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY="typed-secret-xyz"\nPORT=1\n');
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    assert.strictEqual(run(['credential', 'remove'], '').status, 0);
    const r = run(['decrypt'], 'y\nlifecycle-pass-1\n');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Successfully restored plaintext secrets to .env.'));
    const restored = readFileSync(join(dir, '.env'), 'utf8');
    assert.ok(restored.includes('API_KEY="typed-secret-xyz"'));
    const parsed = parseEnvString(restored);
    assert.strictEqual(parsed.API_KEY, 'typed-secret-xyz');
    assert.strictEqual(parsed.PORT, '1');
    assert.ok(!r.stdout.includes('typed-secret-xyz'));
  });

  it('init persists an unlock credential visible via credential status', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    const r = run(['credential', 'status'], '');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Password entry: stored'));
    assert.ok(!r.stdout.includes('stored-pass-1'));
  });

  it('run auto-unlocks from the stored credential with empty stdin', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=AUTO_VALUE\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    writeFileSync(join(dir, 'v.js'), 'console.log(process.env.API_KEY);');
    const r = run(['run', 'node', 'v.js'], '');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('AUTO_VALUE'));
  });

  it('run injects every .env variable with exact names and values', () => {
    const envText = [
      '# leading comment',
      '# SECRET_COMMENT=should-not-exist',
      'API_KEY=sk-test-key-with#hash',
      'DB_PASSWORD="p@ss=word"',
      "JWT_SECRET='jwt#secret=value'",
      'APP_NAME=MyApp',
      'NODE_ENV=development',
      'PORT=8080',
      'DATABASE_URL=postgres://user:pass@localhost:5432/db',
      'SPECIAL_VALUE=abc!@#$%^&*()',
      'QUOTED_VALUE="hello world"',
      'EMPTY_VALUE=',
      'port=9090',
      'mixedCase=KeepMe'
    ].join('\n');
    writeFileSync(join(dir, '.env'), envText);
    assert.strictEqual(run(['init'], 'lifecycle-pass-1\nlifecycle-pass-1\n', 60000).status, 0);
    writeFileSync(join(dir, 'dump.js'), [
      'const keys = ["API_KEY","DB_PASSWORD","JWT_SECRET","APP_NAME","NODE_ENV","PORT","DATABASE_URL","SPECIAL_VALUE","QUOTED_VALUE","EMPTY_VALUE","port","mixedCase","SECRET_COMMENT"];',
      'const out = {};',
      'for (const k of keys) out[k] = process.env[k];',
      'console.log(JSON.stringify(out));'
    ].join('\n'));
    const r = run(['run', 'node', 'dump.js'], '');
    assert.strictEqual(r.error, undefined);
    assert.strictEqual(r.status, 0);
    const line = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop();
    const dumped = JSON.parse(line);
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
    assert.strictEqual(dumped.port, '9090');
    assert.strictEqual(dumped.mixedCase, 'KeepMe');
    assert.strictEqual(dumped.SECRET_COMMENT, undefined);
  });

  it('init persists password and recovery without plaintext in credentials.json', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    const init = run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000);
    assert.strictEqual(init.status, 0);
    const status = run(['credential', 'status'], '');
    assert.ok(status.stdout.includes('Password entry: stored'));
    assert.ok(status.stdout.includes('Recovery entry: stored'));
    const credPath = join(home, '.secretveil', 'credentials.json');
    assert.ok(existsSync(credPath));
    const raw = readFileSync(credPath, 'utf8');
    assert.ok(!raw.includes('stored-pass-1'));
    const parsed = JSON.parse(raw);
    const entry = Object.values(parsed.projects)[0];
    assert.strictEqual(entry.backend, 'keychain');
    assert.ok(entry.path);
    assert.ok(entry.updatedAt);
    assert.ok(!entry.slots);
    assert.ok(!existsSync(join(home, '.secretveil', 'vault.key')));
    assert.ok(!existsSync(join(dir, '.secretveil', 'vault.key')));
    assert.ok(!existsSync(join(dir, '.secretveil', 'key')));
    assert.ok(!existsSync(join(dir, '.secretveil', 'master.key')));
    assert.ok(!existsSync(join(dir, '.secretveil')));
    const projectFiles = [
      join(dir, '.env'),
      join(storeDir(dir), 'config.json'),
      join(storeDir(dir), 'secrets.enc')
    ];
    for (const file of projectFiles) {
      assert.ok(!readFileSync(file, 'utf8').includes('stored-pass-1'));
    }
  });

  it('decrypt retrieves unlock credential from the global store', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY="from-global-store"\nPORT=7\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    assert.ok(readFileSync(join(dir, '.env'), 'utf8').includes('API_KEY=<encrypted>'));
    const r = run(['decrypt'], 'y\n');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes('Using stored credential.'));
    assert.ok(readFileSync(join(dir, '.env'), 'utf8').includes('API_KEY="from-global-store"'));
    assert.ok(!r.stdout.includes('from-global-store'));
    assert.ok(!existsSync(join(home, '.secretveil', 'vault.key')));
  });

  it('unlock and run survive a new CLI process after lock-equivalent restart', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=RESTART_VALUE\nPORT=3000\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    writeFileSync(join(dir, 'v.js'), 'console.log(process.env.API_KEY + "|" + process.env.PORT);');
    const first = run(['run', 'node', 'v.js'], '');
    assert.strictEqual(first.status, 0);
    assert.ok(first.stdout.includes('RESTART_VALUE|3000'));
    const unlocked = run(['unlock'], '');
    assert.strictEqual(unlocked.status, 0);
    assert.ok(unlocked.stdout.includes('Using stored credential.'));
    const second = run(['run', 'node', 'v.js'], '');
    assert.strictEqual(second.status, 0);
    assert.ok(second.stdout.includes('RESTART_VALUE|3000'));
  });

  it('corrupted credentials.json fails closed and still accepts a typed password', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=SAFE_OK\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    writeFileSync(join(home, '.secretveil', 'credentials.json'), '{broken');
    writeFileSync(join(dir, 'v.js'), 'console.log(process.env.API_KEY);');
    const auto = run(['run', 'node', 'v.js'], '');
    assert.notStrictEqual(auto.status, 0);
    const typed = run(['run', 'node', 'v.js'], 'stored-pass-1\n');
    assert.strictEqual(typed.status, 0);
    assert.ok(typed.stdout.includes('SAFE_OK'));
    assert.ok(!((typed.stdout || '') + (typed.stderr || '')).includes('stored-pass-1'));
  });

  it('credential remove forgets the project and auto-unlock stops working', () => {
    writeFileSync(join(dir, '.env'), 'API_KEY=x\n');
    assert.strictEqual(run(['init'], 'stored-pass-1\nstored-pass-1\n', 60000).status, 0);
    writeFileSync(join(dir, 'v.js'), 'console.log(1);');
    const removed = run(['credential', 'remove'], '');
    assert.strictEqual(removed.status, 0);
    assert.ok(removed.stdout.includes('Removed stored credentials'));
    const after = run(['credential', 'status'], '');
    assert.ok(after.stdout.includes('Password entry: not stored'));
    const r = run(['run', 'node', 'v.js'], '');
    assert.strictEqual(r.error, undefined);
    assert.notStrictEqual(r.status, 0);
    const ok = run(['unlock'], 'stored-pass-1\n');
    assert.strictEqual(ok.status, 0);
  });
});
