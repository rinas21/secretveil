import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEnvString } from '../src/secrets/parser.js';
import { redactEnvContent } from '../src/commands/init.js';
import { getSecretKeys, detectPlaintextSecrets } from '../src/utils/helpers.js';
import { generateDEK, encryptWithKey, decryptWithKey } from '../src/crypto/encryption.js';
import { buildChildEnv, ENCRYPTED_PLACEHOLDER } from '../src/runtime/runner.js';

const NASTY = {
  API_KEY: 'unquoted-123',
  DB_PASSWORD: 'abc123',
  JWT_SECRET: 'jwt value',
  APP_NAME: 'My Test Application',
  GREETING: 'Hello SecretVeil',
  SPECIAL_CHARS: 'abc!@#$%^&*()',
  WITH_SPACES: 'value with spaces and "double quotes"',
  WITH_SQUOTES: "value with 'single quotes'",
  WITH_EQUALS: 'a=b=c',
  WITH_HASH: 'abc#def',
  EMPTY_VALUE: '',
  UNICODE_VALUE: '日本語テスト🔑',
  URL_VALUE: 'postgresql://user@localhost:5432/testdb',
  NUMERIC_VALUE: '8080'
};

function buildEnv() {
  return [
    'API_KEY=unquoted-123',
    'DB_PASSWORD="abc123"',
    "JWT_SECRET='jwt value'",
    'APP_NAME="My Test Application"',
    "GREETING='Hello SecretVeil'",
    'SPECIAL_CHARS="abc!@#$%^&*()"',
    `WITH_SPACES='value with spaces and "double quotes"'`,
    `WITH_SQUOTES="value with 'single quotes'"`,
    'WITH_EQUALS=a=b=c',
    'WITH_HASH="abc#def"',
    'EMPTY_VALUE=""',
    'UNICODE_VALUE="日本語テスト🔑"',
    'URL_VALUE="postgresql://user@localhost:5432/testdb"',
    'NUMERIC_VALUE=8080',
    '# a comment',
    '',
    'export EXPORTED_CFG=kept'
  ].join('\n');
}

describe('.env parsing: quoting and syntax', () => {
  it('parses every documented syntax form exactly', () => {
    const parsed = parseEnvString(buildEnv());
    for (const [key, value] of Object.entries(NASTY)) {
      assert.strictEqual(parsed[key], value, `mismatch for ${key}`);
    }
    assert.strictEqual(parsed.EXPORTED_CFG, 'kept');
  });

  it('surrounding quotes never leak into values', () => {
    const parsed = parseEnvString('DB_PASSWORD="abc123"\nJWT_SECRET=\'xyz\'\nPLAIN=noquotes');
    assert.strictEqual(parsed.DB_PASSWORD, 'abc123');
    assert.strictEqual(parsed.JWT_SECRET, 'xyz');
    assert.strictEqual(parsed.PLAIN, 'noquotes');
    assert.ok(!parsed.DB_PASSWORD.includes('"'));
  });

  it('empty values stay empty strings, never undefined or null', () => {
    const parsed = parseEnvString('EMPTY_VALUE=""\nE2=\nE3=\'\'');
    assert.strictEqual(parsed.EMPTY_VALUE, '');
    assert.strictEqual(parsed.E2, '');
    assert.strictEqual(parsed.E3, '');
    assert.ok(!('MISSING' in parsed));
  });
});

describe('.env classification and preservation', () => {
  it('classifies only secret-named variables', () => {
    const parsed = parseEnvString(buildEnv());
    const secrets = getSecretKeys(parsed).sort();
    assert.deepStrictEqual(secrets, ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET'].sort());
  });

  it('redaction keeps every non-secret line byte-identical', () => {
    const original = buildEnv();
    const redacted = redactEnvContent(original, ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET']);
    const origLines = original.split('\n');
    const newLines = redacted.split('\n');
    assert.strictEqual(origLines.length, newLines.length);
    for (let i = 0; i < origLines.length; i++) {
      const key = (origLines[i].split('=')[0] || '').trim().replace(/^export\s+/, '');
      if (['API_KEY', 'DB_PASSWORD', 'JWT_SECRET'].includes(key)) {
        assert.ok(newLines[i].endsWith('=<encrypted>'), `line ${i} not redacted`);
      } else {
        assert.strictEqual(newLines[i], origLines[i], `line ${i} changed`);
      }
    }
  });

  it('detectPlaintextSecrets flags only real secret values', () => {
    const config = { secretKeys: ['API_KEY', 'DB_PASSWORD'] };
    assert.strictEqual(detectPlaintextSecrets('API_KEY=real\nPORT=1', config), true);
    assert.strictEqual(detectPlaintextSecrets('API_KEY=<encrypted>\nPORT=1', config), false);
  });
});

describe('buildChildEnv injects every parsed variable', () => {
  it('merges decrypted secrets over placeholders and keeps non-secrets exact', () => {
    const parsed = {
      API_KEY: ENCRYPTED_PLACEHOLDER,
      PORT: '8080',
      port: '9090',
      mixedCase: 'KeepMe',
      EMPTY_VALUE: '',
      QUOTED_VALUE: 'hello world',
      SPECIAL_VALUE: 'abc!@#$%^&*()',
      WITH_HASH: 'abc#def',
      WITH_EQUALS: 'a=b=c'
    };
    const secrets = {
      API_KEY: 'sk-test-key-with#hash'
    };
    const child = buildChildEnv({ PATH: '/bin', PORT: 'from-parent' }, parsed, secrets);
    assert.strictEqual(child.API_KEY, 'sk-test-key-with#hash');
    assert.strictEqual(child.PORT, '8080');
    assert.strictEqual(child.port, '9090');
    assert.strictEqual(child.mixedCase, 'KeepMe');
    assert.strictEqual(child.EMPTY_VALUE, '');
    assert.strictEqual(child.QUOTED_VALUE, 'hello world');
    assert.strictEqual(child.SPECIAL_VALUE, 'abc!@#$%^&*()');
    assert.strictEqual(child.WITH_HASH, 'abc#def');
    assert.strictEqual(child.WITH_EQUALS, 'a=b=c');
    assert.ok(!Object.prototype.hasOwnProperty.call(child, 'SECRET_COMMENT'));
    assert.strictEqual(child.PATH, '/bin');
  });

  it('does not inject the encrypted placeholder when no matching secret exists', () => {
    const child = buildChildEnv({}, { ORPHAN: ENCRYPTED_PLACEHOLDER, KEEP: '1' }, {});
    assert.ok(!Object.prototype.hasOwnProperty.call(child, 'ORPHAN'));
    assert.strictEqual(child.KEEP, '1');
  });
});

describe('.env values survive DEK round-trip exactly', () => {
  it('encrypts and decrypts every nasty value without alteration', async () => {
    const dek = generateDEK();
    for (const [name, value] of Object.entries(NASTY)) {
      const enc = await encryptWithKey(JSON.stringify({ name, value }), dek);
      const back = JSON.parse(await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek)).value;
      assert.strictEqual(back, value, `round-trip altered ${name}`);
      assert.strictEqual(typeof back, 'string', `round-trip changed type of ${name}`);
    }
  });
});
