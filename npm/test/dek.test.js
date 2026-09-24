import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, mkdirSync, writeFileSync, readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { deriveKey, generateSalt, saltToHex, hexToSalt } from '../src/crypto/kdf.js';
import {
  encryptSecret, decryptSecret, getAlgorithm, encryptWithKey, decryptWithKey,
  wrapKey, unwrapKey, generateDEK, generateRecoveryKey, normalizeRecoveryKey,
  validateRecoveryKeyFormat, hexToDEK
} from '../src/crypto/encryption.js';
import {
  createStore, loadConfig, loadSecrets, isInitialized, atomicReplace,
  removeTempFiles, getSecretVeilDirectory
} from '../src/secrets/store.js';
import { createSession, clearSession } from '../src/session/session.js';

const TEST_DIR = '/tmp/opencode/secretveil-dek-test';
const KDF_PARAMS = { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 };
let _home;
let _savedHome;
let _savedProfile;

function isolateHome() {
  _savedHome = process.env.HOME;
  _savedProfile = process.env.USERPROFILE;
  _home = mkdtempSync(join(tmpdir(), 'sv-dek-home-'));
  process.env.HOME = _home;
  process.env.USERPROFILE = _home;
}

function restoreHome() {
  process.env.HOME = _savedHome;
  process.env.USERPROFILE = _savedProfile;
  try { rmSync(_home, { recursive: true, force: true }); } catch (_) {}
}

describe('DEK Generation', () => {
  it('generates a 256-bit DEK', () => {
    const dek = generateDEK();
    assert.strictEqual(dek.length, 32);
  });

  it('generates unique DEKs', () => {
    const dek1 = generateDEK();
    const dek2 = generateDEK();
    assert.notStrictEqual(dek1.toString('hex'), dek2.toString('hex'));
  });
});

describe('Key Wrapping', () => {
  it('wraps and unwraps DEK with password', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const wrapped = await wrapKey(dek, 'test-password', salt, KDF_PARAMS);
    assert.ok(wrapped.salt);
    assert.ok(wrapped.nonce);
    assert.ok(wrapped.ciphertext);
    assert.ok(wrapped.tag);
    const unwrapped = await unwrapKey(wrapped, 'test-password', KDF_PARAMS);
    assert.strictEqual(unwrapped, dek.toString('hex'));
  });

  it('wrong password fails to unwrap', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const wrapped = await wrapKey(dek, 'test-password', salt, KDF_PARAMS);
    await assert.rejects(() => unwrapKey(wrapped, 'wrong-password', KDF_PARAMS));
  });

  it('wraps and unwraps DEK with recovery key', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const recoveryKey = generateRecoveryKey();
    const normalized = normalizeRecoveryKey(recoveryKey);
    const wrapped = await wrapKey(dek, normalized, salt, KDF_PARAMS);
    const unwrapped = await unwrapKey(wrapped, normalized, KDF_PARAMS);
    assert.strictEqual(unwrapped, dek.toString('hex'));
  });
});

describe('Recovery Key Format', () => {
  it('generates formatted recovery key', () => {
    const key = generateRecoveryKey();
    assert.ok(/^[A-Z0-9]{5}(-[A-Z0-9]{5}){5}$/.test(key));
  });

  it('normalizes recovery key input', () => {
    const key = generateRecoveryKey();
    const normalized = normalizeRecoveryKey(key);
    assert.strictEqual(normalized.length, 30);
    assert.strictEqual(normalizeRecoveryKey(key.toLowerCase()), normalized);
    assert.strictEqual(normalizeRecoveryKey(`SV-${key}`), normalized);
    assert.strictEqual(normalizeRecoveryKey(key.replace(/-/g, ' ')), normalized);
  });

  it('validates recovery key format', () => {
    assert.ok(validateRecoveryKeyFormat(generateRecoveryKey()));
    assert.ok(!validateRecoveryKeyFormat('short'));
    assert.ok(!validateRecoveryKeyFormat(''));
  });
});

describe('DEK Encryption', () => {
  it('encrypts and decrypts with DEK', async () => {
    const dek = generateDEK();
    const plaintext = JSON.stringify({ name: 'API_KEY', value: 'SBX_API_7F31A92C' });
    const encrypted = await encryptWithKey(plaintext, dek);
    const decrypted = await decryptWithKey(encrypted.ciphertext, encrypted.nonce, encrypted.tag, dek);
    const parsed = JSON.parse(decrypted);
    assert.strictEqual(parsed.value, 'SBX_API_7F31A92C');
  });
});

describe('v2 Store Creation and Migration', () => {
  beforeEach(() => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
  });

  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('creates v2 store with keyEncryption in global home, not project', () => {
    const config = {
      version: 2,
      algorithm: 'aes-256-gcm',
      kdf: 'argon2id',
      salt: 'abc',
      secretKeys: ['API_KEY'],
      keyEncryption: {
        password: { salt: 's', nonce: 'n', ciphertext: 'c', tag: 't' },
        recovery: { salt: 's', nonce: 'n', ciphertext: 'c', tag: 't' }
      }
    };
    const secretsData = {
      version: 2,
      keyEncryption: config.keyEncryption,
      secrets: { API_KEY: { nonce: 'n', ciphertext: 'c', tag: 't' } }
    };
    createStore(TEST_DIR, config, secretsData);
    assert.ok(isInitialized(TEST_DIR));
    assert.ok(!existsSync(join(TEST_DIR, '.secretveil')));
    assert.ok(existsSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json')));
    const loaded = loadConfig(TEST_DIR);
    assert.strictEqual(loaded.version, 2);
    assert.ok(loaded.keyEncryption);
  });

  it('atomicReplace preserves existing data', () => {
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    const secretsData = { version: 1, secrets: {} };
    createStore(TEST_DIR, config, secretsData);
    const newConfig = {
      version: 2,
      algorithm: 'aes-256-gcm',
      kdf: 'argon2id',
      salt: 'abc',
      secretKeys: ['API_KEY'],
      keyEncryption: { password: {}, recovery: {} }
    };
    const newSecrets = { version: 2, keyEncryption: newConfig.keyEncryption, secrets: {} };
    atomicReplace(TEST_DIR, newConfig, newSecrets);
    const loaded = loadConfig(TEST_DIR);
    assert.strictEqual(loaded.version, 2);
  });

  it('removeTempFiles cleans tmp artifacts', () => {
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    const secretsData = { version: 1, secrets: {} };
    createStore(TEST_DIR, config, secretsData);
    const tempPath = join(getSecretVeilDirectory(TEST_DIR), 'secrets.enc.tmp');
    mkdirSync(getSecretVeilDirectory(TEST_DIR), { recursive: true });
    writeFileSync(tempPath, '{}');
    removeTempFiles(TEST_DIR);
    assert.ok(!existsSync(tempPath));
  });
});

describe('Store Format v2 security', () => {
  beforeEach(() => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    restoreHome();
  });

  it('config.json does not contain plaintext secrets', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const password = 'store-pass';
    const passwordWrapper = await wrapKey(dek, password, salt, KDF_PARAMS);
    const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(generateRecoveryKey()), generateSalt(), KDF_PARAMS);
    const enc = await encryptWithKey(JSON.stringify({ name: 'API_KEY', value: 'PLAINTEXT_SECRET_XYZ' }), dek);
    const keyEncryption = {
      password: { salt: passwordWrapper.salt, nonce: passwordWrapper.nonce, ciphertext: passwordWrapper.ciphertext, tag: passwordWrapper.tag },
      recovery: { salt: recoveryWrapper.salt, nonce: recoveryWrapper.nonce, ciphertext: recoveryWrapper.ciphertext, tag: recoveryWrapper.tag }
    };
    const config = {
      version: 2,
      algorithm: getAlgorithm(),
      kdf: 'argon2id',
      kdfParams: KDF_PARAMS,
      salt: saltToHex(salt),
      secretKeys: ['API_KEY'],
      keyEncryption
    };
    createStore(TEST_DIR, config, { version: 2, algorithm: getAlgorithm(), keyEncryption, secrets: { API_KEY: enc } });
    const configContent = readFileSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json'), 'utf8');
    assert.ok(!configContent.includes('PLAINTEXT_SECRET_XYZ'));
    assert.ok(!configContent.includes(password));
  });

  it('secrets.enc does not contain plaintext secrets', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const passwordWrapper = await wrapKey(dek, 'pw', salt, KDF_PARAMS);
    const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(generateRecoveryKey()), generateSalt(), KDF_PARAMS);
    const enc = await encryptWithKey(JSON.stringify({ name: 'API_KEY', value: 'PLAINTEXT_SECRET_XYZ' }), dek);
    const keyEncryption = {
      password: { salt: passwordWrapper.salt, nonce: passwordWrapper.nonce, ciphertext: passwordWrapper.ciphertext, tag: passwordWrapper.tag },
      recovery: { salt: recoveryWrapper.salt, nonce: recoveryWrapper.nonce, ciphertext: recoveryWrapper.ciphertext, tag: recoveryWrapper.tag }
    };
    const config = {
      version: 2,
      algorithm: getAlgorithm(),
      kdf: 'argon2id',
      kdfParams: KDF_PARAMS,
      salt: saltToHex(salt),
      secretKeys: ['API_KEY'],
      keyEncryption
    };
    createStore(TEST_DIR, config, { version: 2, algorithm: getAlgorithm(), keyEncryption, secrets: { API_KEY: enc } });
    const secretsContent = readFileSync(join(getSecretVeilDirectory(TEST_DIR), 'secrets.enc'), 'utf8');
    assert.ok(!secretsContent.includes('PLAINTEXT_SECRET_XYZ'));
  });

  it('store files never contain password or recovery key', async () => {
    const dek = generateDEK();
    const salt = generateSalt();
    const password = 'unique-pw-not-in-store';
    const recoveryKey = generateRecoveryKey();
    const passwordWrapper = await wrapKey(dek, password, salt, KDF_PARAMS);
    const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recoveryKey), generateSalt(), KDF_PARAMS);
    const enc = await encryptWithKey(JSON.stringify({ name: 'API_KEY', value: 'v' }), dek);
    const keyEncryption = {
      password: { salt: passwordWrapper.salt, nonce: passwordWrapper.nonce, ciphertext: passwordWrapper.ciphertext, tag: passwordWrapper.tag },
      recovery: { salt: recoveryWrapper.salt, nonce: recoveryWrapper.nonce, ciphertext: recoveryWrapper.ciphertext, tag: recoveryWrapper.tag }
    };
    const config = {
      version: 2,
      algorithm: getAlgorithm(),
      kdf: 'argon2id',
      kdfParams: KDF_PARAMS,
      salt: saltToHex(salt),
      secretKeys: ['API_KEY'],
      keyEncryption
    };
    createStore(TEST_DIR, config, { version: 2, algorithm: getAlgorithm(), keyEncryption, secrets: { API_KEY: enc } });
    const allFiles = [
      readFileSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json'), 'utf8'),
      readFileSync(join(getSecretVeilDirectory(TEST_DIR), 'secrets.enc'), 'utf8')
    ].join('\n');
    assert.ok(!allFiles.includes(password));
    assert.ok(!allFiles.includes(normalizeRecoveryKey(recoveryKey)));
    assert.ok(!allFiles.includes(recoveryKey));
  });
});
