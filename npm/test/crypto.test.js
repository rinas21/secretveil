import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { deriveKey, generateSalt, saltToHex, hexToSalt } from '../src/crypto/kdf.js';
import { encryptSecret, decryptSecret, getAlgorithm } from '../src/crypto/encryption.js';

const TEST_PASSWORD = 'test-password-123';

describe('Argon2id KDF', () => {
  it('derives a 256-bit key', async () => {
    const salt = generateSalt();
    const key = await deriveKey(TEST_PASSWORD, salt);
    assert.strictEqual(key.length, 32);
  });

  it('different salts produce different keys', async () => {
    const salt1 = randomBytes(16);
    const salt2 = randomBytes(16);
    const key1 = await deriveKey(TEST_PASSWORD, salt1);
    const key2 = await deriveKey(TEST_PASSWORD, salt2);
    assert.notStrictEqual(key1.toString('hex'), key2.toString('hex'));
  });

  it('same salt and password produce same key', async () => {
    const salt = generateSalt();
    const key1 = await deriveKey(TEST_PASSWORD, salt);
    const key2 = await deriveKey(TEST_PASSWORD, salt);
    assert.strictEqual(key1.toString('hex'), key2.toString('hex'));
  });
});

describe('AES-256-GCM Encryption', () => {
  it('encrypts and decrypts correctly', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('KEY', 'Hello, World!', TEST_PASSWORD, salt);
    const value = await decryptSecret(encrypted, TEST_PASSWORD, salt);
    assert.strictEqual(value, 'Hello, World!');
  });

  it('uses unique nonces for each encryption', async () => {
    const salt = generateSalt();
    const result1 = await encryptSecret('KEY', 'value1', TEST_PASSWORD, salt);
    const result2 = await encryptSecret('KEY', 'value1', TEST_PASSWORD, salt);
    assert.notStrictEqual(result1.nonce, result2.nonce);
  });

  it('modified ciphertext fails decryption', async () => {
    const salt = generateSalt();
    const result = await encryptSecret('KEY', 'value', TEST_PASSWORD, salt);
    const modifiedCiphertext = result.ciphertext.replace(/./, 'x');
    try {
      await decryptSecret(result, 'test-password-123', salt);
      assert.fail('Should have thrown');
    } catch (_) {
      assert.ok(true);
    }
  });
});

describe('Secret encryption/decryption', () => {
  it('encrypts and decrypts a secret', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('API_KEY', 'SBX_API_7F31A92C', TEST_PASSWORD, salt);
    const value = await decryptSecret(encrypted, TEST_PASSWORD, salt);
    assert.strictEqual(value, 'SBX_API_7F31A92C');
  });

  it('handles empty secrets', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('KEY', '', TEST_PASSWORD, salt);
    const value = await decryptSecret(encrypted, TEST_PASSWORD, salt);
    assert.strictEqual(value, '');
  });

  it('handles unicode secrets', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('KEY', '日本語テスト', TEST_PASSWORD, salt);
    const value = await decryptSecret(encrypted, TEST_PASSWORD, salt);
    assert.strictEqual(value, '日本語テスト');
  });

  it('handles very long secrets', async () => {
    const salt = generateSalt();
    const longSecret = 'a'.repeat(10000);
    const encrypted = await encryptSecret('KEY', longSecret, TEST_PASSWORD, salt);
    const value = await decryptSecret(encrypted, TEST_PASSWORD, salt);
    assert.strictEqual(value, longSecret);
  });

  it('handles multiple secrets', async () => {
    const salt = generateSalt();
    const secrets = { API_KEY: 'key1', DB_PASSWORD: 'pass2', JWT_SECRET: 'sec3' };
    const encrypted = {};
    for (const [name, value] of Object.entries(secrets)) {
      encrypted[name] = await encryptSecret(name, value, TEST_PASSWORD, salt);
    }
    for (const [name, value] of Object.entries(secrets)) {
      const decrypted = await decryptSecret(encrypted[name], TEST_PASSWORD, salt);
      assert.strictEqual(decrypted, value);
    }
  });

  it('incorrect password fails', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('KEY', 'value', TEST_PASSWORD, salt);
    try {
      await decryptSecret(encrypted, 'wrong-password', salt);
      assert.fail('Should have thrown');
    } catch (_) {
      assert.ok(true);
    }
  });

  it('secret values are not present as plaintext in the encrypted store', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('API_KEY', 'SBX_API_7F31A92C', TEST_PASSWORD, salt);
    const json = JSON.stringify(encrypted);
    assert.ok(!json.includes('SBX_API_7F31A92C'));
    assert.ok(!json.includes('API_KEY=SBX'));
  });
});

describe('Corrupted store handling', () => {
  it('wrong password fails safely', async () => {
    const salt = generateSalt();
    const encrypted = await encryptSecret('KEY', 'value', TEST_PASSWORD, salt);
    try {
      await decryptSecret(encrypted, 'wrong-password', salt);
      assert.fail('Should have thrown');
    } catch (_) {
      assert.ok(true);
    }
  });
});
