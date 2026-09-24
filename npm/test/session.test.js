import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseEnvString } from '../src/secrets/parser.js';
import { deriveKey, generateSalt, saltToHex, hexToSalt } from '../src/crypto/kdf.js';
import { encryptSecret, decryptSecret, getAlgorithm } from '../src/crypto/encryption.js';
import { createStore, loadConfig, loadSecrets, isInitialized, getSecretVeilDirectory } from '../src/secrets/store.js';
import { createSession, hasSession, invalidateSession, getSession, clearSession } from '../src/session/session.js';

const TEST_DIR = '/tmp/opencode/secretveil-test-session';

describe('Session Management', () => {
  beforeEach(() => {
    clearSession();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    clearSession();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
  });

  it('createSession stores session data', () => {
    const config = { salt: 'abc' };
    const secretsData = { secrets: {} };
    const session = createSession(TEST_DIR, config, secretsData);
    assert.strictEqual(session.projectDir, TEST_DIR);
    assert.ok(session.config);
    assert.ok(session.secretsData);
  });

  it('getSession returns the cached session', () => {
    const config = { salt: 'abc' };
    const secretsData = { secrets: {} };
    createSession(TEST_DIR, config, secretsData);
    const session = getSession();
    assert.ok(session !== null);
  });

  it('hasSession returns true after createSession', () => {
    const config = { salt: 'abc' };
    const secretsData = { secrets: {} };
    createSession(TEST_DIR, config, secretsData);
    assert.ok(hasSession());
  });

  it('invalidateSession clears the session', () => {
    const config = { salt: 'abc' };
    const secretsData = { secrets: {} };
    createSession(TEST_DIR, config, secretsData);
    invalidateSession();
    assert.strictEqual(hasSession(), false);
  });

  it('clearSession clears the session', () => {
    const config = { salt: 'abc' };
    const secretsData = { secrets: {} };
    createSession(TEST_DIR, config, secretsData);
    clearSession();
    assert.strictEqual(hasSession(), false);
  });

  it('session does not contain plaintext secrets on disk', async () => {
    const salt = generateSalt();
    const config = {
      version: 1, algorithm: getAlgorithm(), kdf: 'argon2id',
      kdfParams: { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 },
      salt: saltToHex(salt), secretKeys: ['API_KEY']
    };
    const encrypted = await encryptSecret('API_KEY', 'SBX_API_7F31A92C', 'test-pass', salt);
    const secretsData = { version: 1, secrets: { API_KEY: encrypted } };
    createStore(TEST_DIR, config, secretsData);
    const loadedConfig = loadConfig(TEST_DIR);
    const loadedSecrets = loadSecrets(TEST_DIR);
    const json = JSON.stringify({ config: loadedConfig, secrets: loadedSecrets });
    assert.ok(!json.includes('SBX_API_7F31A92C'));
  });
});
