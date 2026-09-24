import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, readFileSync, mkdtempSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createStore, isInitialized, getSecretVeilDirectory, hasStoreArtifacts, loadConfig, clearStaleProjectState } from '../src/secrets/store.js';
import { generateSalt, saltToHex } from '../src/crypto/kdf.js';
import { getAlgorithm } from '../src/crypto/encryption.js';
import { createSession, hasSession, invalidateSession, getSession, clearSession } from '../src/session/session.js';

const TEST_DIR = '/tmp/opencode/secretveil-test';
let homeDir;
let savedHome;
let savedProfile;

describe('Encrypted Store', () => {
  beforeEach(() => {
    savedHome = process.env.HOME;
    savedProfile = process.env.USERPROFILE;
    homeDir = mkdtempSync(join(tmpdir(), 'sv-store-home-'));
    process.env.HOME = homeDir;
    process.env.USERPROFILE = homeDir;
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    process.env.HOME = savedHome;
    process.env.USERPROFILE = savedProfile;
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    try { rmSync(homeDir, { recursive: true, force: true }); } catch (_) {}
  });

  it('creates store files in global ~/.secretveil, not in the project', () => {
    const salt = generateSalt();
    const config = { version: 1, algorithm: getAlgorithm(), kdf: 'argon2id', salt: saltToHex(salt), secretKeys: ['API_KEY'] };
    const secretsData = { version: 1, secrets: {} };
    createStore(TEST_DIR, config, secretsData);
    assert.ok(isInitialized(TEST_DIR));
    assert.ok(!existsSync(join(TEST_DIR, '.secretveil')));
    assert.ok(existsSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json')));
    assert.ok(existsSync(join(getSecretVeilDirectory(TEST_DIR), 'secrets.enc')));
  });

  it('config.json does not contain plaintext secrets', () => {
    const salt = generateSalt();
    const config = { version: 1, algorithm: getAlgorithm(), kdf: 'argon2id', salt: saltToHex(salt), secretKeys: ['API_KEY'] };
    const secretsData = { version: 1, secrets: { API_KEY: { nonce: 'xyz', ciphertext: 'abc', tag: 'def' } } };
    createStore(TEST_DIR, config, secretsData);
    const content = readFileSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json'), 'utf8');
    assert.ok(!content.includes('SBX_API_7F31A92C'));
  });

  it('stores projectBinding and treats recreated directory as not initialized', async () => {
    const salt = generateSalt();
    createStore(TEST_DIR, {
      version: 2, algorithm: getAlgorithm(), kdf: 'argon2id', salt: saltToHex(salt), secretKeys: ['API_KEY'],
      keyEncryption: { password: {}, recovery: {} }
    }, { version: 2, secrets: {} });
    assert.ok(isInitialized(TEST_DIR));
    const binding = loadConfig(TEST_DIR).projectBinding;
    assert.ok(binding);
    assert.equal(typeof binding.ino, 'number');
    assert.ok(hasStoreArtifacts(TEST_DIR));

    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
    assert.ok(hasStoreArtifacts(TEST_DIR));
    assert.ok(!isInitialized(TEST_DIR));

    await clearStaleProjectState(TEST_DIR);
    assert.ok(!hasStoreArtifacts(TEST_DIR));
  });
});

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
});
