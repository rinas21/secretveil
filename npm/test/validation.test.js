import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync, mkdirSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateConfig, validateStore, validateSalt, validateNonce, validateTag } from '../src/utils/validation.js';
import { createStore, getSecretVeilDirectory } from '../src/secrets/store.js';

const TEST_DIR = '/tmp/opencode/secretveil-validation-test';
let homeDir, savedHome, savedProfile;

describe('Configuration Validation', () => {
  beforeEach(() => {
    savedHome = process.env.HOME;
    savedProfile = process.env.USERPROFILE;
    homeDir = mkdtempSync(join(tmpdir(), 'sv-val-home-'));
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

  it('validates correct config', () => {
    createStore(TEST_DIR, {
      version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id',
      kdfParams: { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 },
      salt: 'abc123def456', secretKeys: ['API_KEY']
    }, { version: 1, secrets: {} });
    const result = validateConfig(TEST_DIR);
    assert.strictEqual(result.valid, true);
  });

  it('rejects unsupported version', () => {
    createStore(TEST_DIR, {
      version: 99, algorithm: 'aes-256-gcm', kdf: 'argon2id',
      kdfParams: {}, salt: 'abc', secretKeys: []
    }, { version: 99, secrets: {} });
    const result = validateConfig(TEST_DIR);
    assert.strictEqual(result.valid, false);
  });

  it('rejects missing version', () => {
    const storeDir = getSecretVeilDirectory(TEST_DIR);
    mkdirSync(storeDir, { recursive: true });
    writeFileSync(join(storeDir, 'config.json'), JSON.stringify({
      algorithm: 'aes-256-gcm', kdf: 'argon2id', kdfParams: {}, salt: 'abc', secretKeys: []
    }));
    writeFileSync(join(storeDir, 'secrets.enc'), JSON.stringify({ version: 1, secrets: {} }));
    const result = validateConfig(TEST_DIR);
    assert.strictEqual(result.valid, false);
  });

  it('rejects invalid algorithm', () => {
    createStore(TEST_DIR, {
      version: 1, algorithm: 'blowfish', kdf: 'argon2id', kdfParams: {}, salt: 'abc', secretKeys: []
    }, { version: 1, secrets: {} });
    const result = validateConfig(TEST_DIR);
    assert.strictEqual(result.valid, false);
  });

  it('rejects malformed JSON', () => {
    const storeDir = getSecretVeilDirectory(TEST_DIR);
    mkdirSync(storeDir, { recursive: true });
    writeFileSync(join(storeDir, 'config.json'), 'not json');
    writeFileSync(join(storeDir, 'secrets.enc'), '{}');
    const result = validateConfig(TEST_DIR);
    assert.strictEqual(result.valid, false);
  });

  it('validates salt format', () => {
    assert.strictEqual(validateSalt('abc123def456789a'), true);
    assert.strictEqual(validateSalt('ab'), false);
    assert.strictEqual(validateSalt(''), false);
    assert.strictEqual(validateSalt(null), false);
  });

  it('validates nonce format', () => {
    assert.strictEqual(validateNonce('abc123def456'), true);
    assert.strictEqual(validateNonce('ab'), false);
    assert.strictEqual(validateNonce(''), false);
  });

  it('validates tag format', () => {
    assert.strictEqual(validateTag('a'.repeat(32)), true);
    assert.strictEqual(validateTag('ab'), false);
    assert.strictEqual(validateTag(''), false);
  });

  it('validates store', () => {
    createStore(TEST_DIR, {
      version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id',
      kdfParams: {}, salt: 'abc123', secretKeys: ['API_KEY']
    }, { version: 1, secrets: {} });
    const result = validateStore(TEST_DIR);
    assert.strictEqual(result.valid, true);
  });
});
