import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, mkdirSync, mkdtempSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateSalt, saltToHex, hexToSalt, deriveKey } from '../src/crypto/kdf.js';
import {
  encryptSecret, decryptSecret, getAlgorithm, encryptWithKey, decryptWithKey,
  wrapKey, unwrapKey, generateDEK, generateRecoveryKey, normalizeRecoveryKey,
  validateRecoveryKeyFormat, hexToDEK
} from '../src/crypto/encryption.js';
import {
  createStore, loadConfig, loadSecrets, isInitialized, atomicReplace,
  getSecretVeilDirectory
} from '../src/secrets/store.js';
import { clearSession, createSession, hasSession } from '../src/session/session.js';
import { unlock } from '../src/commands/unlock.js';
import { recover } from '../src/commands/recover.js';
import { password as changePassword } from '../src/commands/password.js';
import { recovery as recoveryCmd } from '../src/commands/recovery.js';
import { migrate } from '../src/commands/migrate.js';

const TEST_DIR = '/tmp/opencode/secretveil-recovery-test';
const KDF_PARAMS = { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 };
const PASSWORD = 'recovery-test-pass';
const SECRETS = { API_KEY: 'SBX_API_RECOVERY_TEST', DB_PASSWORD: 'db-secret-value' };

let _home, _savedHome, _savedProfile, recoveryKey;

function isolateHome() {
  _savedHome = process.env.HOME;
  _savedProfile = process.env.USERPROFILE;
  _home = mkdtempSync(join(tmpdir(), 'sv-rec-home-'));
  process.env.HOME = _home;
  process.env.USERPROFILE = _home;
}

function restoreHome() {
  process.env.HOME = _savedHome;
  process.env.USERPROFILE = _savedProfile;
  try { rmSync(_home, { recursive: true, force: true }); } catch (_) {}
}

async function buildV2Store(projectDir, password, secrets, recKey) {
  const dek = generateDEK();
  const salt = generateSalt();
  const recoverySalt = generateSalt();
  const passwordWrapper = await wrapKey(dek, password, salt, KDF_PARAMS);
  const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recKey), recoverySalt, KDF_PARAMS);
  const keyEncryption = {
    password: {
      salt: passwordWrapper.salt,
      nonce: passwordWrapper.nonce,
      ciphertext: passwordWrapper.ciphertext,
      tag: passwordWrapper.tag
    },
    recovery: {
      salt: recoveryWrapper.salt,
      nonce: recoveryWrapper.nonce,
      ciphertext: recoveryWrapper.ciphertext,
      tag: recoveryWrapper.tag
    }
  };
  const encrypted = {};
  for (const [name, value] of Object.entries(secrets)) {
    encrypted[name] = await encryptWithKey(JSON.stringify({ name, value }), dek);
  }
  const config = {
    version: 2,
    algorithm: getAlgorithm(),
    kdf: 'argon2id',
    kdfParams: KDF_PARAMS,
    salt: saltToHex(salt),
    secretKeys: Object.keys(secrets),
    keyEncryption
  };
  createStore(projectDir, config, {
    version: 2,
    algorithm: getAlgorithm(),
    keyEncryption,
    secrets: encrypted
  });
  return { dek, config };
}

async function buildV1Store(projectDir, password, secrets) {
  const salt = generateSalt();
  const encrypted = {};
  for (const [name, value] of Object.entries(secrets)) {
    encrypted[name] = await encryptSecret(name, value, password, salt, KDF_PARAMS);
  }
  const config = {
    version: 1,
    algorithm: getAlgorithm(),
    kdf: 'argon2id',
    kdfParams: KDF_PARAMS,
    salt: saltToHex(salt),
    secretKeys: Object.keys(secrets)
  };
  createStore(projectDir, config, { version: 1, secrets: encrypted });
}

describe('Unlock via password / recovery', () => {
  beforeEach(async () => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
  });
  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('unwraps DEK with password', async () => {
    const config = loadConfig(TEST_DIR);
    const dekHex = await unwrapKey(config.keyEncryption.password, PASSWORD, config.kdfParams);
    assert.strictEqual(Buffer.from(dekHex, 'hex').length, 32);
  });

  it('unwraps DEK with recovery key', async () => {
    const config = loadConfig(TEST_DIR);
    const dekHex = await unwrapKey(
      config.keyEncryption.recovery,
      normalizeRecoveryKey(recoveryKey),
      config.kdfParams
    );
    assert.strictEqual(Buffer.from(dekHex, 'hex').length, 32);
  });

  it('accepts spaced / lowercase recovery key', async () => {
    const config = loadConfig(TEST_DIR);
    const spaced = recoveryKey.toLowerCase().replace(/-/g, ' ');
    const dekHex = await unwrapKey(
      config.keyEncryption.recovery,
      normalizeRecoveryKey(spaced),
      config.kdfParams
    );
    assert.strictEqual(Buffer.from(dekHex, 'hex').length, 32);
  });

  it('rejects wrong password', async () => {
    const config = loadConfig(TEST_DIR);
    await assert.rejects(
      () => unwrapKey(config.keyEncryption.password, 'wrong-password', config.kdfParams)
    );
  });

  it('rejects wrong recovery key', async () => {
    const config = loadConfig(TEST_DIR);
    const other = normalizeRecoveryKey(generateRecoveryKey());
    await assert.rejects(
      () => unwrapKey(config.keyEncryption.recovery, other, config.kdfParams)
    );
  });
});

describe('Password reset via recover', () => {
  beforeEach(async () => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
  });
  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('re-wraps DEK with new password; secrets still decrypt', async () => {
    const config = loadConfig(TEST_DIR);
    const secretsData = loadSecrets(TEST_DIR);
    const dekHex = await unwrapKey(
      config.keyEncryption.recovery,
      normalizeRecoveryKey(recoveryKey),
      config.kdfParams
    );
    const dek = hexToDEK(dekHex);
    const newPassword = 'brand-new-password';
    const salt = hexToSalt(config.salt);
    const newWrapper = await wrapKey(dek, newPassword, salt, config.kdfParams);
    const newConfig = {
      ...config,
      keyEncryption: {
        ...config.keyEncryption,
        password: {
          salt: newWrapper.salt,
          nonce: newWrapper.nonce,
          ciphertext: newWrapper.ciphertext,
          tag: newWrapper.tag
        }
      }
    };
    atomicReplace(TEST_DIR, newConfig, secretsData);

    const reloaded = loadConfig(TEST_DIR);
    const unlocked = await unwrapKey(reloaded.keyEncryption.password, newPassword, reloaded.kdfParams);
    assert.strictEqual(unlocked, dekHex);
    await assert.rejects(
      () => unwrapKey(reloaded.keyEncryption.password, PASSWORD, reloaded.kdfParams)
    );

    const store = loadSecrets(TEST_DIR);
    const plaintext = await decryptWithKey(
      store.secrets.API_KEY.ciphertext,
      store.secrets.API_KEY.nonce,
      store.secrets.API_KEY.tag,
      dek
    );
    assert.strictEqual(JSON.parse(plaintext).value, SECRETS.API_KEY);
  });

  it('recover command rejects CLI credential args', async () => {
    await assert.rejects(() => recover(['some-key']), /Credentials must not/);
  });
});

describe('Password change re-wraps DEK only', () => {
  beforeEach(async () => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
  });
  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('changes password wrapper without re-encrypting secrets', async () => {
    const before = loadSecrets(TEST_DIR);
    const beforeCipher = before.secrets.API_KEY.ciphertext;
    const config = loadConfig(TEST_DIR);
    const dekHex = await unwrapKey(config.keyEncryption.password, PASSWORD, config.kdfParams);
    const dek = hexToDEK(dekHex);
    const newPassword = 'changed-password';
    const salt = hexToSalt(config.salt);
    const newWrapper = await wrapKey(dek, newPassword, salt, config.kdfParams);
    atomicReplace(TEST_DIR, {
      ...config,
      keyEncryption: {
        ...config.keyEncryption,
        password: {
          salt: newWrapper.salt,
          nonce: newWrapper.nonce,
          ciphertext: newWrapper.ciphertext,
          tag: newWrapper.tag
        }
      }
    }, before);

    const after = loadSecrets(TEST_DIR);
    assert.strictEqual(after.secrets.API_KEY.ciphertext, beforeCipher);
    const unlocked = await unwrapKey(loadConfig(TEST_DIR).keyEncryption.password, newPassword, config.kdfParams);
    assert.strictEqual(unlocked, dekHex);
  });

  it('password command rejects CLI credential args', async () => {
    await assert.rejects(() => changePassword(['pw']), /Credentials must not/);
  });
});

describe('Recovery key regenerate', () => {
  beforeEach(async () => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
  });
  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('new recovery key unwraps; old key fails', async () => {
    const config = loadConfig(TEST_DIR);
    const dekHex = await unwrapKey(config.keyEncryption.password, PASSWORD, config.kdfParams);
    const dek = hexToDEK(dekHex);
    const newKey = generateRecoveryKey();
    const recoverySalt = hexToSalt(config.salt);
    const newWrapper = await wrapKey(dek, normalizeRecoveryKey(newKey), recoverySalt, config.kdfParams);
    atomicReplace(TEST_DIR, {
      ...config,
      keyEncryption: {
        ...config.keyEncryption,
        recovery: {
          salt: newWrapper.salt,
          nonce: newWrapper.nonce,
          ciphertext: newWrapper.ciphertext,
          tag: newWrapper.tag
        }
      }
    }, loadSecrets(TEST_DIR));

    const reloaded = loadConfig(TEST_DIR);
    const unlocked = await unwrapKey(
      reloaded.keyEncryption.recovery,
      normalizeRecoveryKey(newKey),
      reloaded.kdfParams
    );
    assert.strictEqual(unlocked, dekHex);
    await assert.rejects(
      () => unwrapKey(reloaded.keyEncryption.recovery, normalizeRecoveryKey(recoveryKey), reloaded.kdfParams)
    );
  });

  it('recovery command requires regenerate subcommand', async () => {
    await assert.rejects(() => recoveryCmd([]), /Usage: secretveil recovery regenerate/);
    await assert.rejects(() => recoveryCmd(['regenerate', 'extra']), /Credentials must not/);
  });
});

describe('Migrate v1 to v2', () => {
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

  it('migrates v1 store to v2 with DEK wrappers', async () => {
    await buildV1Store(TEST_DIR, PASSWORD, SECRETS);
    assert.strictEqual(loadConfig(TEST_DIR).version, 1);

    const config = loadConfig(TEST_DIR);
    const secretsData = loadSecrets(TEST_DIR);
    const salt = hexToSalt(config.salt);
    const kdfParams = config.kdfParams;
    const oldSecrets = {};
    for (const name of Object.keys(secretsData.secrets)) {
      oldSecrets[name] = await decryptSecret(secretsData.secrets[name], PASSWORD, salt, kdfParams);
    }

    const dek = generateDEK();
    const recKey = generateRecoveryKey();
    const passwordWrapper = await wrapKey(dek, PASSWORD, salt, kdfParams);
    const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recKey), generateSalt(), kdfParams);
    const newSecrets = {};
    for (const [name, value] of Object.entries(oldSecrets)) {
      newSecrets[name] = await encryptWithKey(JSON.stringify({ name, value }), dek);
    }
    const keyEncryption = {
      password: {
        salt: passwordWrapper.salt,
        nonce: passwordWrapper.nonce,
        ciphertext: passwordWrapper.ciphertext,
        tag: passwordWrapper.tag
      },
      recovery: {
        salt: recoveryWrapper.salt,
        nonce: recoveryWrapper.nonce,
        ciphertext: recoveryWrapper.ciphertext,
        tag: recoveryWrapper.tag
      }
    };
    atomicReplace(TEST_DIR, {
      version: 2,
      algorithm: getAlgorithm(),
      kdf: 'argon2id',
      kdfParams,
      salt: config.salt,
      secretKeys: config.secretKeys,
      keyEncryption
    }, { version: 2, algorithm: getAlgorithm(), keyEncryption, secrets: newSecrets });

    const v2 = loadConfig(TEST_DIR);
    assert.strictEqual(v2.version, 2);
    assert.ok(v2.keyEncryption.password);
    assert.ok(v2.keyEncryption.recovery);
    const dekHex = await unwrapKey(v2.keyEncryption.password, PASSWORD, kdfParams);
    const plaintext = await decryptWithKey(
      loadSecrets(TEST_DIR).secrets.API_KEY.ciphertext,
      loadSecrets(TEST_DIR).secrets.API_KEY.nonce,
      loadSecrets(TEST_DIR).secrets.API_KEY.tag,
      hexToDEK(dekHex)
    );
    assert.strictEqual(JSON.parse(plaintext).value, SECRETS.API_KEY);
  });

  it('migrate is no-op for already-v2 store', async () => {
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
    const cwd = process.cwd();
    process.chdir(TEST_DIR);
    const logs = [];
    const orig = console.log;
    console.log = (...a) => logs.push(a.join(' '));
    try {
      await migrate([]);
    } finally {
      console.log = orig;
      process.chdir(cwd);
    }
    assert.ok(logs.join('\n').includes('already version 2'));
  });
});

describe('Recovery security', () => {
  beforeEach(async () => {
    isolateHome();
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    clearSession();
    recoveryKey = generateRecoveryKey();
    await buildV2Store(TEST_DIR, PASSWORD, SECRETS, recoveryKey);
  });
  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    clearSession();
    restoreHome();
  });

  it('store lives under ~/.secretveil, not the project', () => {
    assert.ok(!existsSync(join(TEST_DIR, '.secretveil')));
    assert.ok(existsSync(join(getSecretVeilDirectory(TEST_DIR), 'config.json')));
  });

  it('store files never contain password, recovery key, or plaintext secrets', () => {
    const dir = getSecretVeilDirectory(TEST_DIR);
    const all = [
      readFileSync(join(dir, 'config.json'), 'utf8'),
      readFileSync(join(dir, 'secrets.enc'), 'utf8')
    ].join('\n');
    assert.ok(!all.includes(PASSWORD));
    assert.ok(!all.includes(recoveryKey));
    assert.ok(!all.includes(normalizeRecoveryKey(recoveryKey)));
    assert.ok(!all.includes(SECRETS.API_KEY));
    assert.ok(!all.includes(SECRETS.DB_PASSWORD));
  });

  it('unlock rejects CLI credential args', async () => {
    await assert.rejects(() => unlock(['password']), /Credentials must not/);
  });

  it('validateRecoveryKeyFormat enforces 30 alphanumerics', () => {
    assert.ok(validateRecoveryKeyFormat(recoveryKey));
    assert.ok(validateRecoveryKeyFormat(`SV-${recoveryKey}`));
    assert.ok(!validateRecoveryKeyFormat('too-short'));
  });
});
