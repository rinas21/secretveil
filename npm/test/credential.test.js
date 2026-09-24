import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  getProjectId,
  getUserDir,
  setCredential,
  getCredential,
  removeCredentials,
  credentialStatus,
  inspectCredentialRecord,
  userStorePermissions,
  vaultKeyExists,
  SLOT_PASSWORD,
  SLOT_RECOVERY,
  ERR_CREDENTIAL_STORE_CORRUPT,
  __setKeytarLoader,
  __resetCredentialCache
} from '../src/credentials/store.js';
import { invalidateSession } from '../src/session/session.js';
import { generateDEK, wrapKey, encryptWithKey, generateRecoveryKey, normalizeRecoveryKey, getAlgorithm } from '../src/crypto/encryption.js';
import { generateSalt, saltToHex } from '../src/crypto/kdf.js';
import { createStore, loadSecrets, getSecretVeilDirectory } from '../src/secrets/store.js';
import { resolveDEK } from '../src/credentials/resolve.js';

const KDF_PARAMS = { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 };
const realKeytarLoader = () => import('keytar');

let savedHome;
let savedProfile;
let homeDir;
let sharedFake;

function fakeKeychain() {
  const mem = new Map();
  const sep = String.fromCharCode(0);
  return {
    setPassword: async (s, a, v) => { mem.set(s + sep + a, v); },
    getPassword: async (s, a) => (mem.has(s + sep + a) ? mem.get(s + sep + a) : null),
    deletePassword: async (s, a) => mem.delete(s + sep + a)
  };
}

function withKeychainHome() {
  savedHome = process.env.HOME;
  savedProfile = process.env.USERPROFILE;
  homeDir = mkdtempSync(join(tmpdir(), 'sv-cred-home-'));
  process.env.HOME = homeDir;
  process.env.USERPROFILE = homeDir;
  sharedFake = fakeKeychain();
  __setKeytarLoader(async () => ({ default: sharedFake }));
  __resetCredentialCache();
}

function restoreHome() {
  process.env.HOME = savedHome;
  process.env.USERPROFILE = savedProfile;
  __setKeytarLoader(realKeytarLoader);
  __resetCredentialCache();
  try { rmSync(homeDir, { recursive: true, force: true }); } catch (_) {}
}

describe('Credential store: project identity', () => {
  it('produces stable filesystem-safe IDs unique per location', () => {
    const a1 = getProjectId('/tmp/opencode/proj-a');
    const a2 = getProjectId('/tmp/opencode/proj-a');
    const b = getProjectId('/tmp/opencode/proj-b');
    assert.strictEqual(a1, a2);
    assert.notStrictEqual(a1, b);
    assert.ok(/^[0-9a-f]{64}$/.test(a1));
  });

  it('resolves user storage under the home directory', () => {
    assert.ok(getUserDir().endsWith('.secretveil'));
  });
});

describe('Credential store: OS keychain + global index', () => {
  beforeEach(withKeychainHome);
  afterEach(restoreHome);

  it('stores and retrieves password and recovery slots independently', async () => {
    const projectDir = join(homeDir, 'proj');
    assert.strictEqual(await setCredential(projectDir, SLOT_PASSWORD, 'pw-1'), 'keychain');
    assert.strictEqual(await setCredential(projectDir, SLOT_RECOVERY, 'RCV-1'), 'keychain');
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), 'pw-1');
    assert.strictEqual(await getCredential(projectDir, SLOT_RECOVERY), 'RCV-1');
    const record = inspectCredentialRecord(projectDir);
    assert.strictEqual(record.backend, 'keychain');
    assert.ok(!record.slots);
  });

  it('returns null for missing projects and slots', async () => {
    assert.strictEqual(await getCredential(join(homeDir, 'nope'), SLOT_PASSWORD), null);
  });

  it('never persists plaintext credentials in credentials.json', async () => {
    const projectDir = join(homeDir, 'proj');
    await setCredential(projectDir, SLOT_PASSWORD, 'super-secret-pw-xyz');
    await setCredential(projectDir, SLOT_RECOVERY, 'RECOVERY-ABC-123');
    const raw = readFileSync(join(homeDir, '.secretveil', 'credentials.json'), 'utf8');
    assert.ok(!raw.includes('super-secret-pw-xyz'));
    assert.ok(!raw.includes('RECOVERY-ABC-123'));
    const record = JSON.parse(raw).projects[getProjectId(projectDir)];
    assert.deepStrictEqual(Object.keys(record).sort(), ['backend', 'path', 'updatedAt']);
  });

  it('creates no vault.key', async () => {
    const projectDir = join(homeDir, 'proj');
    await setCredential(projectDir, SLOT_PASSWORD, 'pw-1');
    assert.strictEqual(vaultKeyExists(), false);
    assert.ok(!existsSync(join(homeDir, '.secretveil', 'vault.key')));
    assert.ok(!existsSync(join(homeDir, '.secretveil', 'file')));
  });

  it('two projects share the same global credentials.json', async () => {
    const p1 = join(homeDir, 'project-a');
    const p2 = join(homeDir, 'project-b');
    await setCredential(p1, SLOT_PASSWORD, 'pw-a');
    await setCredential(p2, SLOT_PASSWORD, 'pw-b');
    const index = JSON.parse(readFileSync(join(homeDir, '.secretveil', 'credentials.json'), 'utf8'));
    assert.strictEqual(Object.keys(index.projects).length, 2);
    assert.strictEqual(await getCredential(p1, SLOT_PASSWORD), 'pw-a');
    assert.strictEqual(await getCredential(p2, SLOT_PASSWORD), 'pw-b');
  });

  it('remove deletes keychain entries and index metadata', async () => {
    const projectDir = join(homeDir, 'proj');
    await setCredential(projectDir, SLOT_PASSWORD, 'pw-1');
    await setCredential(projectDir, SLOT_RECOVERY, 'RCV-1');
    let status = await credentialStatus(projectDir);
    assert.strictEqual(status.passwordStored, true);
    assert.strictEqual(status.recoveryStored, true);
    assert.ok(!JSON.stringify(status).includes('pw-1'));
    const removed = await removeCredentials(projectDir);
    assert.ok(removed.includes('keychain:password'));
    assert.ok(removed.includes('keychain:recovery'));
    status = await credentialStatus(projectDir);
    assert.strictEqual(status.passwordStored, false);
    assert.strictEqual(status.recoveryStored, false);
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), null);
  });

  it('restricts ~/.secretveil and credentials.json', async () => {
    if (process.platform === 'win32') return;
    const projectDir = join(homeDir, 'proj');
    await setCredential(projectDir, SLOT_PASSWORD, 'perm-pw');
    const perms = userStorePermissions();
    assert.strictEqual(perms.dir, 0o700);
    assert.strictEqual(perms.files['credentials.json'], 0o600);
  });
});

describe('Credential store: no keychain', () => {
  beforeEach(() => {
    savedHome = process.env.HOME;
    savedProfile = process.env.USERPROFILE;
    homeDir = mkdtempSync(join(tmpdir(), 'sv-cred-home-'));
    process.env.HOME = homeDir;
    process.env.USERPROFILE = homeDir;
    __setKeytarLoader(async () => { throw new Error('no keychain'); });
    __resetCredentialCache();
  });

  afterEach(restoreHome);

  it('refuses persistence and creates neither vault.key nor credentials slots', async () => {
    const projectDir = join(homeDir, 'proj');
    await assert.rejects(
      () => setCredential(projectDir, SLOT_PASSWORD, 'pw-1'),
      /Credential store is unavailable/
    );
    assert.strictEqual(vaultKeyExists(), false);
    assert.ok(!existsSync(join(homeDir, '.secretveil', 'vault.key')));
    assert.ok(!existsSync(join(homeDir, '.secretveil', 'credentials.json')));
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), null);
  });
});

describe('Credential store: automatic unlock after restart', () => {
  beforeEach(withKeychainHome);
  afterEach(restoreHome);

  async function buildProject(name, password, secrets) {
    const projectDir = join(homeDir, name);
    mkdirSync(projectDir, { recursive: true });
    const dek = generateDEK();
    const salt = generateSalt();
    const recoveryKey = generateRecoveryKey();
    const passwordWrapper = await wrapKey(dek, password, salt, KDF_PARAMS);
    const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recoveryKey), generateSalt(), KDF_PARAMS);
    const encrypted = {};
    for (const [k, v] of Object.entries(secrets)) {
      encrypted[k] = await encryptWithKey(JSON.stringify({ name: k, value: v }), dek);
    }
    const keyEncryption = {
      password: { salt: passwordWrapper.salt, nonce: passwordWrapper.nonce, ciphertext: passwordWrapper.ciphertext, tag: passwordWrapper.tag },
      recovery: { salt: recoveryWrapper.salt, nonce: recoveryWrapper.nonce, ciphertext: recoveryWrapper.ciphertext, tag: recoveryWrapper.tag }
    };
    const config = { version: 2, algorithm: getAlgorithm(), kdf: 'argon2id', kdfParams: KDF_PARAMS, salt: saltToHex(salt), secretKeys: Object.keys(secrets), keyEncryption };
    createStore(projectDir, config, { version: 2, algorithm: getAlgorithm(), keyEncryption, secrets: encrypted });
    return { projectDir, recoveryKey };
  }

  it('resolveDEK unlocks from the stored password with no prompt (restart simulation)', async () => {
    const { projectDir } = await buildProject('app', 'restart-pw', { API_KEY: 'K1' });
    await setCredential(projectDir, SLOT_PASSWORD, 'restart-pw');
    __resetCredentialCache();
    const logs = [];
    const origLog = console.log;
    console.log = (...a) => logs.push(a.join(' '));
    try {
      const { dek, via } = await resolveDEK(projectDir);
      assert.strictEqual(via, 'stored-password');
      const storeData = loadSecrets(projectDir);
      const enc = storeData.secrets.API_KEY;
      const { decryptWithKey } = await import('../src/crypto/encryption.js');
      assert.strictEqual(JSON.parse(await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek)).value, 'K1');
    } finally {
      console.log = origLog;
    }
  });

  it('stored recovery entry is never returned as the password credential', async () => {
    const { projectDir, recoveryKey } = await buildProject('app2', 'pw-x', { API_KEY: 'K1' });
    await setCredential(projectDir, SLOT_RECOVERY, normalizeRecoveryKey(recoveryKey));
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), null);
    assert.strictEqual(await getCredential(projectDir, SLOT_RECOVERY), normalizeRecoveryKey(recoveryKey));
    const status = await credentialStatus(projectDir);
    assert.strictEqual(status.passwordStored, false);
    assert.strictEqual(status.recoveryStored, true);
  });

  it('project directory never contains password, recovery, store, or persistent key files', async () => {
    const { projectDir } = await buildProject('app3', 'persist-pw-check', { API_KEY: 'K1' });
    await setCredential(projectDir, SLOT_PASSWORD, 'persist-pw-check');
    assert.ok(!existsSync(join(projectDir, '.secretveil')));
    const storeDir = getSecretVeilDirectory(projectDir);
    const configRaw = readFileSync(join(storeDir, 'config.json'), 'utf8');
    const secretsRaw = readFileSync(join(storeDir, 'secrets.enc'), 'utf8');
    assert.ok(!configRaw.includes('persist-pw-check'));
    assert.ok(!secretsRaw.includes('persist-pw-check'));
    assert.ok(!existsSync(join(homeDir, '.secretveil', 'vault.key')));
    const names = readdirSync(storeDir);
    assert.ok(names.includes('config.json'));
    assert.ok(names.includes('secrets.enc'));
  });

  it('session invalidation leaves stored credentials (lock / process death)', async () => {
    const { projectDir } = await buildProject('app4', 'lock-pw-stay', { API_KEY: 'K1' });
    await setCredential(projectDir, SLOT_PASSWORD, 'lock-pw-stay');
    await setCredential(projectDir, SLOT_RECOVERY, 'LOCKRECOVERYKEYVALUE0000000001');
    invalidateSession();
    __resetCredentialCache();
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), 'lock-pw-stay');
    assert.strictEqual(await getCredential(projectDir, SLOT_RECOVERY), 'LOCKRECOVERYKEYVALUE0000000001');
  });
});

describe('Credential store: corruption', () => {
  beforeEach(withKeychainHome);
  afterEach(restoreHome);

  it('marks status corrupt when credentials.json is invalid and ignores keychain until fixed', async () => {
    const projectDir = join(homeDir, 'proj');
    await setCredential(projectDir, SLOT_PASSWORD, 'before-corrupt');
    writeFileSync(join(homeDir, '.secretveil', 'credentials.json'), '{not-json', { mode: 0o600 });
    assert.strictEqual(await getCredential(projectDir, SLOT_PASSWORD), null);
    const status = await credentialStatus(projectDir);
    assert.strictEqual(status.corrupt, true);
    assert.strictEqual(status.passwordStored, false);
    await assert.rejects(() => setCredential(projectDir, SLOT_RECOVERY, 'RCV-X'), (err) => err.code === ERR_CREDENTIAL_STORE_CORRUPT);
  });
});
