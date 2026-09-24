import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync, chmodSync, realpathSync, renameSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';

export const KEYCHAIN_SERVICE = 'secretveil';
export const SLOT_PASSWORD = 'password';
export const SLOT_RECOVERY = 'recovery';
export const ERR_CREDENTIAL_STORE_CORRUPT = 'CREDENTIAL_STORE_CORRUPT';

const INDEX_FILE = 'credentials.json';
const OBSOLETE_VAULT_KEY = 'vault.key';
const OBSOLETE_FILE_DIR = 'file';

let keytarLoader = () => import('keytar');
let keychainModule = undefined;

export function __setKeytarLoader(fn) {
  keytarLoader = fn;
  keychainModule = undefined;
}

export function __resetCredentialCache() {
  keychainModule = undefined;
}

export function getUserDir() {
  const home = process.env.HOME || (process.platform === 'win32' ? process.env.USERPROFILE : undefined) || homedir();
  return join(home, '.secretveil');
}

export function getProjectId(projectDir) {
  let canonical = projectDir;
  try {
    canonical = realpathSync(projectDir);
  } catch (_) {
    canonical = projectDir;
  }
  if (process.platform === 'win32') {
    canonical = canonical.toLowerCase();
  }
  canonical = canonical.replace(/\\/g, '/').replace(/\/+$/, '');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function corruptError(message) {
  const err = new Error(message);
  err.code = ERR_CREDENTIAL_STORE_CORRUPT;
  return err;
}

function ensureUserDir() {
  const dir = getUserDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  try {
    if (process.platform !== 'win32') {
      chmodSync(dir, 0o700);
    }
  } catch (_) {}
  return dir;
}

function indexPath() {
  return join(getUserDir(), INDEX_FILE);
}

function restrictMode(path, mode) {
  try {
    if (process.platform !== 'win32') {
      chmodSync(path, mode);
    }
  } catch (_) {}
}

function readIndex() {
  const path = indexPath();
  if (!existsSync(path)) {
    return { projects: {} };
  }
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (_) {
    throw corruptError('Credential store is corrupted.');
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid');
    }
    if (parsed.projects == null) {
      parsed.projects = {};
    }
    if (typeof parsed.projects !== 'object' || Array.isArray(parsed.projects)) {
      throw new Error('invalid');
    }
    return parsed;
  } catch (_) {
    throw corruptError('Credential store is corrupted.');
  }
}

function writeIndex(index) {
  ensureUserDir();
  const path = indexPath();
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(index, null, 2), { mode: 0o600 });
  restrictMode(tmp, 0o600);
  renameSync(tmp, path);
  restrictMode(path, 0o600);
}

function recordIndex(projectId, projectDir, backend) {
  const index = readIndex();
  index.projects = index.projects || {};
  index.projects[projectId] = {
    path: projectDir,
    backend,
    updatedAt: new Date().toISOString()
  };
  writeIndex(index);
}

function pruneIndex(projectId) {
  const index = readIndex();
  if (index.projects && index.projects[projectId]) {
    delete index.projects[projectId];
    writeIndex(index);
  }
}

function accountName(projectId, slot) {
  return `${projectId}.${slot}`;
}

async function getKeytar() {
  if (keychainModule !== undefined) {
    return keychainModule;
  }
  if (process.env.SECRETVEIL_TEST_KEYCHAIN) {
    const filePath = process.env.SECRETVEIL_TEST_KEYCHAIN;
    const read = () => {
      try {
        return JSON.parse(readFileSync(filePath, 'utf8'));
      } catch (_) {
        return {};
      }
    };
    const write = (obj) => {
      try {
        mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
      } catch (_) {}
      writeFileSync(filePath, JSON.stringify(obj), { mode: 0o600 });
      restrictMode(filePath, 0o600);
    };
    keychainModule = {
      setPassword: async (service, account, value) => {
        const data = read();
        data[`${service}\0${account}`] = value;
        write(data);
      },
      getPassword: async (service, account) => {
        const data = read();
        const key = `${service}\0${account}`;
        return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
      },
      deletePassword: async (service, account) => {
        const data = read();
        const key = `${service}\0${account}`;
        if (!Object.prototype.hasOwnProperty.call(data, key)) return false;
        delete data[key];
        write(data);
        return true;
      }
    };
    return keychainModule;
  }
  try {
    const mod = await keytarLoader();
    const kt = mod.default || mod;
    if (!kt || typeof kt.setPassword !== 'function' || typeof kt.getPassword !== 'function') {
      keychainModule = null;
      return null;
    }
    const probe = `__secretveil_probe_${process.pid}`;
    await kt.setPassword(KEYCHAIN_SERVICE, probe, 'probe');
    const value = await kt.getPassword(KEYCHAIN_SERVICE, probe);
    try {
      await kt.deletePassword(KEYCHAIN_SERVICE, probe);
    } catch (_) {}
    keychainModule = value === 'probe' ? kt : null;
  } catch (_) {
    keychainModule = null;
  }
  return keychainModule;
}

function checkSlot(slot) {
  if (slot !== SLOT_PASSWORD && slot !== SLOT_RECOVERY) {
    throw new Error('Unknown credential slot.');
  }
}

function cleanupObsoleteArtifacts(projectId) {
  try {
    const vaultPath = join(getUserDir(), OBSOLETE_VAULT_KEY);
    if (existsSync(vaultPath)) {
      rmSync(vaultPath, { force: true });
    }
  } catch (_) {}
  try {
    const blob = join(getUserDir(), OBSOLETE_FILE_DIR, `${projectId}.enc`);
    if (existsSync(blob)) {
      rmSync(blob, { force: true });
    }
  } catch (_) {}
}

export async function setCredential(projectDir, slot, value) {
  checkSlot(slot);
  if (!value) {
    throw new Error('Credential value cannot be empty.');
  }
  const projectId = getProjectId(projectDir);
  const kt = await getKeytar();
  if (!kt) {
    throw new Error('Credential store is unavailable (OS keychain required).');
  }
  await kt.setPassword(KEYCHAIN_SERVICE, accountName(projectId, slot), value);
  const stored = await kt.getPassword(KEYCHAIN_SERVICE, accountName(projectId, slot));
  if (stored !== value) {
    throw new Error('Credential persistence verification failed.');
  }
  recordIndex(projectId, projectDir, 'keychain');
  cleanupObsoleteArtifacts(projectId);
  return 'keychain';
}

export async function getCredential(projectDir, slot) {
  checkSlot(slot);
  const projectId = getProjectId(projectDir);
  try {
    readIndex();
  } catch (err) {
    if (err.code === ERR_CREDENTIAL_STORE_CORRUPT) {
      return null;
    }
    throw err;
  }
  try {
    const kt = await getKeytar();
    if (!kt) return null;
    const value = await kt.getPassword(KEYCHAIN_SERVICE, accountName(projectId, slot));
    return value || null;
  } catch (_) {
    return null;
  }
}

export async function removeCredentials(projectDir) {
  const projectId = getProjectId(projectDir);
  const removed = [];

  try {
    const kt = await getKeytar();
    if (kt) {
      for (const slot of [SLOT_PASSWORD, SLOT_RECOVERY]) {
        try {
          const deleted = await kt.deletePassword(KEYCHAIN_SERVICE, accountName(projectId, slot));
          if (deleted) removed.push(`keychain:${slot}`);
        } catch (_) {}
      }
      try {
        const deleted = await kt.deletePassword(KEYCHAIN_SERVICE, `${projectId}.wrap`);
        if (deleted) removed.push('keychain:wrap');
      } catch (_) {}
    }
  } catch (_) {}

  try {
    pruneIndex(projectId);
    removed.push('index');
  } catch (err) {
    if (err.code !== ERR_CREDENTIAL_STORE_CORRUPT) {
      throw err;
    }
  }

  cleanupObsoleteArtifacts(projectId);
  return removed;
}

export async function credentialStatus(projectDir) {
  const projectId = getProjectId(projectDir);
  const userDir = getUserDir();
  const keychainAvailable = (await getKeytar()) !== null;
  try {
    const index = readIndex();
    const entry = index.projects[projectId];
    const password = await getCredential(projectDir, SLOT_PASSWORD);
    const recovery = await getCredential(projectDir, SLOT_RECOVERY);
    return {
      userDir,
      projectId,
      projectPath: projectDir,
      keychainAvailable,
      passwordStored: password !== null,
      recoveryStored: recovery !== null,
      recordedBackend: entry ? entry.backend : null,
      corrupt: false
    };
  } catch (err) {
    if (err.code === ERR_CREDENTIAL_STORE_CORRUPT) {
      return {
        userDir,
        projectId,
        projectPath: projectDir,
        keychainAvailable,
        passwordStored: false,
        recoveryStored: false,
        recordedBackend: null,
        corrupt: true
      };
    }
    throw err;
  }
}

export function inspectCredentialRecord(projectDir) {
  const projectId = getProjectId(projectDir);
  try {
    const index = readIndex();
    return index.projects[projectId] || null;
  } catch (err) {
    if (err.code === ERR_CREDENTIAL_STORE_CORRUPT) {
      return { corrupt: true };
    }
    throw err;
  }
}

export function userStorePermissions() {
  const dir = getUserDir();
  const result = { dir: null, files: {} };
  try {
    result.dir = statSync(dir).mode & 0o777;
  } catch (_) {}
  const path = join(dir, INDEX_FILE);
  try {
    result.files[INDEX_FILE] = statSync(path).mode & 0o777;
  } catch (_) {}
  return result;
}

export function vaultKeyExists() {
  return existsSync(join(getUserDir(), OBSOLETE_VAULT_KEY));
}
