import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, rmSync, renameSync, statSync, realpathSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { getUserDir, getProjectId } from '../credentials/store.js';

const PROJECTS_DIR = 'projects';
const CONFIG_FILE = 'config.json';
const SECRETS_FILE = 'secrets.enc';
const TEMP_SUFFIX = '.tmp';
const LEGACY_DIR = '.secretveil';

function restrictMode(path, mode) {
  try {
    chmodSync(path, mode);
  } catch (_) {}
}

function ensureDir(dir) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  try {
    chmodSync(dir, 0o700);
  } catch (_) {}
  return dir;
}

/** Global per-project store: ~/.secretveil/projects/<project-id>/ */
export function getSecretVeilDir(projectDir) {
  return join(getUserDir(), PROJECTS_DIR, getProjectId(projectDir));
}

function legacySecretVeilDir(projectDir) {
  return join(projectDir, LEGACY_DIR);
}

function getConfigPath(projectDir) {
  return join(getSecretVeilDir(projectDir), CONFIG_FILE);
}

function getSecretsPath(projectDir) {
  return join(getSecretVeilDir(projectDir), SECRETS_FILE);
}

function legacyConfigPath(projectDir) {
  return join(legacySecretVeilDir(projectDir), CONFIG_FILE);
}

function legacySecretsPath(projectDir) {
  return join(legacySecretVeilDir(projectDir), SECRETS_FILE);
}

function resolveConfigPath(projectDir) {
  const globalPath = getConfigPath(projectDir);
  if (existsSync(globalPath)) return globalPath;
  const legacy = legacyConfigPath(projectDir);
  if (existsSync(legacy)) return legacy;
  return globalPath;
}

function resolveSecretsPath(projectDir) {
  const globalPath = getSecretsPath(projectDir);
  if (existsSync(globalPath)) return globalPath;
  const legacy = legacySecretsPath(projectDir);
  if (existsSync(legacy)) return legacy;
  return globalPath;
}

/** True when config.json + secrets.enc exist (ignores binding). */
export function hasStoreArtifacts(projectDir) {
  return existsSync(resolveConfigPath(projectDir)) && existsSync(resolveSecretsPath(projectDir));
}

/**
 * Bind store to the project directory's device+inode so a deleted/recreated
 * path at the same string location is not treated as the old project.
 */
export function buildProjectBinding(projectDir) {
  let canonical = projectDir;
  try {
    canonical = realpathSync(projectDir);
  } catch (_) {
    canonical = projectDir;
  }
  const st = statSync(canonical);
  // birthtimeMs distinguishes deleted/recreated dirs even when the filesystem reuses inodes
  const birthtimeMs = Math.trunc(st.birthtimeMs || st.ctimeMs || 0);
  return {
    path: canonical.replace(/\\/g, '/').replace(/\/+$/, ''),
    dev: st.dev,
    ino: st.ino,
    birthtimeMs
  };
}

export function projectBindingMatches(projectDir, binding) {
  if (!binding || binding.dev == null || binding.ino == null) {
    return null;
  }
  try {
    const current = buildProjectBinding(projectDir);
    if (current.dev !== binding.dev || current.ino !== binding.ino) {
      return false;
    }
    // Legacy bindings without birthtimeMs: ino/dev only (inode reuse risk on some FS)
    if (binding.birthtimeMs == null || binding.birthtimeMs === 0) {
      return true;
    }
    if (current.birthtimeMs === 0) {
      return true;
    }
    return current.birthtimeMs === binding.birthtimeMs;
  } catch (_) {
    // Path temporarily unreadable — do not treat as stale/mismatched.
    return null;
  }
}

function attachBinding(projectDir, config) {
  try {
    return { ...config, projectBinding: buildProjectBinding(projectDir) };
  } catch (_) {
    return { ...config };
  }
}

/**
 * Initialized only when valid store files exist AND (when a binding is present)
 * the binding still matches this directory. Credential metadata alone never counts.
 */
export function isInitialized(projectDir) {
  if (!hasStoreArtifacts(projectDir)) {
    return false;
  }
  let config;
  try {
    config = JSON.parse(readFileSync(resolveConfigPath(projectDir), 'utf8'));
  } catch (_) {
    return false;
  }
  const match = projectBindingMatches(projectDir, config.projectBinding);
  if (match === false) {
    return false;
  }
  return true;
}

/** Stamp or refresh projectBinding on an existing live store (lazy migration). */
export function ensureProjectBinding(projectDir) {
  if (!hasStoreArtifacts(projectDir)) return false;
  let config;
  let secretsData;
  try {
    config = loadConfig(projectDir);
    secretsData = loadSecrets(projectDir);
  } catch (_) {
    return false;
  }
  const match = projectBindingMatches(projectDir, config.projectBinding);
  if (match === true) {
    return true;
  }
  if (match === false) {
    return false;
  }
  try {
    const next = attachBinding(projectDir, config);
    if (next.projectBinding) {
      atomicReplace(projectDir, next, secretsData);
    }
    return true;
  } catch (_) {
    return true;
  }
}

export function loadConfig(projectDir) {
  const raw = readFileSync(resolveConfigPath(projectDir), 'utf8');
  return JSON.parse(raw);
}

export function saveConfig(projectDir, config) {
  const configPath = getConfigPath(projectDir);
  ensureDir(dirname(configPath));
  writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  restrictMode(configPath, 0o600);
}

export function saveSecrets(projectDir, secretsData) {
  const secretsPath = getSecretsPath(projectDir);
  ensureDir(dirname(secretsPath));
  writeFileSync(secretsPath, JSON.stringify(secretsData, null, 2), { mode: 0o600 });
  restrictMode(secretsPath, 0o600);
}

export function loadSecrets(projectDir) {
  const raw = readFileSync(resolveSecretsPath(projectDir), 'utf8');
  return JSON.parse(raw);
}

export function createStore(projectDir, config, secretsData) {
  ensureDir(getSecretVeilDir(projectDir));
  const bound = attachBinding(projectDir, config);
  saveConfig(projectDir, bound);
  saveSecrets(projectDir, secretsData);
}

export function atomicReplace(projectDir, config, secretsData) {
  const bound = attachBinding(projectDir, config);
  const finalSecretsPath = getSecretsPath(projectDir);
  const finalConfigPath = getConfigPath(projectDir);
  ensureDir(dirname(finalSecretsPath));
  const tempSecretsPath = finalSecretsPath + TEMP_SUFFIX;
  const tempConfigPath = finalConfigPath + TEMP_SUFFIX;
  writeFileSync(tempSecretsPath, JSON.stringify(secretsData, null, 2), { mode: 0o600 });
  writeFileSync(tempConfigPath, JSON.stringify(bound, null, 2), { mode: 0o600 });
  rmSync(finalSecretsPath, { force: true });
  rmSync(finalConfigPath, { force: true });
  renameSync(tempSecretsPath, finalSecretsPath);
  renameSync(tempConfigPath, finalConfigPath);
  restrictMode(finalSecretsPath, 0o600);
  restrictMode(finalConfigPath, 0o600);
}

export function isStoreVersion2(projectDir) {
  try {
    const config = loadConfig(projectDir);
    return config.version === 2;
  } catch {
    return false;
  }
}

export function getEncryptedStorePath(projectDir) {
  return resolveSecretsPath(projectDir);
}

export function getSecretVeilDirectory(projectDir) {
  return getSecretVeilDir(projectDir);
}

export function getTempSecretsPath(projectDir) {
  return getSecretsPath(projectDir) + TEMP_SUFFIX;
}

export function removeTempFiles(projectDir) {
  try { rmSync(getSecretsPath(projectDir) + TEMP_SUFFIX, { force: true }); } catch (_) {}
  try { rmSync(getConfigPath(projectDir) + TEMP_SUFFIX, { force: true }); } catch (_) {}
}

export function removeProjectStore(projectDir) {
  const dir = getSecretVeilDir(projectDir);
  try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  try { rmSync(legacySecretVeilDir(projectDir), { recursive: true, force: true }); } catch (_) {}
}

/**
 * Drop orphaned global store + credentials for this project id.
 * Used when binding shows the directory was recreated, or init reconciles stale state.
 */
export async function clearStaleProjectState(projectDir) {
  removeProjectStore(projectDir);
  try {
    const { removeCredentials } = await import('../credentials/store.js');
    await removeCredentials(projectDir);
  } catch (_) {}
}

/** True when .env still has at least one SecretVeil <encrypted> placeholder. */
export function envHasEncryptedPlaceholders(envContent, secretKeys) {
  const keys = new Set(secretKeys || []);
  if (keys.size === 0) return false;
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    let key = trimmed.substring(0, eqIndex).trim();
    if (/^export\s+/.test(key)) {
      key = key.replace(/^export\s+/, '').trim();
    }
    if (!keys.has(key)) continue;
    const value = trimmed.substring(eqIndex + 1).trim();
    if (value === '<encrypted>' || value === '"<encrypted>"' || value === "'<encrypted>'") {
      return true;
    }
  }
  return false;
}

/**
 * Lazy reconcile before init: clear store when binding mismatches, or when a
 * legacy store has no binding and .env shows no protected placeholders
 * (deleted/recreated project). Do not clear merely because path is unreadable.
 */
export async function reconcileStoreForInit(projectDir, envContent) {
  if (!hasStoreArtifacts(projectDir)) {
    return { cleared: false };
  }
  let config;
  try {
    config = loadConfig(projectDir);
  } catch (_) {
    await clearStaleProjectState(projectDir);
    return { cleared: true, reason: 'corrupt' };
  }
  const match = projectBindingMatches(projectDir, config.projectBinding);
  if (match === false) {
    await clearStaleProjectState(projectDir);
    return { cleared: true, reason: 'binding-mismatch' };
  }
  if (match === true) {
    return { cleared: false };
  }
  // Legacy store without binding, or path unreadable with binding present.
  if (config.projectBinding && match === null) {
    return { cleared: false };
  }
  if (!envHasEncryptedPlaceholders(envContent, config.secretKeys || [])) {
    await clearStaleProjectState(projectDir);
    return { cleared: true, reason: 'orphan-legacy' };
  }
  ensureProjectBinding(projectDir);
  return { cleared: false };
}
