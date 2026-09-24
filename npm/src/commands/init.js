import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { parseEnvString, isEnvFileExists, readEnvContent } from '../secrets/parser.js';
import { createStore, loadConfig, loadSecrets, isInitialized, removeProjectStore, atomicReplace, reconcileStoreForInit } from '../secrets/store.js';
import { deriveKey, generateSalt, saltToHex, hexToSalt } from '../crypto/kdf.js';
import { encryptSecret, decryptSecret, getAlgorithm, encryptWithKey, decryptWithKey, wrapKey, unwrapKey, generateDEK, generateRecoveryKey, normalizeRecoveryKey } from '../crypto/encryption.js';
import { createSession, clearSession } from '../session/session.js';
import { askPassword } from '../utils/readline.js';
import { getSecretKeys } from '../utils/helpers.js';
import { setCredential, SLOT_PASSWORD, SLOT_RECOVERY } from '../credentials/store.js';

async function persistCredentials(projectDir, password, recoveryKey) {
  try {
    await setCredential(projectDir, SLOT_PASSWORD, password);
    await setCredential(projectDir, SLOT_RECOVERY, normalizeRecoveryKey(recoveryKey));
  } catch (_) {
    console.warn('Warning: could not persist credentials to user storage. You can still unlock by entering them manually.');
  }
}

export function redactEnvContent(envContent, secretKeys) {
  const secretSet = new Set(secretKeys);
  const lines = envContent.split('\n');
  return lines.map(line => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return line;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) return line;
    let key = trimmed.substring(0, eqIndex).trim();
    let prefix = '';
    const exportMatch = key.match(/^export\s+/);
    if (exportMatch) {
      prefix = exportMatch[0];
      key = key.slice(prefix.length).trim();
    }
    if (secretSet.has(key)) {
      return `${prefix}${key}=<encrypted>`;
    }
    return line;
  }).join('\n');
}

export function getValueQuoteStyle(rawValue) {
  if (rawValue.length >= 2 && rawValue.startsWith('"') && rawValue.endsWith('"')) {
    return 'double';
  }
  if (rawValue.length >= 2 && rawValue.startsWith("'") && rawValue.endsWith("'")) {
    return 'single';
  }
  return null;
}

export function collectEnvQuoteStyles(envContent) {
  const styles = {};
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    let key = trimmed.substring(0, eqIndex).trim();
    if (/^export\s+/.test(key)) {
      key = key.replace(/^export\s+/, '').trim();
    }
    if (key === '') continue;
    styles[key] = getValueQuoteStyle(trimmed.substring(eqIndex + 1).trim());
  }
  return styles;
}

export function formatEnvValue(value, quote = null) {
  if (value === '') {
    if (quote === 'double') return '""';
    if (quote === 'single') return "''";
    return '';
  }
  if (quote === 'double' && !value.includes('"')) {
    return `"${value}"`;
  }
  if (quote === 'single' && !value.includes("'")) {
    return `'${value}'`;
  }
  const needsQuotes =
    /^\s|\s$/.test(value) ||
    /[\s#"']/.test(value);
  if (!needsQuotes) {
    return quote === 'double' || quote === 'single' ? `"${value}"` : value;
  }
  if (value.includes('"') && !value.includes("'")) {
    return `'${value}'`;
  }
  if (value.includes("'") && !value.includes('"')) {
    return `"${value}"`;
  }
  if (!value.includes('"')) {
    return `"${value}"`;
  }
  if (!value.includes("'")) {
    return `'${value}'`;
  }
  return `"${value}"`;
}

function normalizeSecretEntry(entry) {
  if (entry && typeof entry === 'object' && Object.prototype.hasOwnProperty.call(entry, 'value')) {
    return {
      value: entry.value,
      quote: entry.quote === 'double' || entry.quote === 'single' ? entry.quote : null
    };
  }
  return { value: entry, quote: null };
}

export function restoreEnvContent(envContent, decryptedSecrets) {
  const lines = envContent.split('\n');
  const seen = new Set();
  const out = lines.map((line) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      return line;
    }
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      return line;
    }
    let key = trimmed.substring(0, eqIndex).trim();
    let prefix = '';
    const exportMatch = key.match(/^export\s+/);
    if (exportMatch) {
      prefix = exportMatch[0];
      key = key.slice(prefix.length).trim();
    }
    let rawValue = trimmed.substring(eqIndex + 1).trim();
    if (
      rawValue.length >= 2 &&
      ((rawValue.startsWith('"') && rawValue.endsWith('"')) ||
        (rawValue.startsWith("'") && rawValue.endsWith("'")))
    ) {
      rawValue = rawValue.slice(1, -1);
    }
    if (rawValue === '<encrypted>' && Object.prototype.hasOwnProperty.call(decryptedSecrets, key)) {
      seen.add(key);
      const { value, quote } = normalizeSecretEntry(decryptedSecrets[key]);
      return `${prefix}${key}=${formatEnvValue(value, quote)}`;
    }
    return line;
  });
  for (const [key, entry] of Object.entries(decryptedSecrets)) {
    if (!seen.has(key)) {
      const { value, quote } = normalizeSecretEntry(entry);
      out.push(`${key}=${formatEnvValue(value, quote)}`);
    }
  }
  return out.join('\n');
}

export async function init(args) {
  const projectDir = process.cwd();

  if (!isEnvFileExists(projectDir)) {
    console.log('No .env file found in the current directory.');
    process.exit(1);
  }

  const envContent = readEnvContent(projectDir);
  await reconcileStoreForInit(projectDir, envContent);

  if (isInitialized(projectDir)) {
    if (loadConfig(projectDir).version === 1) {
      console.log('SecretVeil is initialized with version 1. Run "secretveil migrate" to upgrade.');
      return;
    }
    console.log('SecretVeil is already initialized in this project.');
    return;
  }

  const envVars = parseEnvString(envContent);
  const secretKeys = getSecretKeys(envVars);

  if (secretKeys.length === 0) {
    console.log('No secrets detected in .env file.');
    process.exit(1);
  }

  console.log('SecretVeil');
  console.log('Found .env');
  console.log(`Detected ${secretKeys.length} secret(s): ${secretKeys.join(', ')}`);
  console.log('');
  console.log('Create a password to protect your secrets.');

  const password = await askPassword('Password: ');
  const passwordConfirm = await askPassword('Confirm password: ');

  if (password !== passwordConfirm) {
    console.log('Passwords do not match.');
    process.exit(1);
  }

  if (password.length === 0) {
    console.log('Password cannot be empty.');
    process.exit(1);
  }

  console.log('Encrypting secrets...');

  const salt = generateSalt();
  const saltHex = saltToHex(salt);
  const kdfParams = {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
    hashLength: 32
  };

  const dek = generateDEK();
  const recoveryKey = generateRecoveryKey();

  const passwordWrapper = await wrapKey(dek, password, salt, kdfParams);
  const recoverySalt = generateSalt();
  const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recoveryKey), recoverySalt, kdfParams);

  const secretsData = {};
  const quoteStyles = collectEnvQuoteStyles(envContent);
  for (const key of secretKeys) {
    secretsData[key] = await encryptWithKey(
      JSON.stringify({ name: key, value: envVars[key], quote: quoteStyles[key] ?? null }),
      dek
    );
  }

  const config = {
    version: 2,
    algorithm: getAlgorithm(),
    kdf: 'argon2id',
    kdfParams,
    salt: saltHex,
    secretKeys,
    keyEncryption: {
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
    }
  };

  const storeData = {
    version: 2,
    algorithm: getAlgorithm(),
    keyEncryption: config.keyEncryption,
    secrets: secretsData
  };

  createStore(projectDir, config, storeData);

  console.log('Verifying encrypted store...');
  try {
    const verifyConfig = loadConfig(projectDir);
    const verifySecrets = loadSecrets(projectDir);
    const verifySalt = hexToSalt(verifyConfig.salt);
    const verifyKey = await deriveKey(password, verifySalt, verifyConfig.kdfParams);
    const dekFromPassword = await unwrapKey(verifyConfig.keyEncryption.password, password, verifyConfig.kdfParams);
    const verifyNames = Object.keys(verifySecrets.secrets || verifySecrets);
    for (const name of verifyNames) {
      const enc = verifySecrets.secrets ? verifySecrets.secrets[name] : verifySecrets[name];
      await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, Buffer.from(dekFromPassword, 'hex'));
    }
  } catch (err) {
    console.log('Verification failed. Cleaning up...');
    removeProjectStore(projectDir);
    process.exit(1);
  }

  const redactedEnv = redactEnvContent(envContent, secretKeys);
  writeFileSync(join(projectDir, '.env'), redactedEnv, { mode: 0o600 });
  try { chmodSync(join(projectDir, '.env'), 0o600); } catch (_) {}

  clearSession();

  console.log('');
  console.log('SecretVeil Recovery Key');
  console.log('');
  console.log(recoveryKey);
  console.log('');
  console.log('IMPORTANT: Store this recovery key somewhere secure.');
  console.log('If you lose both your password and recovery key,');
  console.log('your encrypted secrets cannot be recovered.');
  console.log('');
  await persistCredentials(projectDir, password, recoveryKey);
  console.log('SecretVeil initialized successfully.');
}

export async function migrateFromV1(projectDir) {
  const config = loadConfig(projectDir);
  if (config.version !== 1) {
    throw new Error('Store is not version 1.');
  }

  const password = await askPassword('Password: ');
  const secretsData = loadSecrets(projectDir);
  const salt = hexToSalt(config.salt);
  const kdfParams = config.kdfParams || {};
  const secretNames = Object.keys(secretsData.secrets || secretsData);
  const oldSecrets = {};
  for (const name of secretNames) {
    const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    oldSecrets[name] = await decryptSecret(enc, password, salt, kdfParams);
  }

  const dek = generateDEK();
  const recoveryKey = generateRecoveryKey();
  const recoverySalt = generateSalt();

  const passwordWrapper = await wrapKey(dek, password, salt, kdfParams);
  const recoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(recoveryKey), recoverySalt, kdfParams);

  const newSecretsData = {};
  for (const name of secretNames) {
    newSecretsData[name] = await encryptWithKey(
      JSON.stringify({ name, value: oldSecrets[name] }),
      dek
    );
  }

  const newConfig = {
    version: 2,
    algorithm: getAlgorithm(),
    kdf: 'argon2id',
    kdfParams,
    salt: config.salt,
    secretKeys: config.secretKeys,
    keyEncryption: {
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
    }
  };

  const newStoreData = {
    version: 2,
    algorithm: getAlgorithm(),
    keyEncryption: newConfig.keyEncryption,
    secrets: newSecretsData
  };

  atomicReplace(projectDir, newConfig, newStoreData);

  console.log('');
  console.log('SecretVeil Recovery Key');
  console.log('');
  console.log(recoveryKey);
  console.log('');
  console.log('IMPORTANT: Store this recovery key somewhere secure.');
  console.log('If you lose both your password and recovery key,');
  console.log('your encrypted secrets cannot be recovered.');
  console.log('');
  await persistCredentials(projectDir, password, recoveryKey);
  console.log('Migration to version 2 completed successfully.');
}
