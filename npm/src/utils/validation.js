import { readFileSync } from 'node:fs';
import { getEncryptedStorePath, isInitialized, loadConfig, loadSecrets } from '../secrets/store.js';

function existsSync(path) {
  try {
    readFileSync(path, 'utf8');
    return true;
  } catch {
    return false;
  }
}

export function validateConfig(projectDir) {
  if (!isInitialized(projectDir)) {
    return { valid: false, error: 'Config file not found' };
  }

  let config;
  try {
    config = loadConfig(projectDir);
  } catch (e) {
    return { valid: false, error: 'Malformed JSON in config' };
  }

  const errors = [];

  if (!config.version || typeof config.version !== 'number') {
    errors.push('Missing or invalid version');
  }

  if (config.version > 2) {
    errors.push('Unsupported version');
  }

  if (config.version === 1) {
    if (!config.algorithm || config.algorithm !== 'aes-256-gcm') {
      errors.push('Invalid or unsupported algorithm');
    }
    if (!config.kdf || config.kdf !== 'argon2id') {
      errors.push('Invalid or unsupported KDF');
    }
    if (!config.kdfParams || typeof config.kdfParams !== 'object') {
      errors.push('Missing KDF parameters');
    }
    if (!config.salt || typeof config.salt !== 'string') {
      errors.push('Invalid salt');
    }
    if (!Array.isArray(config.secretKeys)) {
      errors.push('Missing or invalid secretKeys');
    }
  } else if (config.version === 2) {
    if (!config.algorithm || config.algorithm !== 'aes-256-gcm') {
      errors.push('Invalid or unsupported algorithm');
    }
    if (!config.kdf || config.kdf !== 'argon2id') {
      errors.push('Invalid or unsupported KDF');
    }
    if (!config.kdfParams || typeof config.kdfParams !== 'object') {
      errors.push('Missing KDF parameters');
    }
    if (!config.salt || typeof config.salt !== 'string') {
      errors.push('Invalid salt');
    }
    if (!Array.isArray(config.secretKeys)) {
      errors.push('Missing or invalid secretKeys');
    }
    if (!config.keyEncryption || typeof config.keyEncryption !== 'object') {
      errors.push('Missing keyEncryption');
    } else {
      if (!config.keyEncryption.password || !config.keyEncryption.password.nonce || !config.keyEncryption.password.ciphertext || !config.keyEncryption.password.tag) {
        errors.push('Invalid password keyEncryption');
      }
      if (!config.keyEncryption.recovery || !config.keyEncryption.recovery.nonce || !config.keyEncryption.recovery.ciphertext || !config.keyEncryption.recovery.tag) {
        errors.push('Invalid recovery keyEncryption');
      }
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true };
}

export function validateStore(projectDir) {
  const configResult = validateConfig(projectDir);
  if (!configResult.valid) {
    return configResult;
  }

  const secretsPath = getEncryptedStorePath(projectDir);
  if (!existsSync(secretsPath)) {
    return { valid: false, error: 'Secrets file not found' };
  }

  let secretsData;
  try {
    secretsData = loadSecrets(projectDir);
  } catch (e) {
    return { valid: false, error: 'Malformed JSON in secrets file' };
  }

  if (!secretsData.secrets || typeof secretsData.secrets !== 'object') {
    return { valid: false, error: 'Missing secrets object' };
  }

  for (const [name, enc] of Object.entries(secretsData.secrets)) {
    if (secretsData.version === 2) {
      if (!enc.nonce || !enc.ciphertext || !enc.tag) {
        return { valid: false, error: `Invalid encryption data for ${name}` };
      }
    } else {
      if (!enc.nonce || !enc.ciphertext || !enc.tag) {
        return { valid: false, error: `Invalid encryption data for ${name}` };
      }
    }
  }

  return { valid: true };
}

export function validateSalt(salt) {
  if (!salt || typeof salt !== 'string') return false;
  if (salt.length < 16) return false;
  return true;
}

export function validateNonce(nonce) {
  if (!nonce || typeof nonce !== 'string') return false;
  if (nonce.length < 12) return false;
  return true;
}

export function validateTag(tag) {
  if (!tag || typeof tag !== 'string') return false;
  if (tag.length !== 32) return false;
  return true;
}

export function validateKeyEncryption(keyEncryption) {
  if (!keyEncryption || typeof keyEncryption !== 'object') return false;
  if (!keyEncryption.password || !keyEncryption.password.nonce || !keyEncryption.password.ciphertext || !keyEncryption.password.tag) return false;
  if (!keyEncryption.recovery || !keyEncryption.recovery.nonce || !keyEncryption.recovery.ciphertext || !keyEncryption.recovery.tag) return false;
  return true;
}