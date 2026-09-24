import { loadConfig, loadSecrets, ensureProjectBinding } from '../secrets/store.js';
import { hexToSalt } from '../crypto/kdf.js';
import {
  decryptSecret,
  decryptWithKey,
  unwrapKey,
  hexToDEK,
  normalizeRecoveryKey,
  validateRecoveryKeyFormat
} from '../crypto/encryption.js';
import { askPassword } from '../utils/readline.js';
import { getCredential, setCredential, SLOT_PASSWORD, SLOT_RECOVERY } from './store.js';

async function safeGet(projectDir, slot) {
  try {
    return await getCredential(projectDir, slot);
  } catch (_) {
    return null;
  }
}

async function safeSet(projectDir, slot, value) {
  try {
    await setCredential(projectDir, slot, value);
  } catch (_) {
    console.warn('Warning: could not persist credential to user storage.');
  }
}

async function verifyDEK(secretsData, secretNames, dek) {
  for (const name of secretNames) {
    const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek);
  }
}

async function resolveV1(projectDir, config, secretsData, secretNames, kdfParams) {
  const salt = hexToSalt(config.salt);
  const tryPassword = async (password) => {
    for (const name of secretNames) {
      const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
      await decryptSecret(enc, password, salt, kdfParams);
    }
  };

  const stored = await safeGet(projectDir, SLOT_PASSWORD);
  if (stored) {
    try {
      await tryPassword(stored);
      console.log('Using stored credential.');
      return { password: stored, via: 'stored-password' };
    } catch (_) {}
  }

  console.log('Enter your SecretVeil password to unlock this project.');
  const input = await askPassword('Password: ');
  try {
    await tryPassword(input);
    await safeSet(projectDir, SLOT_PASSWORD, input);
    return { password: input, via: 'typed-password' };
  } catch (_) {
    throw new Error('Failed to decrypt secret store.\nCheck your password and SecretVeil configuration.');
  }
}

async function resolveV2(projectDir, config, secretsData, secretNames, kdfParams) {
  const stored = await safeGet(projectDir, SLOT_PASSWORD);
  if (stored) {
    try {
      const dekHex = await unwrapKey(config.keyEncryption.password, stored, kdfParams);
      const dek = hexToDEK(dekHex);
      await verifyDEK(secretsData, secretNames, dek);
      console.log('Using stored credential.');
      return { dek, via: 'stored-password' };
    } catch (_) {}
  }

  console.log('Enter your SecretVeil password or recovery key to unlock.');
  const input = await askPassword('Password or recovery key: ');
  const normalized = normalizeRecoveryKey(input);
  const isRecovery = validateRecoveryKeyFormat(normalized);
  try {
    let dekHex;
    if (isRecovery) {
      dekHex = await unwrapKey(config.keyEncryption.recovery, normalized, kdfParams);
    } else {
      dekHex = await unwrapKey(config.keyEncryption.password, input, kdfParams);
    }
    const dek = hexToDEK(dekHex);
    await verifyDEK(secretsData, secretNames, dek);
    await safeSet(projectDir, isRecovery ? SLOT_RECOVERY : SLOT_PASSWORD, isRecovery ? normalized : input);
    return { dek, via: isRecovery ? 'typed-recovery' : 'typed-password' };
  } catch (_) {
    throw new Error('Failed to decrypt secret store.\nCheck your password/recovery key and SecretVeil configuration.');
  }
}

export async function resolveDEK(projectDir) {
  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);
  const secretNames = Object.keys(secretsData.secrets || secretsData);
  const kdfParams = config.kdfParams || {};
  let resolved;
  if (config.version === 2) {
    resolved = await resolveV2(projectDir, config, secretsData, secretNames, kdfParams);
  } else {
    resolved = await resolveV1(projectDir, config, secretsData, secretNames, kdfParams);
  }
  try {
    ensureProjectBinding(projectDir);
  } catch (_) {}
  return {
    config: loadConfig(projectDir),
    secretsData: loadSecrets(projectDir),
    ...resolved
  };
}
