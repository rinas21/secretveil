import { writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, loadSecrets, isInitialized, atomicReplace, removeTempFiles, getEncryptedStorePath } from '../secrets/store.js';
import { encryptSecret, decryptSecret, encryptWithKey, decryptWithKey, unwrapKey } from '../crypto/encryption.js';
import { hexToDEK } from '../crypto/encryption.js';
import { deriveKey, generateSalt, hexToSalt } from '../crypto/kdf.js';
import { askPassword } from '../utils/readline.js';
import { createSession, clearSession } from '../session/session.js';
import { randomBytes } from 'node:crypto';

export async function rotate(args) {
  const secretName = args[0];
  if (!secretName || secretName.startsWith('--')) {
    throw new Error('Usage: secretveil rotate <secret-name>');
  }

  const projectDir = process.cwd();
  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const generate = args.includes('--generate') || args.includes('-g');
  console.log('Enter your SecretVeil password to rotate a secret.');
  const password = await askPassword('Password: ');

  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);

  const secretNames = Object.keys(secretsData.secrets || secretsData);
  if (!secretNames.includes(secretName)) {
    throw new Error(`Secret "${secretName}" not found.`);
  }

  if (config.version === 2) {
    await rotateV2(projectDir, config, secretsData, secretName, password, generate);
  } else {
    await rotateV1(projectDir, config, secretsData, secretName, password, generate);
  }
}

async function getNewValue(secretName, generate) {
  let newValue;
  if (generate) {
    newValue = generateRandomSecret(secretName);
    console.log('Generated new random value.');
  } else {
    newValue = await askPassword('Enter new value: ');
  }
  if (!newValue || newValue.length === 0) {
    throw new Error('Secret value cannot be empty.');
  }
  return newValue;
}

async function rotateV1(projectDir, config, secretsData, secretName, password, generate) {
  const salt = hexToSalt(config.salt);
  const kdfParams = config.kdfParams || {};
  const enc = secretsData.secrets ? secretsData.secrets[secretName] : secretsData[secretName];
  await decryptSecret(enc, password, salt, kdfParams);

  const newValue = await getNewValue(secretName, generate);
  const newEnc = await encryptSecret(secretName, newValue, password, generateSalt(), kdfParams);

  const updatedSecrets = {};
  const allNames = Object.keys(secretsData.secrets || secretsData);
  for (const name of allNames) {
    const e = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    updatedSecrets[name] = name === secretName ? newEnc : e;
  }

  const newStoreData = {
    version: secretsData.version || 1,
    algorithm: secretsData.algorithm || 'aes-256-gcm',
    kdf: secretsData.kdf || 'argon2id',
    kdfParams: secretsData.kdfParams || kdfParams,
    salt: secretsData.salt || config.salt,
    secrets: updatedSecrets
  };

  const tempPath = getEncryptedStorePath(projectDir) + '.tmp';
  const finalPath = getEncryptedStorePath(projectDir);
  writeFileSync(tempPath, JSON.stringify(newStoreData, null, 2), { mode: 0o600 });

  try {
    const verifySalt = hexToSalt(newStoreData.salt);
    const verifyEnc = newStoreData.secrets[secretName];
    await decryptSecret(verifyEnc, password, verifySalt, newStoreData.kdfParams);
    rmSync(tempPath);
    writeFileSync(finalPath, JSON.stringify(newStoreData, null, 2), { mode: 0o600 });
    clearSession();
    createSession(projectDir, { ...config, _password: password }, newStoreData);
    console.log(`Rotation successful for "${secretName}".`);
  } catch (_) {
    rmSync(tempPath, { force: true });
    throw new Error('Rotation failed. Previous value preserved.');
  }
}

async function rotateV2(projectDir, config, secretsData, secretName, password, generate) {
  const kdfParams = config.kdfParams || {};
  let dek;
  try {
    const dekHex = await unwrapKey(config.keyEncryption.password, password, kdfParams);
    dek = hexToDEK(dekHex);
  } catch (_) {
    throw new Error('Failed to decrypt secret store.\nCheck your password and SecretVeil configuration.');
  }

  const enc = secretsData.secrets ? secretsData.secrets[secretName] : secretsData[secretName];
  await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek);

  const newValue = await getNewValue(secretName, generate);
  const newEnc = await encryptWithKey(
    JSON.stringify({ name: secretName, value: newValue }),
    dek
  );

  const updatedSecrets = {};
  const allNames = Object.keys(secretsData.secrets || secretsData);
  for (const name of allNames) {
    const e = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    updatedSecrets[name] = name === secretName ? newEnc : e;
  }

  const newStoreData = {
    version: 2,
    algorithm: secretsData.algorithm || 'aes-256-gcm',
    keyEncryption: config.keyEncryption,
    secrets: updatedSecrets
  };

  try {
    const verifyEnc = newStoreData.secrets[secretName];
    await decryptWithKey(verifyEnc.ciphertext, verifyEnc.nonce, verifyEnc.tag, dek);
    atomicReplace(projectDir, config, newStoreData);
    removeTempFiles(projectDir);
    clearSession();
    createSession(projectDir, { ...config }, newStoreData, dek);
    console.log(`Rotation successful for "${secretName}".`);
  } catch (_) {
    removeTempFiles(projectDir);
    throw new Error('Rotation failed. Previous value preserved.');
  }
}

function generateRandomSecret(secretName) {
  const upper = secretName.toUpperCase();
  const prefix = upper.includes('KEY') ? 'SK_' :
                 upper.includes('PASSWORD') || upper.includes('PWD') ? 'PWD_' :
                 upper.includes('SECRET') || upper.includes('TOKEN') ? 'TKN_' : 'VAL_';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = prefix;
  const length = 32 - prefix.length;
  const rb = randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[rb[i] % chars.length];
  }
  return result;
}
