import { decryptSecret, decryptWithKey } from '../crypto/encryption.js';
import { loadConfig, loadSecrets } from '../secrets/store.js';
import { hexToSalt } from '../crypto/kdf.js';
import { hexToDEK } from '../crypto/encryption.js';
import { unwrapKey } from '../crypto/encryption.js';

export const ENCRYPTED_PLACEHOLDER = '<encrypted>';

export function buildChildEnv(processEnv, parsedEnv, decryptedSecrets) {
  const child = { ...processEnv };
  for (const [name, value] of Object.entries(parsedEnv)) {
    if (value === ENCRYPTED_PLACEHOLDER) {
      continue;
    }
    child[name] = value;
  }
  for (const [name, value] of Object.entries(decryptedSecrets)) {
    child[name] = value;
  }
  return child;
}

export async function decryptInMemory(projectDir, password) {
  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);
  if (config.version === 2) {
    return decryptInMemoryV2(projectDir, password);
  }
  const salt = hexToSalt(config.salt);
  const kdfParams = config.kdfParams || {};
  const secretNames = Object.keys(secretsData.secrets || secretsData);
  const decrypted = {};
  for (const name of secretNames) {
    const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    decrypted[name] = await decryptSecret(enc, password, salt, kdfParams);
  }
  return decrypted;
}

export async function decryptInMemoryV2(projectDir, password) {
  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);
  const kdfParams = config.kdfParams || {};
  const dekHex = await unwrapKey(config.keyEncryption.password, password, kdfParams);
  const dek = hexToDEK(dekHex);
  return decryptInMemoryWithDEK(projectDir, dek);
}

export async function decryptInMemoryWithDEK(projectDir, dek) {
  const secretsData = loadSecrets(projectDir);
  const secretNames = Object.keys(secretsData.secrets || secretsData);
  const decrypted = {};
  for (const name of secretNames) {
    const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    decrypted[name] = JSON.parse(await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek)).value;
  }
  return decrypted;
}
