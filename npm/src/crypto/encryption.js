import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { deriveKey, saltToHex, hexToSalt } from './kdf.js';
import { createHash } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const DEK_LENGTH = 32;

export function getAlgorithm() {
  return ALGORITHM;
}

export function generateNonce() {
  return randomBytes(IV_LENGTH);
}

export function nonceToHex(nonce) {
  return nonce.toString('hex');
}

export function hexToNonce(hex) {
  return Buffer.from(hex, 'hex');
}

export function generateDEK() {
  return randomBytes(DEK_LENGTH);
}

export function dekToHex(dek) {
  return dek.toString('hex');
}

export function hexToDEK(hex) {
  return Buffer.from(hex, 'hex');
}

export async function encryptWithKey(plaintext, key) {
  const nonce = generateNonce();
  const cipher = createCipheriv(ALGORITHM, key, nonce);
  const input = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    nonce: nonceToHex(nonce),
    ciphertext: encrypted.toString('base64'),
    tag: authTag.toString('hex')
  };
}

export async function decryptWithKey(ciphertextB64, nonceHex, tagHex, key) {
  const nonce = hexToNonce(nonceHex);
  const tag = Buffer.from(tagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextB64, 'base64');
  const decipher = createDecipheriv(ALGORITHM, key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

export async function decryptWithKeyBuffer(ciphertextB64, nonceHex, tagHex, key) {
  const nonce = hexToNonce(nonceHex);
  const tag = Buffer.from(tagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextB64, 'base64');
  const decipher = createDecipheriv(ALGORITHM, key, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
}

export async function encrypt(plaintext, password, salt, kdfParams) {
  const key = await deriveKey(password, salt, kdfParams);
  return encryptWithKey(plaintext, key);
}

export async function decrypt(ciphertextB64, nonceHex, tagHex, password, salt, kdfParams) {
  const key = await deriveKey(password, salt, kdfParams);
  return decryptWithKey(ciphertextB64, nonceHex, tagHex, key);
}

export async function encryptSecret(secretName, value, password, salt, kdfParams) {
  const plaintext = JSON.stringify({ name: secretName, value });
  return encrypt(plaintext, password, salt, kdfParams);
}

export async function decryptSecret(encryptedData, password, salt, kdfParams) {
  const plaintext = await decrypt(
    encryptedData.ciphertext,
    encryptedData.nonce,
    encryptedData.tag,
    password,
    salt,
    kdfParams
  );
  const parsed = JSON.parse(plaintext);
  return parsed.value;
}

export async function wrapKey(dek, password, salt, kdfParams) {
  const key = await deriveKey(password, salt, kdfParams);
  const nonce = generateNonce();
  const cipher = createCipheriv(ALGORITHM, key, nonce);
  const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    salt: saltToHex(salt),
    nonce: nonceToHex(nonce),
    ciphertext: encrypted.toString('base64'),
    tag: authTag.toString('hex')
  };
}

export async function unwrapKey(wrappedData, password, kdfParams) {
  const salt = Buffer.from(wrappedData.salt, 'hex');
  const key = await deriveKey(password, salt, kdfParams);
  const decrypted = await decryptWithKeyBuffer(
    wrappedData.ciphertext,
    wrappedData.nonce,
    wrappedData.tag,
    key
  );
  return decrypted.toString('hex');
}

export function generateRecoveryKey() {
  const bytes = randomBytes(30);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const groups = [];
  for (let i = 0; i < 6; i++) {
    let group = '';
    for (let j = 0; j < 5; j++) {
      const idx = bytes[i * 5 + j] % chars.length;
      group += chars[idx];
    }
    groups.push(group);
  }
  return groups.join('-');
}

export function normalizeRecoveryKey(key) {
  let normalized = key.trim().toUpperCase().replace(/[\s-]/g, '');
  // Accept optional SV- display prefix (e.g. SV-ABCDE-FGHIJ-...)
  if (normalized.startsWith('SV') && normalized.length === 32) {
    normalized = normalized.slice(2);
  }
  return normalized;
}

export function validateRecoveryKeyFormat(key) {
  const normalized = normalizeRecoveryKey(key);
  return /^[A-Z0-9]{30}$/.test(normalized);
}
