import { randomBytes, createHash } from 'node:crypto';
import argon2 from 'argon2';

export const KDF_PARAMS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16
};

export async function deriveKey(password, salt, params = KDF_PARAMS) {
  const merged = { ...KDF_PARAMS, ...params };
  const hash = await argon2.hash(password, {
    type: merged.type,
    memoryCost: merged.memoryCost,
    timeCost: merged.timeCost,
    parallelism: merged.parallelism,
    hashLength: merged.hashLength,
    salt
  });
  return createHash('sha256').update(hash).digest();
}

export async function deriveKeyFromParams(password, salt, kdfParams) {
  const params = {
    ...KDF_PARAMS,
    ...kdfParams
  };
  return deriveKey(password, salt, params);
}

export function generateSalt() {
  return randomBytes(KDF_PARAMS.saltLength);
}

export function saltToHex(salt) {
  return salt.toString('hex');
}

export function hexToSalt(hex) {
  return Buffer.from(hex, 'hex');
}
