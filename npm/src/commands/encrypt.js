import { writeFileSync, renameSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { getSession, createSession, invalidateSession } from '../session/session.js';
import { isInitialized, loadConfig, loadSecrets, atomicReplace, removeTempFiles } from '../secrets/store.js';
import { encryptSecret, encryptWithKey } from '../crypto/encryption.js';
import { hexToSalt } from '../crypto/kdf.js';
import { resolveDEK } from '../credentials/resolve.js';
import { isEnvFileExists, readEnvContent, getEnvPath, parseEnvString } from '../secrets/parser.js';
import { getSecretKeys } from '../utils/helpers.js';
import { redactEnvContent, collectEnvQuoteStyles } from './init.js';
import { askLine } from '../utils/readline.js';

function isAffirmative(answer) {
  return /^(y|yes)$/i.test(String(answer || '').trim());
}

function atomicWriteEnv(projectDir, content) {
  const envPath = getEnvPath(projectDir);
  const tempPath = join(projectDir, '.env.tmp');
  try {
    writeFileSync(tempPath, content, { mode: 0o600 });
    renameSync(tempPath, envPath);
    try {
      chmodSync(envPath, 0o600);
    } catch (_) {}
  } catch (err) {
    try {
      rmSync(tempPath, { force: true });
    } catch (_) {}
    throw err;
  }
}

/**
 * Plaintext secret keys to encrypt: init heuristic ∩ SecretVeil-protected keys,
 * excluding values already marked <encrypted>.
 */
export function findPlaintextSecretsToEncrypt(envContent, config) {
  const envVars = parseEnvString(envContent);
  const protectedKeys = new Set(config.secretKeys || []);
  const detected = getSecretKeys(envVars);
  return detected.filter((key) => {
    if (!protectedKeys.has(key)) return false;
    if (!Object.prototype.hasOwnProperty.call(envVars, key)) return false;
    return envVars[key] !== '<encrypted>';
  });
}

async function encryptSecretsIntoStore(session, envVars, keysToEncrypt, quoteStyles) {
  const config = session.config;
  const secretsData = session.secretsData;
  const existing = { ...(secretsData.secrets || secretsData) };
  const kdfParams = config.kdfParams || {};

  for (const key of keysToEncrypt) {
    const value = envVars[key];
    const quote = quoteStyles[key] ?? null;
    if (config.version === 2) {
      if (!session.dek) {
        throw new Error('Session missing DEK. Please unlock.');
      }
      existing[key] = await encryptWithKey(
        JSON.stringify({ name: key, value, quote }),
        session.dek
      );
    } else {
      const salt = hexToSalt(config.salt);
      existing[key] = await encryptSecret(key, value, config._password, salt, kdfParams);
    }
  }

  const newSecretsData = config.version === 2
    ? {
        version: 2,
        algorithm: secretsData.algorithm || config.algorithm,
        keyEncryption: secretsData.keyEncryption || config.keyEncryption,
        secrets: existing
      }
    : {
        version: secretsData.version || 1,
        algorithm: secretsData.algorithm || config.algorithm,
        secrets: existing
      };

  return newSecretsData;
}

export async function encrypt(args) {
  if (args && args.length > 0) {
    throw new Error('Usage: secretveil encrypt');
  }

  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  if (!isEnvFileExists(projectDir)) {
    throw new Error('No .env file found in the current directory.');
  }

  const envContent = readEnvContent(projectDir);
  const config = loadConfig(projectDir);
  const keysToEncrypt = findPlaintextSecretsToEncrypt(envContent, config);

  if (keysToEncrypt.length === 0) {
    console.log('No plaintext secrets to encrypt. .env already protected or has no SecretVeil-managed secrets.');
    return;
  }

  console.log('Warning: plaintext secrets will be encrypted and protected.');
  console.log('');
  const confirm = await askLine('Continue? (y/N): ');
  if (!isAffirmative(confirm)) {
    console.log('Encrypt cancelled. .env left unchanged.');
    return;
  }

  console.log('Encrypting secrets...');

  let session = getSession();
  if (!session) {
    const resolved = await resolveDEK(projectDir);
    if (resolved.config.version === 2) {
      session = createSession(projectDir, { ...resolved.config }, resolved.secretsData, resolved.dek);
    } else {
      session = createSession(projectDir, { ...resolved.config, _password: resolved.password }, resolved.secretsData);
    }
  }

  const envVars = parseEnvString(envContent);
  const quoteStyles = collectEnvQuoteStyles(envContent);
  const envSnapshot = envContent;

  let newSecretsData;
  try {
    newSecretsData = await encryptSecretsIntoStore(session, envVars, keysToEncrypt, quoteStyles);
  } catch (_) {
    throw new Error('Failed to encrypt secrets.\nCheck your password/recovery key and SecretVeil configuration.');
  }

  const latestConfig = loadConfig(projectDir);
  try {
    atomicReplace(projectDir, latestConfig, newSecretsData);
    removeTempFiles(projectDir);
  } catch (_) {
    throw new Error('Failed to update encrypted store. .env left unchanged.');
  }

  console.log('Updating .env...');

  try {
    const redacted = redactEnvContent(envSnapshot, keysToEncrypt);
    atomicWriteEnv(projectDir, redacted);
  } catch (_) {
    throw new Error('Failed to update .env. Encrypted store was updated; .env left unchanged.');
  }

  invalidateSession();

  console.log(`Encrypted ${keysToEncrypt.length} secret(s).`);
  console.log('Successfully protected secrets in .env.');
}
