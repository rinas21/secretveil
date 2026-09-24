import { writeFileSync, renameSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { getSession, createSession, invalidateSession } from '../session/session.js';
import { isInitialized } from '../secrets/store.js';
import { hexToSalt } from '../crypto/kdf.js';
import { decryptSecret, decryptWithKey } from '../crypto/encryption.js';
import { resolveDEK } from '../credentials/resolve.js';
import { isEnvFileExists, readEnvContent, getEnvPath } from '../secrets/parser.js';
import { restoreEnvContent } from './init.js';
import { askLine } from '../utils/readline.js';

function isAffirmative(answer) {
  return /^(y|yes)$/i.test(String(answer || '').trim());
}

async function decryptAllSecrets(session) {
  const decrypted = {};
  const secretNames = Object.keys(session.secretsData.secrets || session.secretsData);
  for (const name of secretNames) {
    const enc = session.secretsData.secrets
      ? session.secretsData.secrets[name]
      : session.secretsData[name];
    let parsed;
    if (session.config.version === 2) {
      if (!session.dek) {
        throw new Error('Session missing DEK. Please unlock.');
      }
      parsed = JSON.parse(
        await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, session.dek)
      );
    } else {
      const salt = hexToSalt(session.config.salt);
      const kdfParams = session.config.kdfParams || {};
      parsed = {
        value: await decryptSecret(enc, session.config._password, salt, kdfParams),
        quote: null
      };
    }
    decrypted[name] = {
      value: parsed.value,
      quote: parsed.quote === 'double' || parsed.quote === 'single' ? parsed.quote : null
    };
  }
  return decrypted;
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

function wipeSecrets(decrypted) {
  for (const key of Object.keys(decrypted)) {
    delete decrypted[key];
  }
}

export async function decrypt(args) {
  if (args && args.length > 0) {
    throw new Error('Usage: secretveil decrypt');
  }

  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  if (!isEnvFileExists(projectDir)) {
    throw new Error('No .env file found in the current directory.');
  }

  console.log('Warning: plaintext secrets will be written to .env.');
  console.log('Anyone with access to this file (including AI agents) will be able to read them.');
  console.log('');
  const confirm = await askLine('Continue? (y/N): ');
  if (!isAffirmative(confirm)) {
    console.log('Decrypt cancelled. .env left unchanged.');
    return;
  }

  console.log('Decrypting secrets...');

  let session = getSession();
  if (!session) {
    const { config, secretsData, password, dek } = await resolveDEK(projectDir);
    if (config.version === 2) {
      session = createSession(projectDir, { ...config }, secretsData, dek);
    } else {
      session = createSession(projectDir, { ...config, _password: password }, secretsData);
    }
  }

  let decrypted;
  try {
    decrypted = await decryptAllSecrets(session);
  } catch (_) {
    throw new Error('Failed to decrypt secret store.\nCheck your password/recovery key and SecretVeil configuration.');
  }

  const secretCount = Object.keys(decrypted).length;
  if (secretCount === 0) {
    wipeSecrets(decrypted);
    throw new Error('No encrypted secrets found in the store.');
  }

  console.log('Restoring .env...');

  try {
    const envContent = readEnvContent(projectDir);
    const restored = restoreEnvContent(envContent, decrypted);
    atomicWriteEnv(projectDir, restored);
  } catch (_) {
    wipeSecrets(decrypted);
    throw new Error('Failed to restore .env. Previous contents preserved.');
  }

  wipeSecrets(decrypted);
  invalidateSession();

  console.log(`Decrypted ${secretCount} secret(s).`);
  console.log('Successfully restored plaintext secrets to .env.');
}
