import { spawn } from 'node:child_process';
import { getSession, invalidateSession, createSession } from '../session/session.js';
import { isInitialized } from '../secrets/store.js';
import { hexToSalt } from '../crypto/kdf.js';
import { decryptSecret, decryptWithKey } from '../crypto/encryption.js';
import { resolveDEK } from '../credentials/resolve.js';
import { parseEnvFile, isEnvFileExists, getEnvPath } from '../secrets/parser.js';
import { buildChildEnv } from '../runtime/runner.js';

export async function run(args) {
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  let session = getSession();
  if (!session) {
    const { config, secretsData, password, dek } = await resolveDEK(projectDir);
    if (config.version === 2) {
      session = createSession(projectDir, { ...config }, secretsData, dek);
    } else {
      session = createSession(projectDir, { ...config, _password: password }, secretsData);
    }
  }

  const s = getSession();
  const decryptedEnv = {};
  const secretNames = Object.keys(s.secretsData.secrets || s.secretsData);

  for (const name of secretNames) {
    const enc = s.secretsData.secrets ? s.secretsData.secrets[name] : s.secretsData[name];
    if (s.config.version === 2) {
      const dek = s.dek;
      if (!dek) {
        throw new Error('Session missing DEK. Please unlock.');
      }
      decryptedEnv[name] = JSON.parse(await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek)).value;
    } else {
      const salt = hexToSalt(s.config.salt);
      const kdfParams = s.config.kdfParams || {};
      decryptedEnv[name] = await decryptSecret(enc, s.config._password, salt, kdfParams);
    }
  }

  const parsedEnv = isEnvFileExists(projectDir) ? parseEnvFile(getEnvPath(projectDir)) : {};
  const childEnv = buildChildEnv(process.env, parsedEnv, decryptedEnv);

  const cmdArgs = args.length > 0 ? args : ['node', 'server.js'];
  const [exec, ...rest] = cmdArgs;

  const child = spawn(exec, rest, {
    env: childEnv,
    stdio: 'inherit',
    shell: false
  });

  const wipe = () => {
    for (const key of Object.keys(decryptedEnv)) {
      delete decryptedEnv[key];
    }
    invalidateSession();
  };

  return new Promise((resolve, reject) => {
    child.on('close', (code) => {
      wipe();
      resolve(code);
    });
    child.on('error', (err) => {
      wipe();
      reject(err);
    });
  });
}
