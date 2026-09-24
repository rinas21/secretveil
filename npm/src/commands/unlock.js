import { isInitialized } from '../secrets/store.js';
import { createSession, hasSession } from '../session/session.js';
import { resolveDEK } from '../credentials/resolve.js';

export async function unlock(args) {
  if (args && args.length > 0) {
    throw new Error('Credentials must not be passed as command-line arguments. You will be prompted securely.');
  }
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  if (hasSession()) {
    throw new Error('SecretVeil is already unlocked.');
  }

  const { config, secretsData, password, dek } = await resolveDEK(projectDir);
  if (config.version === 2) {
    createSession(projectDir, { ...config }, secretsData, dek);
  } else {
    createSession(projectDir, { ...config, _password: password }, secretsData);
  }
  console.log('SecretVeil unlocked.');
}
