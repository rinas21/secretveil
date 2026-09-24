import { isInitialized, loadConfig, loadSecrets, getEncryptedStorePath } from '../secrets/store.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectPlaintextSecrets } from '../utils/helpers.js';

export async function status(args) {
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    console.log('SecretVeil status');
    console.log('Initialized: no');
    return;
  }

  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);
  const secretCount = Object.keys(secretsData.secrets || secretsData).length;

  const envPath = join(projectDir, '.env');
  const envContent = readFileSync(envPath, 'utf8');
  const hasPlaintext = detectPlaintextSecrets(envContent, config);

  console.log('SecretVeil status');
  console.log('Initialized: yes');
  console.log(`Store version: ${config.version || 1}`);
  console.log(`Encrypted store: ${getEncryptedStorePath(projectDir)}`);
  console.log(`Secrets: ${secretCount}`);
  console.log(`Plaintext .env: ${hasPlaintext ? 'detected' : 'not detected'}`);
  console.log(`Encryption: ${config.algorithm}`);
  console.log(`KDF: ${config.kdf}`);
  if (config.version === 2 && config.keyEncryption) {
    console.log('DEK architecture: active');
    console.log(`Key wrappers: password, recovery`);
  }
}
