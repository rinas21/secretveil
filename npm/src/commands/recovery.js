import { loadConfig, loadSecrets, isInitialized, atomicReplace, removeTempFiles } from '../secrets/store.js';
import { hasSession, clearSession } from '../session/session.js';
import { hexToSalt } from '../crypto/kdf.js';
import { wrapKey, unwrapKey, generateRecoveryKey, hexToDEK } from '../crypto/encryption.js';
import { askPassword } from '../utils/readline.js';
import { normalizeRecoveryKey, validateRecoveryKeyFormat } from '../crypto/encryption.js';
import { setCredential, SLOT_RECOVERY } from '../credentials/store.js';

export async function recovery(args) {
  // Validate usage before store checks so help/errors work from any cwd
  if (args.length > 1) {
    throw new Error('Credentials must not be passed as command-line arguments. You will be prompted securely.');
  }
  const subcommand = args[0];
  if (subcommand !== 'regenerate') {
    throw new Error('Usage: secretveil recovery regenerate');
  }

  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const config = loadConfig(projectDir);
  if (config.version !== 2) {
    throw new Error('Recovery regeneration requires a version 2 store. Please migrate first.');
  }

  if (hasSession()) {
    clearSession();
  }

  console.log('Regenerate your emergency recovery key. Verify it is really you first.');
  console.log('');
  const currentPassword = await askPassword('Password: ');

  const wrappedPassword = config.keyEncryption.password;
  const kdfParams = config.kdfParams || {};

  let dek;
  try {
    const dekHex = await unwrapKey(wrappedPassword, currentPassword, kdfParams);
    dek = hexToDEK(dekHex);
  } catch (_) {
    throw new Error('Invalid password.');
  }

  const oldRecoveryKey = await askPassword('Enter current recovery key to confirm: ');
  const normalizedOldKey = normalizeRecoveryKey(oldRecoveryKey);

  if (!validateRecoveryKeyFormat(normalizedOldKey)) {
    throw new Error('Invalid recovery key format.');
  }

  const wrappedRecovery = config.keyEncryption.recovery;
  let oldDekHex;
  try {
    oldDekHex = await unwrapKey(wrappedRecovery, normalizedOldKey, kdfParams);
  } catch (_) {
    throw new Error('Invalid recovery key.');
  }

  const newRecoveryKey = generateRecoveryKey();
  const recoverySalt = hexToSalt(config.salt);
  const newRecoveryWrapper = await wrapKey(dek, normalizeRecoveryKey(newRecoveryKey), recoverySalt, kdfParams);

  const newConfig = {
    ...config,
    keyEncryption: {
      ...config.keyEncryption,
      recovery: {
        salt: newRecoveryWrapper.salt,
        nonce: newRecoveryWrapper.nonce,
        ciphertext: newRecoveryWrapper.ciphertext,
        tag: newRecoveryWrapper.tag
      }
    }
  };

  const secretsData = loadSecrets(projectDir);
  atomicReplace(projectDir, newConfig, secretsData);
  removeTempFiles(projectDir);

  try {
    await setCredential(projectDir, SLOT_RECOVERY, normalizeRecoveryKey(newRecoveryKey));
  } catch (_) {
    console.warn('Warning: recovery key regenerated, but the stored credential could not be updated.');
  }

  clearSession();

  console.log('');
  console.log('SecretVeil Recovery Key');
  console.log('');
  console.log(newRecoveryKey);
  console.log('');
  console.log('IMPORTANT: Store this recovery key somewhere secure.');
  console.log('If you lose both your password and recovery key,');
  console.log('your encrypted secrets cannot be recovered.');
  console.log('');
  console.log('Recovery key regenerated successfully.');
  console.log('The old recovery key no longer works.');
  console.log('');
}
