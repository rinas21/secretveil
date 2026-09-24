import { loadConfig, loadSecrets, isInitialized, atomicReplace, removeTempFiles } from '../secrets/store.js';
import { hasSession, clearSession } from '../session/session.js';
import { hexToSalt } from '../crypto/kdf.js';
import { decryptWithKey, wrapKey, unwrapKey, hexToDEK } from '../crypto/encryption.js';
import { askPassword } from '../utils/readline.js';
import { normalizeRecoveryKey, validateRecoveryKeyFormat } from '../crypto/encryption.js';
import { getCredential, setCredential, SLOT_PASSWORD, SLOT_RECOVERY } from '../credentials/store.js';

export async function recover(args) {
  if (args && args.length > 0) {
    throw new Error('Credentials must not be passed as command-line arguments. You will be prompted securely.');
  }
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const config = loadConfig(projectDir);
  if (config.version !== 2) {
    throw new Error('Recovery requires a version 2 store. Please migrate first.');
  }

  if (hasSession()) {
    clearSession();
  }

  console.log('SecretVeil Recovery');
  console.log('Use your emergency recovery key to reset a forgotten password.');
  console.log('');

  let normalizedKey = null;
  try {
    const stored = await getCredential(projectDir, SLOT_RECOVERY);
    if (stored && validateRecoveryKeyFormat(stored)) {
      normalizedKey = normalizeRecoveryKey(stored);
      console.log('Using stored recovery credential.');
    }
  } catch (_) {
    normalizedKey = null;
  }

  if (!normalizedKey) {
    console.log('Enter your recovery key to reset your password.');
    const recoveryKey = await askPassword('Recovery key: ');
    normalizedKey = normalizeRecoveryKey(recoveryKey);
  }

  if (!validateRecoveryKeyFormat(normalizedKey)) {
    throw new Error('Invalid recovery key format.');
  }

  const kdfParams = config.kdfParams || {};
  const wrappedRecovery = config.keyEncryption.recovery;

  let dek;
  try {
    const dekHex = await unwrapKey(wrappedRecovery, normalizedKey, kdfParams);
    dek = hexToDEK(dekHex);
  } catch (_) {
    throw new Error('Invalid recovery key.');
  }

  const newPassword = await askPassword('Set a new SecretVeil password: ');
  const newPasswordConfirm = await askPassword('Confirm new password: ');

  if (newPassword !== newPasswordConfirm) {
    throw new Error('Passwords do not match.');
  }

  if (newPassword.length === 0) {
    throw new Error('Password cannot be empty.');
  }

  const salt = hexToSalt(config.salt);
  const newPasswordWrapper = await wrapKey(dek, newPassword, salt, kdfParams);

  const newConfig = {
    ...config,
    keyEncryption: {
      ...config.keyEncryption,
      password: {
        salt: newPasswordWrapper.salt,
        nonce: newPasswordWrapper.nonce,
        ciphertext: newPasswordWrapper.ciphertext,
        tag: newPasswordWrapper.tag
      }
    }
  };

  const secretsData = loadSecrets(projectDir);
  const secretNames = Object.keys(secretsData.secrets || secretsData);
  for (const name of secretNames) {
    const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
    await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek);
  }

  atomicReplace(projectDir, newConfig, secretsData);
  removeTempFiles(projectDir);

  try {
    await setCredential(projectDir, SLOT_PASSWORD, newPassword);
  } catch (_) {
    console.warn('Warning: password reset, but the stored credential could not be updated.');
  }

  clearSession();

  console.log('');
  console.log('Recovery successful.');
  console.log('Your password has been updated. The recovery key remains unchanged.');
  console.log('');
}
