import { loadConfig, loadSecrets, isInitialized, atomicReplace, removeTempFiles } from '../secrets/store.js';
import { hasSession, clearSession } from '../session/session.js';
import { hexToSalt } from '../crypto/kdf.js';
import { wrapKey, unwrapKey, hexToDEK } from '../crypto/encryption.js';
import { askPassword } from '../utils/readline.js';
import { setCredential, SLOT_PASSWORD } from '../credentials/store.js';

export async function password(args) {
  if (args && args.length > 0) {
    throw new Error('Credentials must not be passed as command-line arguments. You will be prompted securely.');
  }
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const config = loadConfig(projectDir);
  if (config.version !== 2) {
    throw new Error('Password change requires a version 2 store. Please migrate first.');
  }

  if (hasSession()) {
    clearSession();
  }

  console.log('Change your SecretVeil password.');
  console.log('');
  const currentPassword = await askPassword('Current password: ');

  const wrappedPassword = config.keyEncryption.password;
  const kdfParams = config.kdfParams || {};

  let dek;
  try {
    const dekHex = await unwrapKey(wrappedPassword, currentPassword, kdfParams);
    dek = hexToDEK(dekHex);
  } catch (_) {
    throw new Error('Invalid current password.');
  }

  const newPassword = await askPassword('New password: ');
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
  atomicReplace(projectDir, newConfig, secretsData);
  removeTempFiles(projectDir);

  try {
    await setCredential(projectDir, SLOT_PASSWORD, newPassword);
  } catch (_) {
    console.warn('Warning: password changed, but the stored credential could not be updated.');
  }

  clearSession();

  console.log('');
  console.log('Password updated successfully.');
  console.log('The recovery key remains unchanged.');
  console.log('');
}
