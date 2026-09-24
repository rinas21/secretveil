import { isInitialized } from '../secrets/store.js';
import { credentialStatus, removeCredentials, getProjectId, getUserDir } from '../credentials/store.js';

export async function credential(args) {
  const subcommand = args[0];
  const projectDir = process.cwd();

  if (subcommand !== 'status' && subcommand !== 'remove') {
    throw new Error('Usage: secretveil credential [status|remove]');
  }

  if (subcommand === 'status') {
    const status = await credentialStatus(projectDir);
    console.log('SecretVeil Credentials');
    console.log('');
    console.log(`User storage: ${status.userDir}`);
    console.log(`Project: ${status.projectPath}`);
    console.log(`Project entry: ${status.projectId}`);
    console.log(`OS keychain available: ${status.keychainAvailable ? 'yes' : 'no (credentials will not persist)'}`);
    console.log(`Password entry: ${status.passwordStored ? 'stored' : 'not stored'}`);
    console.log(`Recovery entry: ${status.recoveryStored ? 'stored' : 'not stored'}`);
    if (status.recordedBackend) {
      console.log(`Storage backend: ${status.recordedBackend}`);
    }
    console.log('');
    console.log('The password entry unlocks automatically. The recovery entry is emergency-only.');
    return;
  }

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const removed = await removeCredentials(projectDir);
  if (removed.length === 0) {
    console.log('No stored credentials for this project.');
    return;
  }
  console.log(`Removed stored credentials for this project (${removed.length} entr${removed.length === 1 ? 'y' : 'ies'}).`);
  console.log('Future unlocks will ask for your password again.');
}

export function getCredentialUserDir() {
  return getUserDir();
}

export function getCredentialProjectId(projectDir) {
  return getProjectId(projectDir);
}
