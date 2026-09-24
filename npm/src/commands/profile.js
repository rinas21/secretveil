import { mkdirSync, existsSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { loadConfig, loadSecrets, isInitialized, createStore, getSecretVeilDirectory } from '../secrets/store.js';
import { encryptSecret, decryptSecret, decryptWithKey, unwrapKey, getAlgorithm } from '../crypto/encryption.js';
import { hexToDEK } from '../crypto/encryption.js';
import { deriveKey, generateSalt, saltToHex, hexToSalt } from '../crypto/kdf.js';
import { askPassword } from '../utils/readline.js';
import { createSession } from '../session/session.js';

const PROFILES_DIR = 'profiles';

export async function profile(args) {
  const subcommand = args[0];
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  switch (subcommand) {
    case 'create': {
      const profileName = args[1];
      if (!profileName) {
        throw new Error('Usage: secretveil profile create <name>');
      }
      await createProfile(projectDir, profileName);
      break;
    }
    case 'list': {
      await listProfiles(projectDir);
      break;
    }
    case 'delete': {
      const profileName = args[1];
      if (!profileName) {
        throw new Error('Usage: secretveil profile delete <name>');
      }
      await deleteProfile(projectDir, profileName);
      break;
    }
    default:
      throw new Error('Usage: secretveil profile [create|list|delete] [name]');
  }
}

async function createProfile(projectDir, profileName) {
  const config = loadConfig(projectDir);
  const secretsData = loadSecrets(projectDir);
  const salt = hexToSalt(config.salt);
  const kdfParams = config.kdfParams || {};
  console.log('Enter your SecretVeil password to create a profile.');
  const password = await askPassword('Password: ');

  const profileDir = join(getSecretVeilDirectory(projectDir), PROFILES_DIR);

  if (!existsSync(profileDir)) {
    mkdirSync(profileDir, { recursive: true });
  }

  const profileSecrets = {};
  const secretNames = Object.keys(secretsData.secrets || secretsData);

  if (config.version === 2) {
    let dek;
    try {
      const dekHex = await unwrapKey(config.keyEncryption.password, password, kdfParams);
      dek = hexToDEK(dekHex);
    } catch (_) {
      throw new Error('Failed to decrypt secret store.\nCheck your password and SecretVeil configuration.');
    }
    for (const name of secretNames) {
      const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
      const plaintext = await decryptWithKey(enc.ciphertext, enc.nonce, enc.tag, dek);
      const value = JSON.parse(plaintext).value;
      profileSecrets[name] = await encryptSecret(name, value, password, generateSalt(), kdfParams);
    }
  } else {
    for (const name of secretNames) {
      const enc = secretsData.secrets ? secretsData.secrets[name] : secretsData[name];
      profileSecrets[name] = await encryptSecret(name, await decryptSecret(enc, password, salt, kdfParams), password, generateSalt(), kdfParams);
    }
  }

  const profileData = {
    version: 1,
    profile: profileName,
    algorithm: getAlgorithm(),
    kdf: 'argon2id',
    salt: saltToHex(generateSalt()),
    secrets: profileSecrets
  };

  const profilePath = join(profileDir, `${profileName}.enc`);
  writeFileSync(profilePath, JSON.stringify(profileData, null, 2), { mode: 0o600 });

  // Update config to track active profile
  config.activeProfile = profileName;
  createStore(projectDir, config, secretsData);

  console.log(`Profile "${profileName}" created.`);
}

async function listProfiles(projectDir) {
  const profileDir = join(getSecretVeilDirectory(projectDir), PROFILES_DIR);
  if (!existsSync(profileDir)) {
    console.log('No profiles found.');
    return;
  }
  const files = readdirSync(profileDir).filter(f => f.endsWith('.enc'));
  const config = loadConfig(projectDir);
  console.log('SecretVeil Profiles');
  for (const file of files) {
    const name = file.replace('.enc', '');
    const active = config.activeProfile === name ? ' (active)' : '';
    console.log(`  ${name}${active}`);
  }
}

async function deleteProfile(projectDir, profileName) {
  const profilePath = join(getSecretVeilDirectory(projectDir), PROFILES_DIR, `${profileName}.enc`);
  if (!existsSync(profilePath)) {
    throw new Error(`Profile "${profileName}" not found.`);
  }
  rmSync(profilePath);
  const config = loadConfig(projectDir);
  delete config.activeProfile;
  const secretsData = loadSecrets(projectDir);
  createStore(projectDir, config, secretsData);
  console.log(`Profile "${profileName}" deleted.`);
}
