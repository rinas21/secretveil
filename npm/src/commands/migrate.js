import { isInitialized, loadConfig } from '../secrets/store.js';
import { migrateFromV1 } from './init.js';

export async function migrate(args) {
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const config = loadConfig(projectDir);
  if (config.version !== 1) {
    console.log(`Store is already version ${config.version}. No migration needed.`);
    return;
  }

  console.log('SecretVeil Migration');
  console.log('Migrating version 1 store to version 2 (DEK architecture)...');
  console.log('Your existing password will continue to work.');
  console.log('');

  await migrateFromV1(projectDir);
}
