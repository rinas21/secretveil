import { mkdirSync, existsSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { loadConfig, loadSecrets, isInitialized, createStore, getSecretVeilDirectory } from '../secrets/store.js';
import { encryptSecret, decryptSecret } from '../crypto/encryption.js';
import { deriveKey, generateSalt, saltToHex } from '../crypto/kdf.js';
import { askPassword } from '../utils/readline.js';
import { createSession } from '../session/session.js';

const POLICIES_FILE = 'policies.json';

export async function policy(args) {
  const subcommand = args[0];
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  switch (subcommand) {
    case 'create': {
      const policyName = args[1];
      if (!policyName) {
        throw new Error('Usage: secretveil policy create <name>');
      }
      await createPolicy(projectDir, policyName, args.slice(2));
      break;
    }
    case 'list': {
      await listPolicies(projectDir);
      break;
    }
    case 'delete': {
      const policyName = args[1];
      if (!policyName) {
        throw new Error('Usage: secretveil policy delete <name>');
      }
      await deletePolicy(projectDir, policyName);
      break;
    }
    default:
      throw new Error('Usage: secretveil policy [create|list|delete] [name] [allowed-secrets...]');
  }
}

async function createPolicy(projectDir, policyName, allowedSecrets) {
  const policies = loadPolicies(projectDir);
  if (policies[policyName]) {
    throw new Error(`Policy "${policyName}" already exists.`);
  }

  if (allowedSecrets.length === 0) {
    throw new Error('At least one secret name is required for the policy.');
  }

  policies[policyName] = { allow: allowedSecrets };
  savePolicies(projectDir, policies);
  console.log(`Policy "${policyName}" created with secrets: ${allowedSecrets.join(', ')}`);
}

async function listPolicies(projectDir) {
  const policies = loadPolicies(projectDir);
  const names = Object.keys(policies);
  if (names.length === 0) {
    console.log('No policies defined.');
    return;
  }
  console.log('SecretVeil Policies');
  for (const name of names) {
    const secrets = policies[name].allow || [];
    console.log(`  ${name}: ${secrets.join(', ')}`);
  }
}

async function deletePolicy(projectDir, policyName) {
  const policies = loadPolicies(projectDir);
  if (!policies[policyName]) {
    throw new Error(`Policy "${policyName}" not found.`);
  }
  delete policies[policyName];
  savePolicies(projectDir, policies);
  console.log(`Policy "${policyName}" deleted.`);
}

function loadPolicies(projectDir) {
  const path = join(getSecretVeilDirectory(projectDir), POLICIES_FILE);
  if (existsSync(path)) {
    try {
      return JSON.parse(readFileSync(path, 'utf8'));
    } catch (_) {
      return {};
    }
  }
  return {};
}

function savePolicies(projectDir, policies) {
  const dir = getSecretVeilDirectory(projectDir);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(join(dir, POLICIES_FILE), JSON.stringify(policies, null, 2), { mode: 0o600 });
}

export async function validatePolicy(projectDir, policyName) {
  const policies = loadPolicies(projectDir);
  if (!policies[policyName]) {
    throw new Error(`Policy "${policyName}" not found.`);
  }
  return policies[policyName];
}

export function getPolicySecrets(policyName, policies) {
  if (!policies || !policies[policyName]) return null;
  return policies[policyName].allow || [];
}
