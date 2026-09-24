import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { isInitialized, getSecretVeilDirectory } from '../secrets/store.js';

const AUDIT_FILE = 'audit.log';

export async function audit(args) {
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const json = args.includes('--json');
  const auditPath = join(getSecretVeilDirectory(projectDir), AUDIT_FILE);

  let entries = [];
  if (existsSync(auditPath)) {
    try {
      const content = readFileSync(auditPath, 'utf8');
      const lines = content.trim().split('\n');
      for (const line of lines) {
        try {
          entries.push(JSON.parse(line));
        } catch (_) {}
      }
    } catch (_) {}
  }

  if (json) {
    console.log(JSON.stringify({ version: 1, entries }, null, 2));
  } else {
    console.log('SecretVeil Audit');
    console.log('');
    if (entries.length === 0) {
      console.log('No audit events recorded.');
    } else {
      for (const entry of entries) {
        console.log(`${entry.timestamp || ''} ${entry.action || ''}`);
        for (const [key, value] of Object.entries(entry)) {
          if (key === 'timestamp' || key === 'action') continue;
          console.log(`  ${key}=${value}`);
        }
      }
    }
    console.log('');
    console.log(`${entries.length} event(s) recorded.`);
  }
}

export async function addAuditEntry(projectDir, entry) {
  const auditPath = join(getSecretVeilDirectory(projectDir), AUDIT_FILE);
  const dir = dirname(auditPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  const record = {
    timestamp: new Date().toISOString(),
    ...entry
  };
  delete record.secret;
  delete record.password;
  delete record.value;
  delete record.key;
  delete record.token;
  delete record.recoveryKey;
  delete record.recovery;
  delete record.dek;
  delete record.wrappedKey;
  delete record.wrappedDEK;
  delete record.ciphertext;
  delete record.passphrase;
  delete record.credential;
  delete record.credentials;
  appendFileSync(auditPath, JSON.stringify(record) + '\n', { mode: 0o600 });
  return record;
}
