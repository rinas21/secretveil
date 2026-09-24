import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function detectPlaintextSecrets(envContent, config) {
  const secretKeys = config.secretKeys || [];
  const lines = envContent.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    let key = trimmed.substring(0, eqIndex).trim();
    if (/^export\s+/.test(key)) {
      key = key.replace(/^export\s+/, '').trim();
    }
    if (!secretKeys.includes(key)) continue;
    const value = trimmed.substring(eqIndex + 1).trim();
    if (value && value !== '<encrypted>' && !value.startsWith('$')) {
      return true;
    }
  }
  return false;
}

export function getSecretKeys(envVars) {
  const sensitivePrefixes = ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET', 'SECRET', 'PASSWORD', 'TOKEN', 'CREDENTIAL'];
  return Object.keys(envVars).filter(key => {
    const upper = key.toUpperCase();
    return sensitivePrefixes.some(prefix => upper.includes(prefix));
  });
}
