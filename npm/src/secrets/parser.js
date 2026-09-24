import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function parseEnvFile(filePath) {
  const content = readFileSync(filePath, 'utf8');
  return parseEnvString(content);
}

export function parseEnvString(content) {
  const env = {};
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      continue;
    }

    let key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();

    if (key === '') {
      continue;
    }

    if (/^export\s+/.test(key)) {
      key = key.replace(/^export\s+/, '').trim();
      if (key === '') {
        continue;
      }
    }

    if (value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
         (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }

    env[key] = value;
  }

  return env;
}

export function isEnvFileExists(projectDir) {
  try {
    readFileSync(join(projectDir, '.env'), 'utf8');
    return true;
  } catch {
    return false;
  }
}

export function getEnvPath(projectDir) {
  return join(projectDir, '.env');
}

export function readEnvContent(projectDir) {
  return readFileSync(getEnvPath(projectDir), 'utf8');
}
