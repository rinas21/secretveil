import { existsSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { isInitialized, loadConfig, loadSecrets, getSecretVeilDirectory } from '../secrets/store.js';
import { detectPlaintextSecrets } from '../utils/helpers.js';

export async function doctor(args) {
  const projectDir = process.cwd();
  const checks = [];
  let passed = 0;
  let warnings = 0;

  // SecretVeil initialized
  if (isInitialized(projectDir)) {
    checks.push({ name: 'SecretVeil initialized', status: 'pass' });
    passed++;
  } else {
    checks.push({ name: 'SecretVeil initialized', status: 'fail', message: 'Run "secretveil init" to initialize' });
    warnings++;
  }

  // Encrypted store exists
  const storeDir = getSecretVeilDirectory(projectDir);
  if (existsSync(storeDir) && existsSync(join(storeDir, 'config.json')) && existsSync(join(storeDir, 'secrets.enc'))) {
    checks.push({ name: 'Encrypted store exists', status: 'pass' });
    passed++;
  } else {
    checks.push({ name: 'Encrypted store exists', status: 'fail', message: 'Encrypted store not found' });
    warnings++;
  }

  // Encryption metadata valid
  if (isInitialized(projectDir)) {
    try {
      const config = loadConfig(projectDir);
      if (config.algorithm && config.kdf && config.kdfParams && config.salt) {
        checks.push({ name: 'Encryption metadata valid', status: 'pass' });
        checks.push({ name: `Encryption: ${config.algorithm}`, status: 'pass' });
        checks.push({ name: `KDF: ${config.kdf}`, status: 'pass' });
        passed += 3;
      } else {
        checks.push({ name: 'Encryption metadata valid', status: 'fail', message: 'Missing encryption metadata' });
        warnings++;
      }
    } catch (_) {
      checks.push({ name: 'Encryption metadata valid', status: 'fail', message: 'Cannot read config' });
      warnings++;
    }
  }

  // Plaintext secrets detected
  const envPath = join(projectDir, '.env');
  if (existsSync(envPath)) {
    const envContent = readFileSync(envPath, 'utf8');
    if (isInitialized(projectDir)) {
      const config = loadConfig(projectDir);
      if (detectPlaintextSecrets(envContent, config)) {
        checks.push({ name: 'No plaintext secrets detected', status: 'fail', message: 'Plaintext secrets found in .env' });
        warnings++;
      } else {
        checks.push({ name: 'No plaintext secrets detected', status: 'pass' });
        passed++;
      }
    }
  }

  // Suspicious files
  const suspiciousFiles = findSuspiciousFiles(projectDir);
  if (suspiciousFiles.length === 0) {
    checks.push({ name: 'No suspicious secret files detected', status: 'pass' });
    passed++;
  } else {
    checks.push({ name: 'No suspicious secret files detected', status: 'warn', message: `${suspiciousFiles.length} suspicious file(s) found` });
    warnings++;
  }

  // .gitignore check
  const gitignorePath = join(projectDir, '.gitignore');
  if (existsSync(gitignorePath)) {
    const gitignore = readFileSync(gitignorePath, 'utf8');
    if (gitignore.includes('.env')) {
      checks.push({ name: '.gitignore configured', status: 'pass' });
      passed++;
    } else {
      checks.push({ name: '.gitignore configured', status: 'warn', message: 'Consider adding .env to .gitignore' });
      warnings++;
    }
  } else {
    checks.push({ name: '.gitignore configured', status: 'warn', message: 'No .gitignore found' });
    warnings++;
  }

  // Stale temporary files
  const staleFiles = findStaleFiles(projectDir);
  if (staleFiles.length === 0) {
    checks.push({ name: 'No stale temporary files', status: 'pass' });
    passed++;
  } else {
    checks.push({ name: 'No stale temporary files', status: 'warn', message: `${staleFiles.length} stale file(s) found` });
    warnings++;
  }

  // Print results
  console.log('SecretVeil Doctor');
  console.log('');
  for (const check of checks) {
    const icon = check.status === 'pass' ? '✓' : check.status === 'fail' ? '✗' : '⚠';
    console.log(`${icon} ${check.name}`);
    if (check.message) {
      console.log(`  ${check.message}`);
    }
  }
  console.log('');
  console.log(`Security checks: ${passed} passed, ${warnings} warning(s)`);
}

function findSuspiciousFiles(projectDir) {
  const suspicious = [];
  const skipDirs = ['node_modules', '.git', '.secretveil', 'dist', 'build'];

  function scan(dir) {
    if (!existsSync(dir)) return;
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const parts = fullPath.split(/[\\/]/);
        if (skipDirs.some(d => parts.includes(d))) continue;
        try {
          const stat = statSync(fullPath);
          if (stat.isDirectory()) {
            scan(fullPath);
          } else if (stat.isFile()) {
            const name = entry.toLowerCase();
            if (name.includes('secret') || name.includes('credential') || name.includes('key') || name.includes('password') || name.includes('token') || name.endsWith('.pem') || name.endsWith('.key')) {
              if (!name.includes('.env') && !name.includes('secretveil')) {
                suspicious.push(fullPath);
              }
            }
          }
        } catch (_) {}
      }
    } catch (_) {}
  }

  scan(projectDir);
  return suspicious;
}

function findStaleFiles(projectDir) {
  const stale = [];
  const skipDirs = ['node_modules', '.git', '.secretveil'];

  function scan(dir) {
    if (!existsSync(dir)) return;
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const parts = fullPath.split(/[\\/]/);
        if (skipDirs.some(d => parts.includes(d))) continue;
        try {
          const stat = statSync(fullPath);
          if (stat.isFile() && (entry.endsWith('.tmp') || entry.endsWith('.bak') || entry.endsWith('.backup'))) {
            stale.push(fullPath);
          }
          if (stat.isDirectory()) {
            scan(fullPath);
          }
        } catch (_) {}
      }
    } catch (_) {}
  }

  scan(projectDir);
  return stale;
}
