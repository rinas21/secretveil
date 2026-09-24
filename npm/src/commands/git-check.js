import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export async function gitCheck(args) {
  const projectDir = process.cwd();
  const { scanProject } = await import('./scan.js');
  const { detectPlaintextSecrets } = await import('../utils/helpers.js');
  const { loadConfig, isInitialized } = await import('../secrets/store.js');

  const findings = [];

  // Check .git exists
  const gitDir = join(projectDir, '.git');
  const gitExists = existsSync(gitDir);

  // Check tracked .env
  const envPath = join(projectDir, '.env');
  if (existsSync(envPath)) {
    findings.push({ check: 'tracked .env', status: 'warn', message: '.env exists in project directory' });
  }

  // Check committed secrets
  if (gitExists && isInitialized(projectDir)) {
    const config = loadConfig(projectDir);
    const secretKeys = config.secretKeys || [];
    // Check if any secret-related files are tracked
    const scanResult = await scanProject(projectDir, { staged: false });
    const highFindings = scanResult.findings.filter(f => f.severity === 'HIGH');
    if (highFindings.length > 0) {
      findings.push({ check: 'suspicious configuration', status: 'warn', message: `${highFindings.length} high-severity finding(s) detected` });
    }
  }

  // Check .gitignore
  const gitignorePath = join(projectDir, '.gitignore');
  let gitignoreOk = false;
  if (existsSync(gitignorePath)) {
    const gitignore = readFileSync(gitignorePath, 'utf8');
    gitignoreOk = gitignore.includes('.env');
  }

  if (gitignoreOk) {
    findings.push({ check: 'Git tracking', status: 'pass', message: '.env in .gitignore' });
  } else {
    findings.push({ check: 'Git tracking', status: 'warn', message: 'Consider adding .env to .gitignore' });
  }

  // Check SecretVeil files (global store, outside the project)
  if (isInitialized(projectDir)) {
    findings.push({ check: 'SecretVeil files', status: 'pass', message: 'Encrypted store present in ~/.secretveil' });
  }

  // Check accidental plaintext credentials
  if (existsSync(envPath)) {
    if (isInitialized(projectDir)) {
      const config = loadConfig(projectDir);
      if (!detectPlaintextSecrets(readFileSync(envPath, 'utf8'), config)) {
        findings.push({ check: 'accidental plaintext credentials', status: 'pass', message: 'No plaintext secrets detected' });
      } else {
        findings.push({ check: 'accidental plaintext credentials', status: 'fail', message: 'Plaintext secrets found in .env' });
      }
    }
  }

  // Print results
  console.log('SecretVeil Git Check');
  console.log('');
  for (const f of findings) {
    const icon = f.status === 'pass' ? '✓' : f.status === 'fail' ? '✗' : '⚠';
    console.log(`${icon} ${f.check}`);
    if (f.message) console.log(`  ${f.message}`);
  }
  console.log('');

  const passes = findings.filter(f => f.status === 'pass').length;
  const warns = findings.filter(f => f.status === 'warn').length;
  const fails = findings.filter(f => f.status === 'fail').length;
  console.log(`Git checks: ${passes} passed, ${warns} warning(s), ${fails} fail(s)`);
}
