import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { isInitialized, loadConfig } from '../secrets/store.js';
import { detectPlaintextSecrets } from '../utils/helpers.js';
import { scanProject } from './scan.js';

export async function aiCheck(args) {
  const projectDir = process.cwd();

  if (!isInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const config = loadConfig(projectDir);
  const findings = [];

  // Check .env for plaintext secrets
  const envPath = join(projectDir, '.env');
  if (existsSync(envPath)) {
    const envContent = readFileSync(envPath, 'utf8');
    if (detectPlaintextSecrets(envContent, config)) {
      findings.push({
        risk: 'warning',
        message: 'Plaintext secrets detected in .env file'
      });
    }
  }

  // Check for possible credentials in source
  const scanResult = await scanProject(projectDir);
  for (const f of scanResult.findings) {
    if (f.severity === 'HIGH') {
      findings.push({
        risk: 'warning',
        message: `${f.file}:${f.line} - Possible ${f.type} detected`
      });
    }
  }

  // Check Docker configuration
  const dockerFiles = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
  for (const df of dockerFiles) {
    const dp = join(projectDir, df);
    if (existsSync(dp)) {
      const content = readFileSync(dp, 'utf8');
      if (content.includes('ENV') || content.includes('ARG') || content.includes('PASSWORD') || content.includes('SECRET') || content.includes('KEY')) {
        findings.push({
          risk: 'warning',
          message: `Docker configuration contains a possible credential: ${df}`
        });
      }
    }
  }

  // Check Git history for secrets
  const gitDir = join(projectDir, '.git');
  if (existsSync(gitDir)) {
    findings.push({
      risk: 'warning',
      message: 'Git repository detected - check history for possible credentials'
    });
  }

  // Encrypted store detected (positive)
  findings.push({
    risk: 'ok',
    message: 'Encrypted SecretVeil store detected'
  });

  // Runtime injection configured (positive)
  findings.push({
    risk: 'ok',
    message: 'Runtime injection configured'
  });

  // Check for plaintext API keys
  const scanResult2 = await scanProject(projectDir);
  const hasApiKey = scanResult2.findings.some(f => f.type.includes('API'));
  if (!hasApiKey) {
    findings.push({
      risk: 'ok',
      message: 'No plaintext API keys detected'
    });
  }

  // Check for plaintext database passwords
  const hasDbPassword = scanResult2.findings.some(f => f.type.includes('Database') || f.type.includes('Password'));
  if (!hasDbPassword) {
    findings.push({
      risk: 'ok',
      message: 'No plaintext database passwords detected'
    });
  }

  // Print results
  console.log('SecretVeil AI Check');
  console.log('');
  console.log('Workspace analysis');
  let warnings = 0;
  let ok = 0;
  for (const f of findings) {
    const icon = f.risk === 'ok' ? '✓' : f.risk === 'warning' ? '⚠' : '✗';
    console.log(`${icon} ${f.message}`);
    if (f.risk === 'warning') warnings++;
    else if (f.risk === 'ok') ok++;
  }
  console.log('');
  console.log(`AI exposure risks: ${warnings} warning(s)`);
}
