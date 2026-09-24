import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isInitialized as checkInitialized } from '../secrets/store.js';

export async function docker(args) {
  const projectDir = process.cwd();

  if (!checkInitialized(projectDir)) {
    throw new Error('SecretVeil is not initialized in this project.');
  }

  const dockerfilePath = join(projectDir, 'Dockerfile');
  const composePath = join(projectDir, 'docker-compose.yml');
  const composeYamlPath = join(projectDir, 'docker-compose.yaml');

  console.log('SecretVeil Docker');
  console.log('');
  console.log('Usage: secretveil run -- docker compose up');
  console.log('');
  console.log('Docker Best Practices:');
  console.log('  - Never use ARG or ENV for secrets in Dockerfiles');
  console.log('  - Use --env-file with SecretVeil runtime injection');
  console.log('  - Secrets are injected at container runtime, not build time');
  console.log('  - Do not commit Dockerfiles with plaintext credentials');
  console.log('');

  if (existsSync(dockerfilePath)) {
    const content = readFileSync(dockerfilePath, 'utf8');
    if (content.includes('ENV ') || content.includes('ARG ')) {
      console.log('⚠ Dockerfile contains ENV or ARG directives.');
      console.log('  Review for potential secret exposure in image layers.');
    }
  }

  if (existsSync(composePath)) {
    console.log('✓ docker-compose.yml found.');
    console.log('  Use "secretveil run -- docker compose up" to inject secrets.');
  }

  if (existsSync(composeYamlPath)) {
    console.log('✓ docker-compose.yaml found.');
    console.log('  Use "secretveil run -- docker compose up" to inject secrets.');
  }

  if (!existsSync(dockerfilePath) && !existsSync(composePath) && !existsSync(composeYamlPath)) {
    console.log('No Docker configuration files found.');
    console.log('Create a Dockerfile or docker-compose.yml for Docker integration.');
  }
}
