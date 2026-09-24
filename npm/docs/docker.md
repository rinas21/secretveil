# Docker

## Overview

SecretVeil provides tooling for Docker workflows to ensure secrets are injected at runtime without creating plaintext artifacts.

## Usage

```bash
secretveil run -- docker compose up
secretveil run -- docker run my-app
```

## Docker Best Practices

### Never Use ARG or ENV for Secrets

```dockerfile
# BAD - Secrets persist in image layers
FROM node:20
ENV API_KEY=sk_live_abc123

# GOOD - Secrets injected at runtime
FROM node:20
CMD ["node", "server.js"]
```

### Use Runtime Injection

```bash
# Correct way to use SecretVeil with Docker
secretveil run -- docker compose up
secretveil run -- docker run -e API_KEY=... my-app
```

## Docker Compose

Create a `docker-compose.yml` without secrets:
```yaml
version: '3.8'
services:
  app:
    build: .
    command: node server.js
    # Do NOT include secrets in environment variables
```

Then run with SecretVeil:
```bash
secretveil run -- docker compose up
```

## Dockerfile

Create a Dockerfile without secrets:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
CMD ["node", "server.js"]
```

## Security Considerations

### What NOT to Do

1. **Never use `ARG` for secrets** - ARG values persist in image metadata
2. **Never use `ENV` for secrets** - ENV values persist in image layers
3. **Never commit Dockerfiles with secrets** - Dockerfiles are in version control
4. **Never put secrets in build logs** - Build logs may be stored and indexed

### What to Do

1. Use `secretveil run -- docker compose up` for runtime injection
2. Use the Docker `--env` flag for additional variables
3. Review Dockerfiles for potential secret exposure
4. Use `.dockerignore` to exclude sensitive files

## Docker Layers and Secrets

Docker `ARG` and `ENV` directives can persist in image metadata/layers:
- `ARG` values are stored in layer metadata
- `ENV` values are stored in the image history
- Both can be inspected with `docker history` or `docker inspect`

SecretVeil prevents this by:
1. Never creating Docker images with secrets
2. Injecting secrets only at runtime
3. Using environment variables that are cleaned up after the process exits

## Hook Installation

Optional: Install a pre-commit hook that runs the scanner:
```bash
secretveil install-hook
```

The hook must be fast enough for normal development. Allow bypass only with an explicit documented option.

## Notes

- Do not expose secrets through Docker image layers, generated Dockerfiles, committed compose files, build logs
- Be extremely careful with Docker ARG and ENV because they can persist in image metadata/layers
