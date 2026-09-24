# CI/CD Integration

## Overview

SecretVeil supports CI/CD integration through documented patterns that keep secrets secure.

## GitHub Actions

### Example Workflow

```yaml
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install
      - run: npm test
```

### Using SecretVeil in CI

```yaml
- name: Run with SecretVeil
  run: |
    secretveil init
    echo "${{ secrets.SECRETVEIL_PASSWORD }}" | secretveil run -- npm test
```

**Important**: The password must be passed via GitHub Secrets, not hardcoded in the workflow file.

## GitLab CI

### Example Configuration

```yaml
test:
  script:
    - npm install
    - echo "$SECRETVEIL_PASSWORD" | secretveil run -- npm test
  variables:
    SECRETVEIL_PASSWORD: $SECRETVEIL_PASSWORD
```

## Generic CI

The generic pattern is:
```bash
echo "$SECRETVEIL_PASSWORD" | secretveil run -- <command>
```

## Security Requirements

1. **Never put long-lived passwords in repository files**
2. **Pass passwords via secure environment variables**
3. **Use the CI system's secret management**
4. **Never commit `.env` files**
5. **Never commit `.secretveil/` config files with passwords**

## Authentication Boundary

The CI system's authentication boundary must remain outside the agent's control. The password should:
1. Be stored in the CI system's secret management
2. Be passed via environment variables at runtime
3. Never be written to disk
4. Never be logged or printed

## Example Pattern

```bash
# In CI script
export SECRETVEIL_PASSWORD="${SECRETVEIL_PASSWORD}"
echo "$SECRETVEIL_PASSWORD" | secretveil run -- npm test
```

## Notes

- The CI implementation must not put long-lived SecretVeil passwords into repository files
- The authentication boundary must remain outside the agent's control
- Use the generic `secretveil run -- <command>` pattern
- Document the required authentication boundary for each CI provider
