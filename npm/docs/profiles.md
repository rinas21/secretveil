# Profiles

## Overview

Environment profiles allow secret isolation across different deployment environments.

## Usage

```bash
secretveil profile create development
secretveil profile create staging
secretveil profile create production
secretveil profile list
secretveil run --profile development npm start
```

## Profile Structure

Profiles are stored in `.secretveil/profiles/`:
```
.secretveil/
├── profiles/
│   ├── development.enc
│   ├── staging.enc
│   └── production.enc
```

Each profile is encrypted separately. The active profile determines which secrets are injected.

## Active Profile

The active profile is displayed in `secretveil status` output. Only the active profile's secrets are injected.

## Profile Isolation

Profiles are completely isolated:
- Development secrets are never mixed with production secrets
- Each profile has its own encryption parameters
- Switching profiles requires re-authentication

## Creating Profiles

```bash
# Create a new profile
secretveil profile create development

# The command prompts for the password
# and creates an encrypted profile
```

## Deleting Profiles

```bash
secretveil profile delete development
```

## Best Practices

1. Always use profiles in multi-environment setups
2. Never mix profiles accidentally
3. Use `--profile` flag explicitly when running commands
4. Delete unused profiles

## Future Enhancements

- Profile-specific KDF parameters
- Profile-specific rotation policies
- Profile-level access control
