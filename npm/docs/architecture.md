# Architecture

## Overview

SecretVeil is a Node.js CLI tool that protects application secrets from AI coding agents through encrypted-at-rest storage and runtime injection.

## DEK Architecture

SecretVeil uses a **Data Encryption Key (DEK)** architecture for secure secret management:

```
                    Random 256-bit DEK
                           │
              ┌────────────┴────────────┐
              │                         │
       Password-derived           Recovery-derived
         key wrapper               key wrapper
              │                         │
              ▼                         ▼
       Wrapped DEK #1              Wrapped DEK #2
              │                         │
              └────────────┬────────────┘
                           ▼
                  Encrypted secrets
```

The DEK is a randomly generated 256-bit key used to encrypt all secret values. The password and recovery key are only used to wrap (encrypt) and unwrap (decrypt) the DEK.

### Benefits

1. **Password changes don't require re-encryption** - Only the password wrapper needs to change
2. **Recovery doesn't require re-encryption** - Only the recovery wrapper needs to change
3. **Separation of concerns** - Encryption keys vs. access credentials
4. **Cross-platform** - No platform-specific credential stores required

## Module Structure

```
src/
├── cli.js                    # CLI entry point with argument parsing
├── commands/
│   ├── init.js              # Initialize SecretVeil with DEK
│   ├── status.js            # Show security status
│   ├── unlock.js            # Unlock with password or recovery key
│   ├── lock.js              # Lock store and invalidate session
│   ├── run.js               # Run command with injected secrets
│   ├── recover.js           # Recover from forgotten password
│   ├── password.js          # Change the SecretVeil password
│   ├── recovery.js          # Manage recovery key
│   ├── scan.js              # Detect exposed secrets
│   ├── doctor.js            # Diagnose configuration
│   ├── profile.js           # Manage environment profiles
│   ├── policy.js            # Manage secret policies
│   ├── rotate.js            # Rotate secrets
│   ├── audit.js             # View audit history
│   ├── ai-check.js          # Analyze AI exposure
│   ├── benchmark.js         # Run exposure benchmark
│   ├── git-check.js         # Check Git exposure
│   └── docker.js            # Docker integration
├── crypto/
│   ├── kdf.js               # Argon2id key derivation
│   └── encryption.js         # AES-256-GCM, DEK wrapping, recovery keys
├── secrets/
│   ├── parser.js            # .env file parsing
│   └── store.js             # Encrypted store management (v1/v2)
├── session/
│   └── session.js           # In-memory session with DEK
├── runtime/
│   └── runner.js            # Decryption and process injection
├── utils/
│   ├── helpers.js           # Detection helpers
│   ├── readline.js          # Secure password input
│   ├── redaction.js         # Output redaction
│   └── validation.js        # Configuration validation
└── test/                    # Test suite
```

## Encryption Flow

```
Password/Recovery Key
    |
    v
Argon2id KDF → 256-bit wrapping key
    |
    v
AES-256-GCM wrap/unwrap DEK
    |
    v
Random 256-bit DEK
    |
    v
AES-256-GCM encrypt/decrypt secrets
```

## Store Format

### Version 1 (legacy)
- Password-derived key directly encrypts secrets
- Single layer of encryption
- Being phased out

### Version 2 (current)
- Random DEK encrypts secrets
- Password wraps DEK
- Recovery key wraps DEK
- Atomic writes for credential changes

## Session Management

- Session is stored in memory only
- Password and recovery key may persist only in the OS keychain; `~/.secretveil/credentials.json` holds project metadata only (path, backend, timestamp)
- Plaintext password/recovery key are never written to the project or to `credentials.json`
- No `vault.key` or other persistent wrap-key file is created
- DEK is stored in memory session only
- Session is invalidated on `lock`; stored credentials are not
- Session expires when process exits

## Key Design Principles

1. **No plaintext on disk**: Secret values are never stored in plaintext
2. **No plaintext password storage**: The password is stored only as an encrypted slot under `~/.secretveil/`, never in the project
3. **Recovery key display**: The recovery key is shown once; a copy may persist encrypted in the user credential store
4. **Authenticated encryption**: AES-256-GCM with unique nonces and auth tags
5. **Secure key derivation**: Argon2id with configurable parameters
6. **Safe errors**: Error messages never contain secret values
7. **No unrestricted dump**: No command dumps all plaintext secrets

## Future Architecture

The codebase is designed for extension with the following planned modules:

- `scan/` - Secret scanning engine
- `profiles/` - Environment profile manager
- `policies/` - Policy engine
- `rotation/` - Secret rotation manager
- `audit/` - Audit log manager
- `benchmark/` - Exposure benchmark framework
- `docker/` - Docker integration
- `ci/` - CI/CD integrations
