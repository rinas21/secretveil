# Configuration

## Initialization

```bash
cd my-project
secretveil init
```

This detects secrets in `.env`, generates a random DEK, encrypts secrets with the DEK, creates password and recovery wrappers, and replaces values with `<encrypted>` placeholders.

## Store Files

Encrypted data lives **outside the project** so AI agents scanning the repo never see it:

```
~/.secretveil/projects/<project-id>/
├── config.json       # Encryption metadata + projectBinding (path/dev/ino)
├── secrets.enc       # Encrypted secrets (keyEncryption, secrets encrypted with DEK)
├── profiles/         # Environment-specific encrypted profiles
├── policies.json     # Per-application secret policies
└── audit.log         # Security event history
```

`projectBinding` (`path`, `dev`, `ino`, `birthtimeMs`) ties the store to the directory identity. A deleted folder recreated at the same path is not “already initialized.” Credential metadata alone never counts. The project directory only keeps a redacted `.env`. Legacy `project/.secretveil/` stores are still readable if present.

### config.json (Version 2)

Contains encryption metadata:
- `version`: Store version (currently 2)
- `algorithm`: Encryption algorithm (aes-256-gcm)
- `kdf`: Key derivation function (argon2id)
- `kdfParams`: Argon2id parameters (memoryCost, timeCost, parallelism, hashLength)
- `salt`: Hex-encoded salt for key derivation
- `secretKeys`: List of secret key names
- `keyEncryption`: Password and recovery key wrappers

### keyEncryption Structure

```json
{
  "keyEncryption": {
    "password": {
      "salt": "...",
      "nonce": "...",
      "ciphertext": "...",
      "tag": "..."
    },
    "recovery": {
      "salt": "...",
      "nonce": "...",
      "ciphertext": "...",
      "tag": "..."
    }
  }
}
```

Each wrapper contains the salt, nonce, ciphertext, and authentication tag for the wrapped DEK.

### .env File

After initialization, the `.env` file contains:
- `<encrypted>` placeholders for secret values
- Original values for non-secret configuration (e.g., `PORT=3000`)
- Comments preserved

## .gitignore

Recommended `.gitignore`:
```gitignore
# Legacy in-repo store (current SecretVeil keeps store in ~/.secretveil/)
.secretveil/

# Environment files
.env
*.env
.env.local
.env.*

# Dependencies
node_modules/

# Build artifacts
dist/
build/
```

## Environment Variables

`secretveil run` injects every variable defined in `.env` into the child process:
- Secret variables: decrypted original values from the store
- Non-secret variables: exact parsed values from `.env`
- Names are preserved exactly (`port=8080` becomes `process.env.port`, never `PORT`)
- Values keep `#`, `=`, spaces, inner quotes, URLs, special characters, and empty strings
- A `#` at the start of a line is a comment and is not injected
- The parent process does not keep decrypted secrets after the child exits

## Profile Configuration

Profiles allow environment-specific secret isolation:
```bash
secretveil profile create development
secretveil profile create staging
secretveil profile create production
secretveil run --profile development npm start
```

## Policy Configuration

Policies restrict which secrets can be injected:
```bash
secretveil policy create backend API_KEY DB_PASSWORD JWT_SECRET
secretveil run --policy backend npm start
```

## Recovery Key

During initialization, a recovery key is displayed once. It must be stored securely outside the project.

To recover from a forgotten password:
```bash
secretveil recover
```

To regenerate the recovery key:
```bash
secretveil recovery regenerate
```

## Validation

All configuration files are validated on load:
- Unknown versions are rejected
- Malformed metadata is rejected
- Invalid salts, nonces, and tags are rejected
- Corrupted stores fail safely
- Version 2 stores require valid `keyEncryption` data

## Migration

Version 1 stores can be migrated to version 2:
1. Load v1 store with existing password
2. Decrypt existing secrets
3. Generate random DEK
4. Encrypt secrets with DEK
5. Create password and recovery wrappers
6. Write new version 2 store atomically
7. Show recovery key to user

Migration preserves all existing secrets and does not re-encrypt if already v2.
