# SecretVeil Task Context

## Project Overview

SecretVeil is a Node.js/npm CLI tool for protecting application secrets from AI coding agents through encrypted-at-rest storage and runtime injection.

**Package**: `@rinas21/secretveil`
**CLI**: `secretveil`
**Version**: 1.0.0
**Type**: ESM (`"type": "module"`)
**Node.js**: `>=20.0.0`

## Architecture

```
src/
├── cli.js                    # CLI entry point
├── commands/                 # All command modules
│   ├── init.js              # Initialize SecretVeil
│   ├── status.js            # Show status
│   ├── unlock.js            # Unlock store
│   ├── lock.js              # Lock store
│   ├── run.js               # Run command with secrets (v1/v2 aware)
│   ├── decrypt.js           # Restore decrypted secrets into .env
│   ├── encrypt.js           # Encrypt plaintext secrets in .env
│   ├── recover.js           # Recover password via recovery key (v2)
│   ├── password.js          # Change password, re-wrap DEK only (v2)
│   ├── recovery.js          # Regenerate recovery key (v2)
│   ├── migrate.js           # Migrate v1 store to v2
│   ├── credential.js        # credential status/remove (user-level store)
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
│   ├── kdf.js               # Argon2id KDF (SHA-256 key extraction)
│   └── encryption.js         # AES-256-GCM, DEK wrap/unwrap, recovery keys
├── credentials/
│   ├── store.js             # ~/.secretveil/credentials.json metadata + OS keychain slots
│   └── resolve.js           # resolveDEK: stored-password auto-unlock + typed fallback
├── secrets/
│   ├── parser.js            # .env parsing
│   └── store.js             # Encrypted store in ~/.secretveil/projects/<id>/ (v1/v2, atomicReplace)
├── session/
│   └── session.js           # In-memory session management (holds DEK for v2)
├── runtime/
│   └── runner.js            # Decryption in memory (v1 + v2 helpers)
├── utils/
│   ├── helpers.js           # Detection helpers
│   ├── readline.js          # Secure password input (shared lazy reader, piped/TTY)
│   ├── redaction.js         # Output redaction (Redactor class)
│   └── validation.js        # Configuration validation (v1 + v2)
└── test/                    # Test suite
```

## Cryptographic Design

- **KDF**: Argon2id with SHA-256 key extraction (`argon2.hash()` → `createHash('sha256').update(hash).digest()`)
- **Encryption**: AES-256-GCM with unique nonces (12 bytes) and auth tags (16 bytes)
- **Salt**: 16 bytes, stored hex-encoded in config
- **KDF Params**: memoryCost=65536, timeCost=3, parallelism=1, hashLength=32
- **DEK (v2)**: Random 256-bit key (`crypto.randomBytes(32)`) encrypts secrets; password and normalized recovery key each wrap the DEK via `wrapKey`/`unwrapKey`. Recovery display format is 6×5 uppercase alphanumerics (30 chars, ~155 bits); wrapping always uses `normalizeRecoveryKey()` output so `SV-…`, lowercase, and space-separated inputs all work.

## Key Security Properties

1. **No plaintext on disk**: `.env` has `<encrypted>` placeholders
2. **No plaintext password storage**: Password/recovery persist only in the OS keychain; `~/.secretveil/credentials.json` is metadata only; never in the project
3. **Authenticated encryption**: AES-256-GCM with unique nonces and auth tags
4. **Safe errors**: Error messages never contain secret values
5. **No unrestricted dump**: No plaintext dump command exists
6. **Session management**: In-memory only, cleared on `lock`
7. **Runtime injection**: Every `.env` variable injected via `spawn` environment (secrets decrypted, non-secrets parsed; names preserved exactly)

## Important Implementation Details

### Password Input

`src/utils/readline.js` uses a shared lazy reader with a promise chain. Piped stdin is read once (`readFileSync(0)`) on first prompt and served line-by-line; TTY uses per-prompt interfaces — hidden raw-mode input with fallback to visible readline, always closed after answering so the process exits. This supports multi-prompt flows (`init`, `recover`, `password`) on Linux/macOS/Windows. Never pass credentials as CLI args.

### KDF Bug Fix

The KDF uses `argon2.hash()` which returns a full encoded string. To get a 32-byte key, we use `createHash('sha256').update(hash).digest()`. This is a deliberate design choice to properly extract a 32-byte key from Argon2id output.

### Decryption API

`decryptSecret(encryptedData, password, salt, kdfParams)` expects:
- `encryptedData`: Object with `nonce`, `ciphertext`, `tag` properties
- `password`: String (NOT the derived key)
- `salt`: Buffer
- `kdfParams`: Object

Common bug: Passing the derived key (Buffer) instead of the password string.

### CLI Testing

Integration tests should use module imports (not spawned processes) to avoid stdin issues. The `cli-all.test.js` demonstrates this approach with `process.chdir()` and `captureLogs()`.

## Test Suite

- `test/parser.test.js` - .env parsing (11 tests)
- `test/crypto.test.js` - Cryptography (14 tests)
- `test/store.test.js` - Store operations (6 tests)
- `test/cli-lifecycle.test.js` - Spawn exit/failure/full-env injection/decrypt/encrypt/recreate/credential regression (28 tests)
- `test/e2e-pack.test.js` - Installed-package init/run/credential persistence (1 test)

**Total**: 171 tests, all passing

## Commands Reference

| Command | Description |
|---------|-------------|
| `init` | Initialize SecretVeil |
| `status` | Show status |
| `unlock` | Unlock store |
| `lock` | Lock store |
| `run <cmd>` | Run with every `.env` variable injected |
| `decrypt` | Restore decrypted secrets into `.env` (plaintext warning + confirm) |
| `encrypt` | Encrypt plaintext secrets in `.env` back to protected state |
| `recover` | Reset password via recovery key |
| `password` | Change password (re-wrap DEK) |
| `recovery regenerate` | Regenerate recovery key |
| `migrate` | Migrate v1 store to v2 |
| `credential status` | Show stored credential slots (never values) |
| `credential remove` | Forget stored credentials for project |
| `scan` | Detect secrets |
| `doctor` | Diagnose config |
| `profile` | Manage profiles |
| `policy` | Manage policies |
| `rotate` | Rotate secrets |
| `audit` | View audit history |
| `ai-check` | AI exposure analysis |
| `benchmark` | Exposure benchmark |
| `git-check` | Git exposure check |
| `docker` | Docker integration |

## Development Commands

```bash
npm test                    # Run all tests
npm pack --dry-run          # Verify package contents
secretveil --help           # Show help
secretveil --version        # Show version
```

## Key Files

- `package.json` - Package configuration (ESM, bin, dependencies)
- `bin/secretveil.js` - CLI entry point
- `src/cli.js` - CLI routing and help
- `.gitignore` - Excluded files
- `README.md` - Documentation
- `LICENSE` - MIT License
- `docs/` - Additional documentation

## Security Notes

- Never commit secrets to Git
- Never put passwords in command-line arguments
- Never put passwords in environment variables
- Never log passwords
- Never put encryption keys in project files
- User-level credentials: password/recovery in OS keychain; `~/.secretveil/credentials.json` is global metadata only; never in the project; no `vault.key`
- `keytar` is optional: without OS keychain, credentials do not persist (prompt fallback); inject via `__setKeytarLoader` or `SECRETVEIL_TEST_KEYCHAIN` in tests
- Spawn-based CLI tests must isolate `HOME`/`USERPROFILE` per test so they never touch the real `~/.secretveil`
- Encrypted store lives under `~/.secretveil/projects/<project-id>/` (`config.json` with `projectBinding`, `secrets.enc`); project has no `.secretveil/` — only redacted `.env`. Credential metadata alone does not mean initialized; deleted/recreated paths re-init via binding mismatch / orphan reconcile.
- The password-derived key exists only in memory during runtime

## Future Architecture

The codebase is designed for extension with:
- `scan/` - Secret scanning engine
- `profiles/` - Environment profile manager
- `policies/` - Policy engine
- `rotation/` - Secret rotation manager
- `benchmark/` - Exposure benchmark framework
- `docker/` - Docker integration
- `ci/` - CI/CD integrations
- `docs/` - Documentation (architecture, security-model, threat-model, etc.)
