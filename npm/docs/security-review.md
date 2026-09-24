# Security Review

## Summary

This document covers the security review findings and fixes for SecretVeil.

## Issues Found and Fixed

### Plaintext Secrets on Disk

**Issue**: After `secretveil init`, plaintext secret values must not exist in the project workspace.

**Fix**: The `.env` file is rewritten with `<encrypted>` placeholders. Plaintext values are removed.

**Verification**: `grep -r "SBX_API_7F31A92C" . --exclude-dir=.secretveil` returns no results.

### Passwords in Logs

**Issue**: Passwords must never appear in CLI output, error messages, or logs.

**Fix**: All password input uses hidden terminal input. Error messages never contain passwords. Audit logs exclude secret values.

### Passwords in Error Messages

**Issue**: Error messages must not contain passwords, API keys, tokens, or decrypted environment variables.

**Fix**: All errors use generic messages like "Failed to decrypt secret store. Check your password and SecretVeil configuration."

### Passwords in Command-Line Arguments

**Issue**: Passwords must never be passed as command-line arguments.

**Fix**: Passwords are read from `stdin` using secure input. The `--help` and `--version` flags do not accept passwords.

### Passwords in Environment Variables

**Issue**: Passwords must never be put in environment variables.

**Fix**: Passwords are read from `stdin` and stored only in the in-memory session object. The session is cleared on `lock`.

### Keys in Project Files

**Issue**: The password-derived encryption key must never be placed in the project workspace.

**Fix**: The key is derived from the password at runtime and exists only in memory. The `.secretveil/` directory contains only encrypted data and metadata.

### Temporary Plaintext Files

**Issue**: Temporary files must not contain plaintext secrets.

**Fix**: `secretveil run` uses `spawn` with `shell: false` and never creates plaintext `.env` files. Decrypted secrets are kept in memory and deleted after use.

### Secrets in Stack Traces

**Issue**: Secrets must not appear in stack traces or debug output.

**Fix**: Error handling catches exceptions and uses generic messages. The `debug` module is not used.

### Secrets in Git

**Issue**: Secrets must not be committed to Git.

**Fix**: `.gitignore` excludes `.env`, `*.env`, and `.secretveil/` (except `secrets.enc`).

### Secrets in Test Fixtures

**Issue**: Test files must not contain real secret values.

**Fix**: Tests use mock values like `SBX_API_7F31A92C` which are test fixtures. No real secrets are used.

### Unsafe Child-Process Argument Handling

**Issue**: Child process arguments must be handled safely.

**Fix**: `secretveil run` uses `spawn` with `shell: false` to prevent shell injection. Arguments are passed as arrays, not strings.

### Shell Injection

**Issue**: Commands must not be vulnerable to shell injection.

**Fix**: `shell: false` prevents shell injection. Commands are passed as arrays.

### Path Traversal

**Issue**: File paths must be validated.

**Fix**: Project paths use `path.join` and are relative to `process.cwd()`.

### Symlink Attacks

**Issue**: Symlink attacks could redirect file operations.

**Fix**: The `.secretveil/` directory should not be a symlink to a sensitive location. Users are advised to check this.

### TOCTOU Problems

**Issue**: Time-of-check-to-time-of-use races could affect file permissions.

**Fix**: File permissions are set after creation. This is a best effort approach.

### Insecure File Permissions

**Issue**: SecretVeil files should have restrictive permissions.

**Fix**: Files are created with mode `0o600`. The `.env` file also uses mode `0o600`.

### Corrupted Store Recovery

**Issue**: Corrupted stores must fail safely.

**Fix**: The `init` command verifies the encrypted store before removing plaintext. If verification fails, the store is cleaned up.

### Accidental Plaintext Backups

**Issue**: Backups must not contain plaintext secrets.

**Fix**: Users are advised to ensure backups do not contain plaintext secrets. The `.gitignore` excludes `.env` files.

## Ongoing Security Measures

1. Run `npm test` after every change
2. Run `npm pack --dry-run` to verify package contents
3. Use `secretveil scan` to check for secrets in the project
4. Use `secretveil doctor` to check configuration
5. Review error messages for potential secret leakage
6. Never commit secrets to Git
7. Use strong passwords for encryption

## Security Test Results

All 110 tests pass, including:
- 11 parser tests
- 14 crypto tests (KDF, AES-256-GCM, encryption/decryption)
- 13 store and session tests
- 8 CLI integration tests
- 15 new feature tests (scan, doctor, profile, policy, audit, benchmark, ai-check, git-check, docker)
- 15 validation tests
- 19 DEK tests (DEK generation, key wrapping, recovery keys, v2 store, security)
- 15 recovery tests (unlock, reset, regeneration, migration, error safety)

No plaintext secrets are found in the project after initialization.
No passwords appear in CLI output.
No secret values appear in errors.
Audit logs contain no secret values.
Scanner output redacts detected secrets.
Policies restrict injected secrets correctly.

## DEK Architecture Review (v2)

Reviewed items specific to the password + recovery key architecture:

- **DEK generation**: `crypto.randomBytes(32)` — CSPRNG, 256 bits, never derived from password
- **DEK persistence**: DEK exists only in memory (session) and AES-256-GCM-wrapped in `keyEncryption`; never plaintext on disk
- **Recovery entropy**: 30 random bytes mapped to 30 uppercase alphanumerics (~155 bits); display dashes are formatting only
- **Normalization safety**: `init`/`recovery regenerate` wrap `normalizeRecoveryKey()` output, so `SV-…`, lowercase, and space-separated inputs unwrap the same DEK; entropy is unaffected (formatting only)
- **Nonce reuse**: every `encryptWithKey`/`wrapKey` call generates a fresh 12-byte nonce; password and recovery wrappers use independent salts and nonces
- **Recovery key storage**: shown once on `init`/`recovery regenerate`; never written to `.secretveil/`, env, logs, errors, or audit records (`addAuditEntry` strips `recoveryKey`, `dek`, `ciphertext`, etc.)
- **CLI args**: `recover`/`password`/`recovery` take no credential positionals; all credentials via secure stdin prompt
- **Child process**: `run` injects only application secrets, never the recovery key or DEK
- **Other commands**: `status`, `scan`, `doctor`, `audit`, `benchmark`, `ai-check` never print key material
- **Atomicity**: `password`, `recover`, `recovery regenerate`, `rotate` (v2), and migration use temp-file + rename via `atomicReplace`; temp files are `.tmp`-suffixed inside `.secretveil/` (gitignored) and removed on success/failure paths
- **Permissions**: store files written `0o600` with best-effort `chmod`; Windows has no Unix semantics — documented in `docs/limitations.md`
- **Memory**: passwords/DEKs held only in module-scope session; cleared on `lock`/`run` completion; Node.js cannot guarantee RAM wiping — documented honestly in `docs/limitations.md`
- **Migration**: v1 stores are decrypted in memory, re-encrypted under a fresh DEK, and replaced atomically; original store is preserved if migration fails
- **Backward compat**: `unlock`/`run`/`rotate`/`profile` detect `config.version` and use the v1 password-direct path for legacy stores
