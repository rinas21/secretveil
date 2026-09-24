# Limitations

## Honest Assessment

SecretVeil provides meaningful security improvements but does not make unsupported claims.

## What SecretVeil Does NOT Protect Against

### Compromised Operating Systems

A compromised OS can read all files on the system, including encrypted stores and process memory. SecretVeil cannot protect against this.

### Privileged Attackers

An attacker with root/sudo privileges can read all files, inspect all processes, and access all memory. SecretVeil cannot protect against this.

### Stolen Passwords

If the user's password is compromised, all secrets encrypted with that password can be decrypted by unwrapping the DEK. SecretVeil cannot protect against password theft.

### Stolen Recovery Keys

If the recovery key is compromised, all secrets can be recovered. The recovery key is an additional credential and must be treated as sensitive.

### Compromised Trusted Runtime

If the Node.js runtime or any trusted component is compromised, secrets in memory can be extracted. SecretVeil cannot protect against this.

### Process-Memory Inspection

Running processes have decrypted secrets in memory. A privileged attacker can inspect process memory. SecretVeil attempts to clean up memory, but this is not guaranteed in all Node.js environments.

### Malicious Application Code

An application can intentionally print its own secrets to stdout, logs, or files. SecretVeil cannot prevent this.

### Same-User Attackers

An attacker with the same user privileges as the developer can read all files accessible by that user. SecretVeil cannot protect against this.

### Trusted Launcher Compromise

If the launcher (e.g., the shell or IDE) is compromised, the password may be captured during entry. SecretVeil cannot protect against this.

### AI-Agent Detection

SecretVeil does **not** attempt to detect whether a process is "really AI". It analyzes the project's configuration and exposure surface instead.

## Secret Classification

`secretveil init` encrypts only variables whose names match the built-in heuristic (case-insensitive substring match against `API_KEY`, `DB_PASSWORD`, `JWT_SECRET`, `SECRET`, `PASSWORD`, `TOKEN`, `CREDENTIAL`). All other `.env` entries are intentionally preserved byte-identically in `.env` so plain configuration (`PORT=8080`, `APP_NAME=...`) keeps working without SecretVeil.

Consequences of this policy:

- The heuristic is name-based, not content-based. A credential-shaped **value** under a non-matching name (for example a database URL containing an embedded password under a custom variable name) is **not** automatically encrypted. Run `secretveil scan` (which uses content patterns plus entropy detection) and rename sensitive variables to match the heuristic, or add them explicitly.
- The heuristic can over-match (for example `TOKEN_EXPIRY=3600` is treated as a secret). Over-matching fails safe: the value is encrypted rather than left in plaintext.
- `export KEY=value` lines are supported; the `export` prefix is preserved when the value is replaced with `<encrypted>`.
- `#` starts a comment only at the beginning of a line. `#` inside quoted or unquoted values is preserved verbatim (matching dotenv behavior); there is no inline-comment stripping.

## Persistent Credential Storage

`~/.secretveil/` holds per-project unlock credentials so `unlock`/`run` survive a laptop restart:

- The **OS keychain backend** (macOS Keychain, Windows Credential Manager, Linux Secret Service via optional `keytar`) protects entries with OS access control plus first-use consent prompts where the platform provides them. It does **not** protect against a fully compromised same-user account, malware running with the user's privileges and keychain access, or a stolen unlocked login session.
- There is **no** encrypted-file credential fallback and **no** `vault.key`. If the keychain is unavailable, SecretVeil does not persist unlock credentials and falls back to prompting.
- Neither approach protects against an AI agent (or any process) with unrestricted access to the user's account. SecretVeil's threat model covers agents that can inspect the **project workspace**; an agent holding the user's login session is outside it. See `docs/credentials.md` and `docs/threat-model.md`.

## Recovery Key Limitations

- The recovery key is an additional credential, not a security defense against AI agents
- The recovery key must be stored securely outside the project
- If the recovery key is lost and the password is forgotten, secrets cannot be recovered
- The recovery key should be treated with the same sensitivity as the password

## Known Limitations

1. **Temporary files**: The `secretveil run` command uses `spawn` with `shell: false`. In some environments, shell commands may create temporary files.
2. **Shell injection**: `secretveil run` passes arguments to `spawn` directly. Shell injection is prevented by `shell: false`, but command arguments should be validated.
3. **Path traversal**: The CLI does not validate all file paths. Users should ensure project directories are trusted.
4. **Symlink attacks**: File operations do not explicitly handle symlink attacks. Users should ensure `.secretveil/` is not a symlink to a sensitive location.
5. **TOCTOU**: File permissions and ownership are set after creation. A TOCTOU race condition is theoretically possible but practically unlikely.
6. **Corrupted store recovery**: Corrupted encryption metadata causes the store to fail safely. No recovery mechanism exists for corrupted data.
7. **Accidental plaintext backups**: Users should ensure backups do not contain plaintext secrets.
8. **Memory handling**: Node.js does not provide guaranteed secure memory wiping. Decrypted secrets exist in memory during runtime.

## Node.js Memory Limitations

Node.js does not provide guaranteed secure memory wiping. While we minimize plaintext lifetime and use Buffers for cryptographic material, we cannot claim that secrets are guaranteed to be erased from RAM. Users should be aware that decrypted secrets may persist in memory until the process exits.

## Git History

After `secretveil init`, previous Git commits may contain plaintext secrets. Users should:
1. Use `git filter-repo` or similar tools to remove secrets from history
2. Never commit `.env` to Git
3. Use `.gitignore` properly

## Docker Considerations

Docker `ARG` and `ENV` directives can persist in image metadata/layers. SecretVeil does not create Docker images with secrets. Users should:
1. Never use `ARG` or `ENV` for secrets in Dockerfiles
2. Use `secretveil run -- docker compose up` for runtime injection
3. Review Dockerfiles for potential secret exposure

## CI/CD Considerations

The CI implementation must not put long-lived SecretVeil passwords into repository files. Users should:
1. Use secret management in CI/CD systems
2. Pass passwords via secure environment variables
3. Never hardcode passwords in CI configuration

## Redaction Limitations

Runtime output redaction is defense in depth, not the primary security boundary:
- Does not rely on redaction as the primary protection
- The application already has access to plaintext secrets
- Redaction may have false positives/negatives
- Binary output and very large streams may not be fully redacted
- Partial secrets embedded in URLs may not be fully redacted
