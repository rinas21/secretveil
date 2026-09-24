# Security Model

## Attacker Capabilities

SecretVeil defines the following attacker capabilities for threat modeling:

### AI Coding Agent

An AI coding agent may be able to:

- Read accessible files in the project workspace
- Search the workspace for secret patterns
- Execute normal development commands
- Modify source code
- Execute scripts
- Inspect generated artifacts
- Inspect Git repository data

### Same-User Attacker

An attacker running with the same user privileges can:

- Read all files accessible by the current user
- Inspect process memory
- Monitor process environment variables
- Read stdin/stdout/stderr of running processes

### Privileged OS Attacker

A privileged OS attacker can:

- Read all files on the system
- Inspect all process memory
- Access all environment variables
- Install keyloggers or hooks

## DEK Architecture Security

SecretVeil uses a layered security model with the DEK architecture:

### What SecretVeil Protects

1. **Workspace inspection**: Plaintext secrets are replaced with `<encrypted>` placeholders
2. **File search**: Secret values are stored encrypted in `.secretveil/secrets.enc`
3. **Git history analysis**: The `.env` file contains no plaintext secrets after initialization
4. **Command execution**: `secretveil run` injects secrets at runtime via environment variables
5. **Configuration file inspection**: `secretveil scan` detects potential secrets
6. **Recovery key isolation**: The recovery key is never stored in the project

### What SecretVeil Does NOT Protect Against

SecretVeil does **not** protect against:

1. **Compromised operating systems**: An attacker with OS access can read all files
2. **Privileged attackers**: An attacker with root/sudo can read all files
3. **Stolen passwords**: If the password is compromised, all secrets are exposed
4. **Stolen recovery keys**: If the recovery key is compromised, all secrets are exposed
5. **Compromised trusted runtime**: If the Node.js runtime is compromised, secrets in memory can be extracted
6. **Process-memory inspection**: Running processes have secrets in memory
7. **Malicious application code**: Applications can intentionally print secrets
8. **Same-user attackers**: An attacker with the same user privileges can read files
9. **Trusted launcher compromise**: If the launcher is compromised, the password may be captured

## Credential Separation

### Password vs. Recovery Key

- **Password**: Used for daily operations (unlock, run, rotate, change)
- **Recovery Key**: Used only for password recovery when the password is forgotten

Both credentials independently wrap the same DEK. Either credential can unlock the store.

### Recovery Key Security

The recovery key is an additional credential and therefore must be treated as sensitive:
- It is never stored in plaintext; an encrypted copy may persist in `~/.secretveil/` for emergency `recover`
- It is never logged
- It is never included in error messages
- It is never included in audit records
- It is never exposed to `secretveil run`, `status`, `scan`, `doctor`, `audit`, `benchmark`, or `ai-check`

## Honest Assessment

SecretVeil provides a meaningful security improvement by:
1. Removing plaintext secrets from the workspace
2. Encrypting secrets at rest with AES-256-GCM
3. Injecting secrets at runtime only
4. Separating encryption from access credentials via the DEK

SecretVeil does **not** claim to be:
- "AI-proof"
- "100% secure"
- "Impossible to extract"
- "Zero-risk"
- Protection against every attacker

## Security Test Results

All tests pass, including:
- 76 existing tests (parser, crypto, store, session, validation, scan, CLI, integration)
- 19 new tests (DEK generation, key wrapping, recovery keys, v2 store, security)
- Total: 95 tests, all passing

No plaintext secrets are found in the project after initialization.
No passwords appear in CLI output.
No secret values appear in errors.
Audit logs contain no secret values.
Scanner output redacts detected secrets.
Policies restrict injected secrets correctly.
