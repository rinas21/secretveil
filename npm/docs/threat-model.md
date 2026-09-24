# Threat Model

## Defined Threat Model

SecretVeil is designed to protect application secrets from AI coding agents that can inspect project files and execute commands.

## Threat Categories

### T1: Workspace Inspection

**Capability**: AI agent reads project files and searches for secrets.

**Protection**: Secret values are encrypted at rest in `.secretveil/secrets.enc`. The `.env` file contains `<encrypted>` placeholders instead of plaintext values. The DEK is wrapped by password/recovery and never stored on disk.

**Residual risk**: The encrypted store exists in the workspace and can be inspected. Without the password or recovery key, the secrets cannot be recovered.

### T2: Command Execution

**Capability**: AI agent executes development commands that might access `.env`.

**Protection**: `secretveil run` injects secrets at runtime via environment variables. The application receives secrets without a plaintext `.env` file.

**Residual risk**: The child process has secrets in its environment, which could be inspected by a privileged attacker.

### T3: Git History Analysis

**Capability**: AI agent searches Git history for committed secrets.

**Protection**: After `secretveil init`, the `.env` file no longer contains plaintext secrets. Git history may still contain previous commits with secrets.

**Residual risk**: Previous Git commits may contain plaintext secrets. Use `git filter-repo` or similar tools to remove secrets from history.

### T4: Configuration File Inspection

**Capability**: AI agent reads configuration files for hardcoded credentials.

**Protection**: `secretveil scan` detects potential secrets in configuration files. Users can remove them before initialization.

**Residual risk**: Some secrets may be in configuration files that `secretveil scan` doesn't detect.

### T5: Repository Data Inspection

**Capability**: AI agent inspects Git repository data for secrets.

**Protection**: `.gitignore` should exclude `.env` and `.secretveil/` (except `secrets.enc`).

**Residual risk**: If `.env` or `.secretveil/` are tracked in Git, secrets may be exposed.

## Recovery Key Threat Considerations

The recovery key is **not** a defense against AI agents. It is a **developer recovery credential**.

- The recovery key does NOT protect secrets from AI agents
- The recovery key is NOT automatically exposed to `secretveil run`
- The recovery key is NOT put in the child process environment
- The recovery key is NOT exposed through `status`, `scan`, `doctor`, `audit`, `benchmark`, or `ai-check`

## What Is NOT Protected

SecretVeil does **not** protect against:

- **Compromised operating systems**: An attacker with OS access can read all files
- **Privileged attackers**: An attacker with root privileges can read all files
- **Stolen passwords**: If the password is compromised, all secrets are exposed
- **Stolen recovery keys**: If the recovery key is compromised, all secrets are exposed
- **Compromised trusted runtime**: If the runtime is compromised, secrets are exposed
- **Process-memory inspection**: Running processes have secrets in memory
- **Malicious application code**: Applications can intentionally print secrets
- **Same-user attackers**: An attacker with the same user privileges can read files
- **Trusted launcher compromise**: If the launcher is compromised, the password may be exposed

## Honest Assessment

SecretVeil provides a meaningful security improvement by:
1. Removing plaintext secrets from the workspace
2. Encrypting secrets at rest
3. Injecting secrets at runtime only
4. Using the DEK architecture for credential separation

SecretVeil does **not** claim to be:
- "AI-proof"
- "100% secure"
- "Impossible to extract"
- "Zero-risk"
- Protection against every attacker

## Best Practices

1. Use strong passwords
2. Keep `.secretveil/secrets.enc` encrypted
3. Use `secretveil run` instead of directly sourcing `.env`
4. Run `secretveil scan` regularly
5. Use `secretveil doctor` to check configuration
6. Never commit `.env` to Git
7. Use `.gitignore` properly
8. Store the recovery key in a password manager or secure offline backup
9. Never store the recovery key inside the project
10. Regenerate the recovery key periodically
