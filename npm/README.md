# SecretVeil

Protect application secrets from AI coding agents with encrypted-at-rest storage and runtime injection.

## Problem

AI coding agents can inspect project files and execute commands. A `.env` file protected only by `.gitignore` remains readable to the agent.

SecretVeil keeps secret values encrypted at rest and makes them available to applications at runtime.

## Installation

```bash
npm install -g @rinas21/secretveil
```

## Quick Start

```bash
cd my-project
secretveil init
secretveil run npm start
```

## Commands

### Core Commands

- `secretveil init` - Initialize SecretVeil in the current project
- `secretveil status` - Show SecretVeil status
- `secretveil unlock` - Unlock the encrypted secret store
- `secretveil lock` - Lock the secret store and invalidate session
- `secretveil run <command>` - Run a command with decrypted secrets injected

### Recovery & Password

- `secretveil recover` - Recover from forgotten password using recovery key
- `secretveil password` - Change the SecretVeil password
- `secretveil recovery regenerate` - Regenerate the recovery key
- `secretveil migrate` - Migrate a version 1 store to version 2 (DEK architecture)

### Stored Credentials

- `secretveil credential status` - Show which unlock credentials are stored for this project
- `secretveil credential remove` - Forget this project's stored credentials

After `init`, your password and recovery key are kept in the OS keychain when available (`~/.secretveil/credentials.json` tracks projects only) so `unlock`, `run`, and `decrypt` work after a laptop restart without re-entering anything. The project directory itself never contains the persisted credential. See `docs/credentials.md` for backends and trust boundaries.

### Secret Detection

- `secretveil scan` - Scan for exposed secrets in source code and configuration
- `secretveil scan --json` - Machine-readable JSON output
- `secretveil scan --staged` - Scan only Git staged files

### Diagnostics

- `secretveil doctor` - Diagnose SecretVeil configuration and security posture

### Environment Profiles

- `secretveil profile create <name>` - Create an environment profile
- `secretveil profile list` - List all profiles
- `secretveil profile delete <name>` - Delete a profile

### Secret Policies

- `secretveil policy create <name> <secret1> <secret2>` - Create a policy with allowed secrets
- `secretveil policy list` - List all policies
- `secretveil policy delete <name>` - Delete a policy

### Secret Rotation

- `secretveil rotate <secret-name>` - Rotate a secret value
- `secretveil rotate --generate <secret-name>` - Generate a random new secret value

### Audit & History

- `secretveil audit` - View security events and access history
- `secretveil audit --json` - Machine-readable JSON output

### AI Exposure Analysis

- `secretveil ai-check` - Analyze AI-agent exposure risks in the project

### Benchmark

- `secretveil benchmark` - Run exposure benchmark
- `secretveil benchmark --baseline` - Run in baseline (plaintext) mode
- `secretveil benchmark --protected` - Run in protected mode
- `secretveil benchmark --json` - Machine-readable JSON output

### Git Integration

- `secretveil git-check` - Check Git repository for secret exposure

### Docker Support

- `secretveil docker` - Docker integration guidance

### Options

- `--help, -h` - Show help message
- `--version, -v` - Show version
- `--json, -j` - Output machine-readable JSON
- `--baseline` - Run benchmark in baseline mode
- `--protected` - Run benchmark in protected mode
- `--generate, -g` - Generate random secret value
- `--profile, -p` - Specify environment profile
- `--policy` - Specify secret policy

## Security Architecture

SecretVeil uses a **Data Encryption Key (DEK)** architecture:

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
                           │
                           ▼
                      Application
```

The actual application secrets are encrypted using the random DEK. The password and recovery key are only used to unlock/wrap the DEK. This allows password changes and recovery without re-encrypting the entire secret store.

## Recovery Key

During `secretveil init`, a recovery key is displayed once:

```
SecretVeil Recovery Key

SV-7K4P-X92M-Q8FD-3L7N-V6RT-2WKP

IMPORTANT: Store this recovery key somewhere secure.
If you lose both your password and recovery key,
your encrypted secrets cannot be recovered.
```

The recovery key:
- Contains 30 alphanumeric characters
- Is formatted as 6 groups of 5 characters separated by dashes
- Must be stored securely outside the project
- Can be used to recover access if the password is forgotten
- Can be regenerated with `secretveil recovery regenerate`

**Never store the recovery key inside the project.**

## Two Credentials

SecretVeil has two independent unlock credentials:

1. **Password** - Your chosen password for daily use
2. **Recovery Key** - Generated during initialization for emergency recovery

| Scenario | Solution |
|----------|----------|
| Forgot password | Use recovery key with `secretveil recover` |
| Lost recovery key | Password still unlocks the store |
| Lost both | Encrypted secrets cannot be recovered |

Strongly recommend storing the recovery key in a password manager or secure offline backup.

## Threat Model

SecretVeil protects against AI coding agents that can read project files and execute commands. The encrypted store lives under `~/.secretveil/projects/<id>/` (outside the project), so agents scanning the repo never see `config.json` or `secrets.enc`. Decryption still requires the password or recovery key.

### What SecretVeil Protects Against

- AI coding agents reading project files
- Workspace search for plaintext secrets
- Command execution that tries to access `.env`
- Git history analysis for exposed secrets

### Limitations

SecretVeil does **not** protect against:

- Compromised operating systems
- Privileged attackers
- Stolen passwords
- Compromised trusted runtime components
- Application code intentionally printing its own secrets
- Process-memory inspection
- An attacker that can legitimately obtain the decryption credential
- Other threats outside the defined threat model

SecretVeil does not claim complete protection from AI agents.

## Design Principle

The AI agent may see redacted `.env` placeholders in the project, but the encrypted store and credentials live under `~/.secretveil/` — outside the repo. The agent should not automatically receive the plaintext secret required by the application.

There is no unrestricted plaintext dump command in any phase.

The recovery key is an additional credential for developer recovery, not automatic application execution. It is never exposed to `secretveil run`, `status`, `scan`, `doctor`, `audit`, `benchmark`, or `ai-check`.

## Git Workflow

Encrypted store files live under `~/.secretveil/` (outside the repo). Keep `.env` out of Git. If you still have a legacy in-repo `.secretveil/` directory, ignore it.

Recommended `.gitignore`:
```
.secretveil/
.env
*.env
node_modules/
```

## CLI Help

```
secretveil --help
```

Shows all available commands and options.

## License

MIT
