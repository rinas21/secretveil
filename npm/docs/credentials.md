# Persistent Credentials

## Overview

Typing the password on every invocation does not survive a laptop restart gracefully. SecretVeil therefore keeps per-project unlock credentials in a **global** user-level store outside any project:

```
~/.secretveil/
├── credentials.json                 # project id → path, backend, timestamp (metadata only)
└── projects/
    └── <project-id>/
        ├── config.json              # encryption metadata
        └── secrets.enc              # encrypted secrets
```

Credentials and the encrypted store both live under `~/.secretveil/` — **nothing** is written under the project except the redacted `.env` (`KEY=<encrypted>`). AI agents that only read the repo never see `config.json` or `secrets.enc`.

`projects/<project-id>/` is intentional v2 layout (not a leftover). Each project id is SHA-256 of the canonical project path. `config.json` also stores a `projectBinding` (`path`, `dev`, `ino`, `birthtimeMs`) so a deleted directory recreated at the same path is not treated as still initialized — birthtime covers filesystems that reuse inodes. Credential rows in `credentials.json` alone never mean “initialized.”

If binding no longer matches (or a legacy store has no binding and `.env` has no `<encrypted>` placeholders), `secretveil init` lazily clears that orphan store + credentials and initializes fresh. Temporary inability to `stat` the project path does **not** trigger cleanup.

```json
{
  "projects": {
    "<project-id>": {
      "path": "/home/user/Desktop/project-a",
      "backend": "keychain",
      "updatedAt": "2026-01-01T00:00:00.000Z"
    }
  }
}
```

The project identifier is the hex SHA-256 of the canonical absolute project path (symlinks resolved, lowercased on Windows, separators normalized).

No `vault.key`, `key`, `master.key`, password, or recovery key is written under the project. Actual password and recovery credentials live in the OS keychain, never as plaintext in `credentials.json`.

## Backend: OS keychain

SecretVeil uses [`keytar`](https://github.com/atom/node-keytar) (an `optionalDependency`) when it can be loaded **and** a round-trip probe (set → get → delete) succeeds:

- **macOS**: Keychain
- **Windows**: Credential Manager (DPAPI-protected)
- **Linux**: libsecret-compatible Secret Service

Service name is `secretveil`; accounts are `<project-id>.password` and `<project-id>.recovery`. After every write, SecretVeil reads the value back to verify it was stored. If the keychain is unavailable, persistence is skipped with a warning — every command still works with manually entered credentials. There is **no** file-based credential fallback and **no** `vault.key`.

## Slot model

| Slot | Written by | Auto-used by | Purpose |
|------|-----------|--------------|---------|
| `password` | `init`, `migrate`, `unlock`/`run`/`decrypt` (after typed success), `password`, `recover` | `unlock`, `run`, `decrypt` | Normal automatic unlock |
| `recovery` | `init`, `migrate`, typed-recovery success, `recovery regenerate` | `recover` only | Emergency password reset |

`credential remove` deletes both keychain slots plus the index entry. `lock` only clears the in-memory session.

## Commands

```bash
secretveil credential status   # backends, which slots exist — never values
secretveil credential remove   # forget this project's stored credentials
```

After a laptop restart, `secretveil unlock`, `run`, and `decrypt` print `Using stored credential.` when the keychain entry is available.

## Trust boundary

- The OS keychain protects against other OS users and against casual same-user inspection; on macOS/Windows, first-use consent prompts additionally gate access.
- It does **not** protect against a fully compromised same-user account or malware with keychain access.
- See `docs/threat-model.md` and `docs/limitations.md`.
