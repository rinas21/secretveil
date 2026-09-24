# SecretVeil

**Protect application secrets from workspace exposure.**

SecretVeil is a developer security tool designed to keep application secrets protected while still making them available to applications at runtime.

The project is being developed as a **multi-language ecosystem**, with each implementation maintained in its own language-specific directory.

## Project Status

### Available

* **Node.js / npm** — `@rinas21/secretveil`
* Version: **1.0.0**
* CLI: `secretveil`
* Published on npm
* Core encryption, secret storage, runtime injection, recovery, scanning, profiles, policies, auditing, and security tooling implemented
* Test suite: **171 passing tests**
* Published package has been tested from a clean project installation

### Planned

Additional language implementations may be added in the future.

Examples:

```text
secretveil/
├── npm/
├── python/
├── go/
├── rust/
└── ...
```

The language directories are independent implementations of the SecretVeil concept.

## Repository Structure

```text
secretveil/
│
├── README.md
│
├── npm/
│   ├── src/
│   ├── bin/
│   ├── test/
│   ├── docs/
│   ├── package.json
│   └── README.md
│
├── python/
│   └── ...
│
└── ...
```

### Language Implementations

Each implementation should have its own directory named after the programming language or ecosystem.

For example:

* `npm/` — Node.js implementation and npm package
* `python/` — Python implementation
* `go/` — Go implementation
* `rust/` — Rust implementation

If a new implementation is created, its development should remain isolated inside its corresponding directory.

## Development

The current implementation is the **Node.js / npm version**.

```bash
cd npm
npm install
npm test
```

Run the CLI locally:

```bash
node bin/secretveil.js --help
```

Or, after installing the package:

```bash
npx secretveil --help
```

## Security Model

SecretVeil is designed around the principle that application secrets should not need to remain exposed as plaintext files during normal development.

The current implementation uses:

* AES-256-GCM for secret encryption
* Random data encryption keys
* Password-derived key protection
* Recovery-key-based recovery
* Global credential storage
* Runtime secret injection
* Secret scanning
* Security diagnostics
* Audit events
* Environment profiles
* Secret policies

Secret values are decrypted in memory when required by an application rather than being printed or written back to the workspace during normal runtime execution.

## Runtime Usage

A protected `.env` can contain SecretVeil-managed values:

```env
API_KEY=<encrypted>
DB_PASSWORD=<encrypted>
JWT_SECRET=<encrypted>

APP_NAME="My Application"
NODE_ENV=development
PORT=8080
```

Applications can then be started through SecretVeil:

```bash
secretveil run -- npm start
```

SecretVeil injects the required environment variables into the application process at runtime.

## Important Principle

SecretVeil is **not intended to make secrets impossible to access**.

Applications need access to secrets to function.

The goal is to reduce unnecessary exposure of those secrets, particularly within development workspaces where source code, `.env` files, AI coding agents, logs, backups, and other tooling may have access to project files.

## Implementations

| Language / Ecosystem | Directory             | Status    |
| -------------------- | --------------------- | --------- |
| Node.js / npm        | [`npm/`](./npm)       | Available |
| Python               | [`python/`](./python) | Planned   |
| Go                   | [`go/`](./go)         | Planned   |
| Rust                 | [`rust/`](./rust)     | Planned   |

Additional implementations can be added as the project evolves.

## Contributing

Development for each language implementation should remain inside its respective directory.

For example:

```text
python/
```

should contain the Python implementation and its tests, while:

```text
npm/
```

contains the Node.js implementation.

Changes should be tested within the relevant implementation before being merged into the main project.

## License

See the [LICENSE](./npm/LICENSE) file for licensing information.
