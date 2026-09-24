# Scanning

## Overview

`secretveil scan` detects potential secrets in project files using pattern matching and entropy-based detection.

## Usage

```bash
secretveil scan
secretveil scan --json
secretveil scan --staged
```

## Detection Methods

### Pattern Detection

Detects known secret formats:
- API keys (`API_KEY=...`)
- AWS credentials (`aws_secret_access_key`, `AKIA...`)
- Database URLs (`postgres://user:password@...`)
- Bearer tokens (`Authorization: Bearer ...`)
- Private keys (`-----BEGIN PRIVATE KEY-----`)
- JWT tokens (`eyJ...`)
- Passwords (`password=...`)
- GitHub tokens (`github_token=...`)
- Stripe keys (`sk_live_...`)
- Slack tokens (`xox...`)

### Entropy Detection

Detects high-entropy strings that don't match known patterns:
- Strings with high Shannon entropy
- Minimum length threshold (20 characters)
- Filters out common strings

## Output Format

```
SecretVeil Scan

Scanning project...

HIGH   src/config.js:12
       Possible API Key
       Redacted: SBX_[REDACTED]A92C

3 findings
```

## Redaction

Detected secrets are always redacted in output:
- `sk_live_abc123def456` becomes `sk_l[REDACTED]456`
- The complete secret is never printed
- Only visible prefix and suffix characters are shown

## False Positives

The scanner is designed to minimize false positives:
- High-entropy threshold filters common strings
- Pattern matching uses specific regex patterns
- Context-aware detection reduces noise

## Supported File Types

Scans source code and configuration files:
- `.js`, `.ts`, `.jsx`, `.tsx`, `.py`, `.go`, `.rs`, `.java`
- `.sh`, `.bash`, `.zsh`
- `.yml`, `.yaml`, `.json`, `.toml`, `.xml`, `.ini`
- `.env`, `.env.example`, `.env.local`
- `Dockerfile`, `docker-compose.yml`
- `.github`, `.gitlab-ci.yml`
- `.npmrc`, `.gitconfig`

## CI Integration

Use `--json` for machine-readable output in CI pipelines:
```bash
secretveil scan --json | jq '.findings'
```

## Limitations

- Does not detect all secret formats
- May produce false positives for high-entropy strings
- Does not analyze compressed or binary files
- Does not scan Git history by default
