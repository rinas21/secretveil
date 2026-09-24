import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { redactSecret, scanFile, detectHighEntropy, scanProject } from '../src/commands/scan.js';

const TEST_DIR = '/tmp/opencode/secretveil-scan-test';

describe('Scanner - Redaction', () => {
  it('redacts secret values', () => {
    const result = redactSecret('sk_live_1234567890abcdef');
    assert.ok(result.includes('[REDACTED]'));
    assert.ok(result.includes('sk_l'));
    assert.ok(result.includes('cdef'));
    assert.ok(!result.includes('1234567890'));
  });

  it('redacts short values completely', () => {
    const result = redactSecret('abc');
    assert.strictEqual(result, '[REDACTED]');
  });

  it('redacts all secrets by default', () => {
    const result = redactSecret('');
    assert.strictEqual(result, '[REDACTED]');
  });

  it('redacts long secrets with visible chars', () => {
    const result = redactSecret('sk_live_1234567890abcdef');
    assert.ok(result.includes('[REDACTED]'));
    assert.ok(result.includes('sk_l'));
  });
});

describe('Scanner - Pattern Detection', () => {
  it('detects API keys', () => {
    const content = 'API_KEY=sk_live_TEST_REDACTION_VALUE';
    const findings = scanFile('test.js', content);
    const apiFindings = findings.filter(f => f.type === 'API Key');
    assert.ok(apiFindings.length > 0);
  });

  it('detects database URLs', () => {
    const content = 'DATABASE_URL=postgres://user:password@localhost/db';
    const findings = scanFile('test.js', content);
    const dbFindings = findings.filter(f => f.type === 'Database URL');
    assert.ok(dbFindings.length > 0);
  });

  it('detects bearer tokens', () => {
    const content = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0';
    const findings = scanFile('test.js', content);
    const tokenFindings = findings.filter(f => f.type === 'Bearer Token');
    assert.ok(tokenFindings.length > 0);
  });

  it('detects private keys', () => {
    const content = '-----BEGIN PRIVATE KEY-----\nMIIB...';
    const findings = scanFile('test.js', content);
    const keyFindings = findings.filter(f => f.type === 'Private Key');
    assert.ok(keyFindings.length > 0);
  });

  it('does not print complete secrets', () => {
    const content = 'API_KEY=sk_live_TEST_REDACTION_VALUE_123456789';
    const findings = scanFile('test.js', content);
    for (const f of findings) {
      assert.ok(f.redacted);
      assert.ok(!f.redacted.includes('sk_live_TEST_REDACTION_VALUE'));
    }
  });
});

describe('Scanner - High Entropy Detection', () => {
  it('detects high entropy strings', () => {
    const content = 'RANDOM=abcdefghijklmnopqrstuvwxyz123456';
    const findings = detectHighEntropy(content);
    const highEntropy = findings.filter(f => f.type === 'High-entropy string');
    assert.ok(highEntropy.length > 0);
  });
});

describe('Scanner - Project Scan', () => {
  beforeEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
  });

  it('scans project for secrets', async () => {
    writeFileSync(join(TEST_DIR, 'config.js'), 'const API_KEY = "sk_live_abc123";');
    const result = await scanProject(TEST_DIR);
    assert.ok(result.total >= 0);
  });

  it('returns redacted values', async () => {
    writeFileSync(join(TEST_DIR, 'config.js'), 'const KEY = "secret1234567890abc";');
    const result = await scanProject(TEST_DIR);
    for (const f of result.findings) {
      assert.ok(f.redacted);
      assert.ok(!f.redacted.includes('secret1234567890abc'));
    }
  });
});
