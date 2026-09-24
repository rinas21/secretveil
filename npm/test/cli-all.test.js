import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const TEST_DIR = '/tmp/opencode/secretveil-alltest';
let _home, _savedHome, _savedProfile;

describe('CLI - All Commands (Module)', () => {
  let origLog;

  beforeEach(() => {
    _savedHome = process.env.HOME; _savedProfile = process.env.USERPROFILE;
    _home = mkdtempSync(join(tmpdir(), 'sv-all-home-'));
    process.env.HOME = _home; process.env.USERPROFILE = _home;
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    origLog = console.log;
  });

  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    process.env.HOME = _savedHome; process.env.USERPROFILE = _savedProfile;
    try { rmSync(_home, { recursive: true, force: true }); } catch (_) {}
    console.log = origLog;
  });

  async function captureLogs(fn) {
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    await fn();
    console.log = origLog;
    return logs.join('\n');
  }

  it('scan module works', async () => {
    const { scanProject } = await import('../src/commands/scan.js');
    const result = await scanProject(TEST_DIR);
    assert.ok(result !== undefined);
  });

  it('doctor module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\nPORT=3000\n');
    process.chdir(TEST_DIR);
    const { doctor } = await import('../src/commands/doctor.js');
    const output = await captureLogs(() => doctor([]));
    assert.ok(output.includes('Doctor'));
  });

  it('profile module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { profile } = await import('../src/commands/profile.js');
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const output = await captureLogs(() => profile(['list']));
    assert.ok(output.includes('Profiles') || output.includes('profiles') || output.includes('No profiles'));
  });

  it('policy module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { policy } = await import('../src/commands/policy.js');
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const output = await captureLogs(() => policy(['list']));
    assert.ok(output.includes('Policies') || output.includes('policy') || output.includes('No policies'));
  });

  it('audit module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { audit, addAuditEntry } = await import('../src/commands/audit.js');
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    await addAuditEntry(TEST_DIR, { action: 'TEST' });
    const output = await captureLogs(() => audit([]));
    assert.ok(output.includes('Audit'));
  });

  it('ai-check module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { aiCheck } = await import('../src/commands/ai-check.js');
    const output = await captureLogs(() => aiCheck([]));
    assert.ok(output.includes('AI Check'));
  });

  it('benchmark module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { benchmark } = await import('../src/commands/benchmark.js');
    const output = await captureLogs(() => benchmark(['--protected']));
    assert.ok(output.includes('Benchmark'));
  });

  it('git-check module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { gitCheck } = await import('../src/commands/git-check.js');
    const output = await captureLogs(() => gitCheck([]));
    assert.ok(output.includes('Git Check'));
  });

  it('docker module works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { docker } = await import('../src/commands/docker.js');
    const output = await captureLogs(() => docker([]));
    assert.ok(output.includes('Docker'));
  });

  it('scan detects API keys', async () => {
    const { scanFile } = await import('../src/commands/scan.js');
    const findings = scanFile('test.js', 'API_KEY=sk_live_abc123def456');
    const apiFindings = findings.filter(f => f.type === 'API Key');
    assert.ok(apiFindings.length > 0);
  });

  it('redaction works', async () => {
    const { redactSecret } = await import('../src/commands/scan.js');
    const result = redactSecret('sk_live_1234567890abcdef');
    assert.ok(result.includes('[REDACTED]'));
  });
});
