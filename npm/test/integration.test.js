import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const TEST_DIR = '/tmp/opencode/secretveil-integration-test';

describe('Integration Tests', () => {
  let origLog;

  beforeEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    mkdirSync(TEST_DIR, { recursive: true });
    origLog = console.log;
  });

  afterEach(() => {
    try { rmSync(TEST_DIR, { recursive: true, force: true }); } catch (_) {}
    console.log = origLog;
  });

  async function captureLogs(fn) {
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));
    await fn();
    console.log = origLog;
    return logs.join('\n');
  }

  it('policy integration works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { policy } = await import('../src/commands/policy.js');
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const output = await captureLogs(() => policy(['list']));
    assert.ok(output.includes('Policies') || output.includes('policy') || output.includes('defined'));
  });

  it('profile integration works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { profile } = await import('../src/commands/profile.js');
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const output = await captureLogs(() => profile(['list']));
    assert.ok(output.includes('Profiles') || output.includes('profiles'));
  });

  it('audit integration works', async () => {
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

  it('benchmark integration works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { benchmark } = await import('../src/commands/benchmark.js');
    const output = await captureLogs(() => benchmark(['--protected']));
    assert.ok(output.includes('Benchmark'));
  });

  it('ai-check integration works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { aiCheck } = await import('../src/commands/ai-check.js');
    const output = await captureLogs(() => aiCheck([]));
    assert.ok(output.includes('AI Check'));
  });

  it('docker integration works', async () => {
    writeFileSync(join(TEST_DIR, '.env'), 'API_KEY=SBX_API_7F31A92C\n');
    process.chdir(TEST_DIR);
    const { createStore } = await import('../src/secrets/store.js');
    const config = { version: 1, algorithm: 'aes-256-gcm', kdf: 'argon2id', salt: 'abc', secretKeys: ['API_KEY'] };
    createStore(TEST_DIR, config, { version: 1, secrets: {} });
    const { docker } = await import('../src/commands/docker.js');
    const output = await captureLogs(() => docker([]));
    assert.ok(output.includes('Docker'));
  });
});
