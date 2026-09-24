import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { parseEnvString } from '../src/secrets/parser.js';

describe('.env Parser', () => {
  it('parses simple KEY=value', () => {
    const result = parseEnvString('KEY=value');
    assert.strictEqual(result.KEY, 'value');
  });

  it('parses quoted double-quote values', () => {
    const result = parseEnvString('KEY="hello world"');
    assert.strictEqual(result.KEY, 'hello world');
  });

  it('parses quoted single-quote values', () => {
    const result = parseEnvString("KEY='hello world'");
    assert.strictEqual(result.KEY, 'hello world');
  });

  it('parses comments', () => {
    const content = '# this is a comment\nKEY=value';
    const result = parseEnvString(content);
    assert.strictEqual(result.KEY, 'value');
    assert.strictEqual(Object.keys(result).length, 1);
  });

  it('parses empty values', () => {
    const result = parseEnvString('KEY=');
    assert.strictEqual(result.KEY, '');
  });

  it('parses special characters', () => {
    const result = parseEnvString('KEY=hello@world.com/path?q=1');
    assert.strictEqual(result.KEY, 'hello@world.com/path?q=1');
  });

  it('parses unicode values', () => {
    const result = parseEnvString('KEY=日本語テスト');
    assert.strictEqual(result.KEY, '日本語テスト');
  });

  it('parses whitespace around values', () => {
    const result = parseEnvString('KEY = value ');
    assert.strictEqual(result.KEY, 'value');
  });

  it('parses multiple variables', () => {
    const content = 'API_KEY=abc\nDB_PASSWORD=secret\nPORT=3000';
    const result = parseEnvString(content);
    assert.strictEqual(result.API_KEY, 'abc');
    assert.strictEqual(result.DB_PASSWORD, 'secret');
    assert.strictEqual(result.PORT, '3000');
  });

  it('handles malformed input gracefully', () => {
    const result = parseEnvString('not a valid line\nKEY=value');
    assert.strictEqual(result.KEY, 'value');
  });

  it('skips blank lines', () => {
    const content = '\n\nKEY=value\n\n';
    const result = parseEnvString(content);
    assert.strictEqual(result.KEY, 'value');
    assert.strictEqual(Object.keys(result).length, 1);
  });
});
