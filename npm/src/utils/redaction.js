export class Redactor {
  constructor() {
    this.secretPatterns = [];
  }

  addPattern(pattern) {
    this.secretPatterns.push(pattern);
  }

  redact(output, secrets) {
    if (!output || !secrets) return output;
    let result = output;
    for (const secret of secrets) {
      if (secret && secret.value) {
        const regex = new RegExp(secret.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        result = result.replace(regex, '[REDACTED]');
      }
    }
    for (const pattern of this.secretPatterns) {
      const regex = new RegExp(pattern.regex, 'g');
      result = result.replace(regex, pattern.replacement || '[REDACTED]');
    }
    return result;
  }

  redactStream(output, secrets) {
    const lines = output.split('\n');
    const redacted = [];
    for (const line of lines) {
      redacted.push(this.redact(line, secrets));
    }
    return redacted.join('\n');
  }

  static defaultRedaction(secretValue) {
    if (!secretValue || secretValue.length <= 8) return '[REDACTED]';
    return secretValue.substring(0, 4) + '[REDACTED]' + secretValue.substring(secretValue.length - 4);
  }
}

export function createDefaultRedactor() {
  const redactor = new Redactor();
  redactor.addPattern({ regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9_\-\.:]{8,}/gi, replacement: '$1=[REDACTED]' });
  redactor.addPattern({ regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}/gi, replacement: '$1=[REDACTED]' });
  return redactor;
}
