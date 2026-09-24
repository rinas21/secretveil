import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const KNOWN_PATTERNS = [
  { name: 'API Key', regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.:]{16,})/gi, severity: 'HIGH' },
  { name: 'AWS Secret Key', regex: /aws_secret_access_key\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{20,})/gi, severity: 'HIGH' },
  { name: 'AWS Access Key', regex: /aws_access_key_id\s*[:=]\s*['"]?(AKIA[0-9A-Z]{16})/gi, severity: 'HIGH' },
  { name: 'Database URL', regex: /(?:postgres|mysql|mongodb|redis):\/\/[^\s:]+:[^\s@]+@/gi, severity: 'HIGH' },
  { name: 'Bearer Token', regex: /bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi, severity: 'HIGH' },
  { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gi, severity: 'HIGH' },
  { name: 'JWT', regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi, severity: 'HIGH' },
  { name: 'Password', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{4,})/gi, severity: 'HIGH' },
  { name: 'GitHub Token', regex: /github[_-]?token\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})/gi, severity: 'HIGH' },
  { name: 'Stripe Key', regex: /sk_(?:live|test)_[a-zA-Z0-9]{16,}/gi, severity: 'HIGH' },
  { name: 'Slack Token', regex: /xox[bps]-[a-zA-Z0-9-]{10,}/gi, severity: 'HIGH' },
  { name: 'Generic Secret', regex: /secret[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.:]{16,})/gi, severity: 'MEDIUM' },
];

const HIGH_ENTROPY_THRESHOLD = 4.0;

export function redactSecret(value, visibleChars = 4) {
  if (!value || value.length <= visibleChars * 2) {
    return '[REDACTED]';
  }
  return value.substring(0, visibleChars) + '[REDACTED]' + value.substring(value.length - visibleChars);
}

export function scanFile(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of KNOWN_PATTERNS) {
      const matches = [...line.matchAll(pattern.regex)];
      for (const match of matches) {
        const fullMatch = match[0];
        const capturedValue = match[1] || fullMatch;
        findings.push({
          file: filePath,
          line: i + 1,
          severity: pattern.severity,
          type: pattern.name,
          raw: fullMatch,
          redacted: redactSecret(capturedValue)
        });
      }
    }
  }

  return findings;
}

export function detectHighEntropy(content) {
  const findings = [];
  const words = content.split(/[\s,"'`;{}()\[\]]+/);
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const tokens = line.split(/[\s=]+/);
    for (const token of tokens) {
      const trimmed = token.trim().replace(/['"]/g, '');
      if (trimmed.length >= 20 && trimmed.length <= 200) {
        const entropy = calculateShannonEntropy(trimmed);
        if (entropy > HIGH_ENTROPY_THRESHOLD && !looksLikeCommonString(trimmed)) {
          findings.push({
            file: '',
            line: i + 1,
            severity: 'MEDIUM',
            type: 'High-entropy string',
            raw: trimmed,
            redacted: redactSecret(trimmed),
            entropy: entropy.toFixed(2)
          });
        }
      }
    }
  }

  return findings;
}

function calculateShannonEntropy(str) {
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

function looksLikeCommonString(str) {
  const commonPatterns = [/^[a-z]+$/, /^[A-Z]+$/, /^[a-z]+\.com$/, /^[a-z]+\.org$/, /^[a-z]+\.net$/];
  return commonPatterns.some(p => p.test(str));
}

export async function scanProject(projectDir, options = {}) {
  const { staged = false, json = false } = options;
  const findings = [];

  const extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.java', '.c', '.cpp', '.h', '.sh', '.bash', '.zsh', '.yml', '.yaml', '.json', '.toml', '.xml', '.ini', '.cfg', '.conf', '.env', '.env.example', '.env.local', '.dockerignore', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.github', '.gitlab-ci.yml', '.gitlab-ci.yaml', '.gitconfig', '.npmrc', '.ssh', '.pem', '.key', '.cert', '.p12', '.pfx', '.txt', '.md', '.log', '.csv'];
  const skipDirs = ['node_modules', '.git', '.secretveil', 'dist', 'build', '.cache', 'vendor'];

  function shouldSkip(path) {
    const parts = path.split(/[\\/]/);
    return skipDirs.some(dir => parts.includes(dir));
  }

  function scanDir(dir) {
    if (!existsSync(dir) || shouldSkip(dir)) return;
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      if (shouldSkip(fullPath)) continue;
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          scanDir(fullPath);
        } else if (stat.isFile()) {
          const ext = entry.split('.').pop();
          const fullExt = '.' + ext;
          if (extensions.some(e => e === fullExt || fullPath === e || entry === e)) {
            try {
              const content = readFileSync(fullPath, 'utf8');
              const fileFindings = scanFile(fullPath, content);
              findings.push(...fileFindings);
              const entropyFindings = detectHighEntropy(content);
              for (const f of entropyFindings) {
                f.file = fullPath;
              }
              findings.push(...entropyFindings);
            } catch (_) {
              // Skip files that can't be read
            }
          }
        }
      } catch (_) {
        // Skip inaccessible files
      }
    }
  }

  scanDir(projectDir);

  const uniqueFindings = [];
  const seen = new Set();
  for (const f of findings) {
    const key = `${f.file}:${f.line}:${f.type}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueFindings.push(f);
    }
  }

  return { findings: uniqueFindings, total: uniqueFindings.length };
}

export async function scan(args) {
  const projectDir = process.cwd();
  const result = await scanProject(projectDir);
  console.log('SecretVeil Scan');
  console.log('');
  console.log('Scanning project...');
  console.log('');
  if (result.findings.length === 0) {
    console.log('No potential secrets detected.');
  } else {
    for (const f of result.findings) {
      const severity = f.severity || 'MEDIUM';
      console.log(`${severity}   ${f.file}:${f.line}`);
      console.log(`       Possible ${f.type}`);
      console.log(`       Redacted: ${f.redacted}`);
    }
    console.log('');
    console.log(`${result.total} findings`);
  }
  return result;
}
