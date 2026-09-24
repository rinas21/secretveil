import { parseArgs } from 'node:util';
import { init } from './commands/init.js';
import { status } from './commands/status.js';
import { unlock } from './commands/unlock.js';
import { lock } from './commands/lock.js';
import { run } from './commands/run.js';
import { scan } from './commands/scan.js';
import { doctor } from './commands/doctor.js';
import { profile } from './commands/profile.js';
import { policy } from './commands/policy.js';
import { rotate } from './commands/rotate.js';
import { audit } from './commands/audit.js';
import { aiCheck } from './commands/ai-check.js';
import { benchmark } from './commands/benchmark.js';
import { gitCheck } from './commands/git-check.js';
import { docker } from './commands/docker.js';
import { recover } from './commands/recover.js';
import { password } from './commands/password.js';
import { recovery } from './commands/recovery.js';
import { migrate } from './commands/migrate.js';
import { credential } from './commands/credential.js';
import { decrypt } from './commands/decrypt.js';
import { encrypt } from './commands/encrypt.js';

const commands = { init, status, unlock, lock, run, scan, doctor, profile, policy, rotate, audit, 'ai-check': aiCheck, benchmark, 'git-check': gitCheck, docker, recover, password, recovery, migrate, credential, decrypt, encrypt };

export async function cli() {
  const args = parseArgs({
    options: {
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
      json: { type: 'boolean', short: 'j' },
      staged: { type: 'boolean', short: 's' },
      baseline: { type: 'boolean' },
      protected: { type: 'boolean' },
      generate: { type: 'boolean', short: 'g' },
      profile: { type: 'string', short: 'p' },
      policy: { type: 'string' }
    },
    strict: false,
    allowPositionals: true
  });

  if (args.values.help) {
    printHelp();
    return;
  }

  if (args.values.version) {
    try {
      const pkg = await import('../package.json', { assert: { type: 'json' } });
      console.log(`secretveil v${pkg.default.version}`);
    } catch (_) {
      console.log('secretveil v1.0.0');
    }
    return;
  }

  const commandName = args.positionals[0];
  const commandArgs = args.positionals.slice(1);

  const command = commands[commandName];
  if (!command) {
    console.error('Unknown command:', commandName);
    console.error('Run "secretveil --help" for usage information.');
    process.exit(1);
  }

  try {
    await command(commandArgs);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
SecretVeil - Protect application secrets from workspace exposure

Usage:
  secretveil <command> [options]

Commands:
  init              Initialize SecretVeil in the current project
  status            Show security status
  unlock            Unlock the encrypted secret store
  lock              Lock the secret store and invalidate session
  run <cmd>         Run a command with decrypted secrets injected
  decrypt           Restore decrypted secrets into .env (writes plaintext)
  encrypt           Encrypt plaintext secrets in .env
  recover           Recover from forgotten password using recovery key
  password          Change the SecretVeil password
  recovery          Manage recovery key (regenerate)
  migrate           Migrate a version 1 store to version 2
  credential        Manage stored unlock credentials (status, remove)
  scan              Scan for exposed secrets
  doctor            Diagnose SecretVeil configuration
  profile           Manage environment profiles
  policy            Manage secret policies
  rotate            Rotate secrets
  audit             View security events
  benchmark         Run exposure benchmark
  ai-check          Analyze AI-agent exposure risks
  git-check         Check Git exposure
  docker            Docker integration

Options:
  --help, -h        Show this help message
  --version, -v     Show version
  --json, -j        Output machine-readable JSON
  --baseline        Run benchmark in baseline mode
  --protected       Run benchmark in protected mode
  --generate, -g    Generate random secret value
  --profile, -p     Specify environment profile
  --policy          Specify secret policy
`);
}
