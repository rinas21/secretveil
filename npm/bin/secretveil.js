#!/usr/bin/env node
import { cli } from '../src/cli.js';
cli().catch(err => {
  process.exit(1);
});
