#!/usr/bin/env node

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { startServer } from './index.js';
import { CliParams } from './types';
import { hasUrlCredentials } from './utils/sanitize.js';

type CliArgs = CliParams & {
  help?: boolean;
};

const argv: CliArgs = yargs(hideBin(process.argv)).options({
  host: { type: 'string', default: 'http://localhost:4502', alias: 'H' },
  user: { type: 'string', default: 'admin', alias: 'u' },
  pass: { type: 'string', default: 'admin', alias: 'p' },
  id: { type: 'string', default: '', alias: 'i', describe: 'clientId' },
  secret: { type: 'string', default: '', alias: 's', describe: 'clientSecret' },
  mcpPort: { type: 'number', default: 8502, alias: 'm' },
  'allow-origin': {
    type: 'string',
    array: true,
    default: [],
    describe: 'extra Origin header value to allow on /mcp (repeatable). Inspector ports 6274/6277 on localhost+127.0.0.1 are always allowed. Comma-separated env: MCP_ALLOWED_ORIGINS.',
  },
})
  .help()
  .alias('h', 'help')
  .parseSync();

if (argv.help) {
  process.exit(0); // prevent startServer from running
}

const { host, user, pass, mcpPort, id, secret } = argv;
const allowOrigin = argv.allowOrigin ?? [];

if (host && hasUrlCredentials(host)) {
  console.error('Error: --host (-H) must not contain embedded credentials. Pass them via -u/-p (Basic) or -i/-s (OAuth) instead.');
  process.exit(1);
}

startServer({ host, user, pass, mcpPort, id, secret, allowOrigin });
