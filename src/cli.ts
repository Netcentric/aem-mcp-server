#!/usr/bin/env node

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { startServer, startStdioServer } from './index.js';
import { CliParams } from './types';
import { hasUrlCredentials } from './utils/sanitize.js';
import { CertParamsSchema } from './aem/aem.auth.schemas.js';

type CliArgs = CliParams & {
  help?: boolean;
};

const argv: CliArgs = yargs(hideBin(process.argv)).options({
  host: { type: 'string', default: 'http://localhost:4502', alias: 'H' },
  user: { type: 'string', default: 'admin', alias: 'u' },
  pass: { type: 'string', default: 'admin', alias: 'p' },
  id: { type: 'string', default: '', alias: 'i', describe: 'clientId' },
  secret: { type: 'string', default: '', alias: 's', describe: 'clientSecret' },
  cert: {
    type: 'string',
    alias: 'C',
    describe: 'path to client certificate PEM file for mTLS to AEM. Env: AEM_CERT_PATH.',
  },
  key: {
    type: 'string',
    alias: 'k',
    describe: 'path to private key PEM file for mTLS to AEM. Env: AEM_KEY_PATH.',
  },
  ca: {
    type: 'string',
    describe: 'path to CA bundle PEM file (only needed for self-signed AEM tenants). Env: AEM_CA_PATH.',
  },
  'cert-watch-interval-min': {
    type: 'number',
    default: Number(process.env.AEM_CERT_WATCH_INTERVAL_MIN) || 0,
    describe: 'periodically check the cert file mtime every N minutes; on change, reload PEMs and rebuild the undici.Agent (rotation without restart). 0 disables (default). SIGHUP still works regardless. Env: AEM_CERT_WATCH_INTERVAL_MIN.',
  },
  stdio: {
    type: 'boolean',
    default: false,
    alias: 'e',
    describe: 'run as a stdio MCP subprocess (JSON-RPC over stdin/stdout) instead of the HTTP server. Mutually exclusive with the HTTP mode — no port is bound. For Claude Desktop / Cursor / VS Code.',
  },
  mcpPort: { type: 'number', default: 8502, alias: 'm' },
  bind: {
    type: 'string',
    default: process.env.MCP_BIND || '127.0.0.1',
    describe: 'host interface to bind (default 127.0.0.1, loopback-only). Use 0.0.0.0 to expose on the LAN. Env: MCP_BIND.',
  },
  'shutdown-drain-seconds': {
    type: 'number',
    default: Number(process.env.MCP_SHUTDOWN_DRAIN_SECONDS) || 60,
    describe: 'max seconds to wait for in-flight requests to finish on SIGINT/SIGTERM before forcing exit. Default 60s — must outlast worst-case bulk tool calls (see docs/BULK_OPERATIONS.md). Env: MCP_SHUTDOWN_DRAIN_SECONDS.',
  },
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

const { host, user, pass, mcpPort, id, secret, bind, stdio } = argv;
const allowOrigin = argv.allowOrigin ?? [];
const shutdownDrainSeconds = argv.shutdownDrainSeconds ?? 60;

if (host && hasUrlCredentials(host)) {
  console.error('Error: --host (-H) must not contain embedded credentials. Pass them via -u/-p (Basic) or -i/-s (OAuth) instead.');
  process.exit(1);
}

// Cert-auth params. Flags take precedence over env vars; `??` only falls
// through on null/undefined so an empty `--cert ""` reaches the schema and
// gets rejected by `.min(1)` (instead of being silently coerced to "no cert
// provided"). `passphrase` is env-only — no CLI flag — to keep the secret
// out of `ps aux`.
const certInput = {
  cert: argv.cert ?? process.env.AEM_CERT_PATH ?? undefined,
  key: argv.key ?? process.env.AEM_KEY_PATH ?? undefined,
  ca: argv.ca ?? process.env.AEM_CA_PATH ?? undefined,
  passphrase: process.env.AEM_KEY_PASSPHRASE || undefined,
};

const certValidation = CertParamsSchema.safeParse(certInput);
if (!certValidation.success) {
  // One-line sanitized error. NEVER echo `issue.received` — a malformed
  // passphrase value would leak into stderr / CI logs.
  const issue = certValidation.error.issues[0];
  const pathSeg = issue?.path?.[0];
  const label = typeof pathSeg === 'string' && pathSeg.length > 0 ? `--${pathSeg}` : 'cert-auth';
  console.error(`Error: ${label}: ${issue?.message ?? 'validation failed'}`);
  process.exit(1);
}

const { cert, key, ca, passphrase } = certValidation.data;

const certWatchIntervalMin = argv.certWatchIntervalMin ?? 0;

const params = {
  host,
  user,
  pass,
  mcpPort,
  id,
  secret,
  cert,
  key,
  ca,
  passphrase,
  certWatchIntervalMin,
  allowOrigin,
  bind,
  shutdownDrainSeconds,
  stdio,
};

// Strict XOR: stdio mode and the HTTP server are mutually exclusive. Running
// both would leave an unauthenticated HTTP endpoint bound on mcpPort alongside
// the stdio subprocess — double the attack surface. In stdio mode no port is
// ever bound.
if (stdio) {
  startStdioServer(params).catch((err) => {
    process.stderr.write(`[stdio] fatal: ${err?.message ?? err}\n`);
    process.exit(1);
  });
} else {
  startServer(params);
}
