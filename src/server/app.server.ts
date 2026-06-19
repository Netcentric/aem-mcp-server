import fs from 'node:fs';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { handleRequest } from '../mcp/mcp.server-handler.js';
import { createMCPServer } from '../mcp/mcp.server.js';
// import { useBasicAuth } from './app.auth.js';
import { AEMConnector } from '../aem/aem.connector.js';
import { destroyAllCertStrategies, reloadAllCertStrategies } from '../aem/aem.auth.js';
import { config } from '../config.js';
import { CliParams } from '../types.js';
import { LOGGER } from '../utils/logger.js';
import { redactCliParams } from '../utils/sanitize.js';
import { transports } from '../mcp/mcp.transports.js';

// Cap on how long we wait for `destroyAllCertStrategies()` during shutdown
// (feat #6). The undici Agent's `destroy()` is normally near-instant — it
// just closes the keep-alive socket pool — but a stuck socket or hostile
// peer could otherwise hang the process past the drain deadline. 5s is plenty
// for real shutdowns and short enough to keep `kill -INT` responsive.
const CERT_DESTROY_TIMEOUT_MS = 5_000;

// MCP spec MUST: validate Origin header to prevent DNS-rebinding attacks.
// Defaults cover the official MCP Inspector (UI :6274, proxy :6277) on both
// loopback hostnames. Extra origins via --allow-origin CLI flag or comma-
// separated MCP_ALLOWED_ORIGINS env var. A loose regex like ^http://localhost(:\d+)?$
// is NOT used: it would permit any other process bound to a local port to spoof
// an Origin header and widen the rebinding attack surface.
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:6274',
  'http://127.0.0.1:6274',
  'http://localhost:6277',
  'http://127.0.0.1:6277',
];

function buildOriginAllowlist(extra: string[] = []): Set<string> {
  const fromEnv = (process.env.MCP_ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return new Set<string>([...DEFAULT_ALLOWED_ORIGINS, ...fromEnv, ...extra]);
}

const createServer = (params: CliParams = {}) => {
  const app = express();

  const allowedOrigins = buildOriginAllowlist(params.allowOrigin);

  // Gate before cors(): a disallowed Origin returns HTTP 403 with a JSON-RPC
  // -32600 (Invalid Request) body. Requests without an Origin header (CLI curl,
  // server-to-server tooling) pass through — only browsers attach Origin.
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (typeof origin === 'string' && !allowedOrigins.has(origin)) {
      res.status(403).json({
        jsonrpc: '2.0',
        error: { code: -32600, message: 'Origin not allowed' },
        id: null,
      });
      return;
    }
    next();
  });

  app.use(cors({
    origin: (origin, cb) => cb(null, !origin || allowedOrigins.has(origin)),
    exposedHeaders: ['Mcp-Session-Id'],
  }));
  app.use(express.json());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // useBasicAuth(app);
  const aemConnector = new AEMConnector(params);

  app.get('/health', async (req: Request, res: Response) => {
    try {
      const { aem, auth } = await aemConnector.testConnection();
      const result = {
        status: 'healthy',
        aem: aem ? 'connected' : 'disconnected',
        auth: auth ? 'authorized' : 'not authorized',
        mcp: 'ready',
        timestamp: new Date().toISOString(),
        version: config.APP_VERSION || '1.0.0',
      };
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ status: 'unhealthy', error: error.message, timestamp: new Date().toISOString() });
    }
  });

  app.post('/mcp', async (req: Request, res: Response) => {
    await handleRequest(req, res, params);
  });

  app.get('/mcp', async (req: Request, res: Response) => {
    res.status(405).set('Allow', 'POST').send('Method Not Allowed');
  });

  app.delete('/mcp', async (req: Request, res: Response) => {
    LOGGER.log('Received DELETE MCP request');
    res.writeHead(405).end(JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    }));
  });


  app.get('/', (req: Request, res: Response) => {
    res.json({
      name: 'AEM MCP Gateway Server',
      description: 'A Model Context Protocol server for Adobe Experience Manager',
      version: config.APP_VERSION || '1.0.0',
      endpoints: {
        health: { method: 'GET', path: '/health', description: 'Health check for all services' },
        mcp: { method: 'POST', path: '/mcp', description: 'JSON-RPC endpoint for MCP calls' },
        mcpMethods: { method: 'GET', path: '/mcp/methods', description: 'List all available MCP methods' },
      },
      architecture: 'MCP integration',
      timestamp: new Date().toISOString(),
    });
  });

  return app;
}

export const startServer = (params: CliParams = {}) => {
  // Default to loopback (127.0.0.1): without an explicit bind argument Express
  // listens on 0.0.0.0, exposing /mcp to anyone on the same LAN (cafe WiFi,
  // office, hotel) who can then drive every tool with whatever AEM credentials
  // the server was launched with. Pass --bind 0.0.0.0 (or MCP_BIND=0.0.0.0)
  // to opt back into all-interfaces explicitly.
  const { mcpPort = 8502, bind = '127.0.0.1', shutdownDrainSeconds = 60 } = params || {};
  const app = createServer(params);
  const server = app.listen(mcpPort, bind, (error?: Error) => {
    if (error) {
      LOGGER.error('Failed to start server:', error);
      process.exit(1);
    }
    LOGGER.log(`0. AEM MCP Server listening on ${bind}:${mcpPort}`);
  });

  // Graceful drain on SIGINT/SIGTERM. The prior handler called process.exit(0)
  // unconditionally, which dropped in-flight tool calls mid-flight — including
  // multi-minute bulk operations (bulkUpdateComponents, bulkConvertComponents,
  // see docs/BULK_OPERATIONS.md) where half-applied AEM mutations are worse
  // than either a clean success or a clean rollback.
  //
  // Drain sequence (logs to stderr at each step — LOGGER is a no-op without
  // MCP_LOGGER, but shutdown diagnostics must always be visible):
  //   1. server.close()  -> stop accepting new connections
  //   2. closeIdleConnections() -> drop keep-alive sockets between requests
  //      so server.close()'s callback can fire without waiting for them
  //   3. transports[].close() -> tear down MCP sessions
  //   4. wait up to shutdownDrainSeconds for in-flight requests
  //   5. process.exit(0)
  let shuttingDown = false;
  const drain = (signal: NodeJS.Signals) => {
    if (shuttingDown) return;
    shuttingDown = true;
    const startedAt = Date.now();
    process.stderr.write(
      `[shutdown] ${signal} received — starting drain (max ${shutdownDrainSeconds}s)\n`
    );

    const forceExit = setTimeout(() => {
      const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
      process.stderr.write(
        `[shutdown] drain deadline reached after ${elapsed}s — abandoning pending requests, exiting 1\n`
      );
      // Exit non-zero so orchestrators (Kubernetes, systemd) can distinguish a
      // forced timeout from a clean drain. A "0" here would tell the
      // orchestrator everything was fine and suppress alerts even when a
      // slow/stuck handler (or a hostile keep-open) prevented the drain from
      // completing.
      process.exit(1);
    }, shutdownDrainSeconds * 1000);
    // Don't keep the event loop alive solely for this timer — once server.close
    // resolves and the process is otherwise idle, exit cleanly.
    forceExit.unref();

    server.close(async (err) => {
      clearTimeout(forceExit);
      const elapsed = ((Date.now() - startedAt) / 1000).toFixed(2);
      if (err) {
        process.stderr.write(`[shutdown] server.close error: ${err.message}\n`);
      }
      // Cert-mode hook (feat #6): release any cached undici.Agent keep-alive
      // socket pools so they don't linger past process.exit. No-op when the
      // active strategies are Basic/OAuth (registry empty → count 0). Bounded
      // by CERT_DESTROY_TIMEOUT_MS so a stuck Agent can't hang the process.
      try {
        const destroyed = await Promise.race<number>([
          destroyAllCertStrategies(),
          new Promise<number>((_, reject) =>
            setTimeout(
              () => reject(new Error(`cert destroy timeout (${CERT_DESTROY_TIMEOUT_MS}ms)`)),
              CERT_DESTROY_TIMEOUT_MS
            )
          ),
        ]);
        if (destroyed > 0) {
          process.stderr.write(
            `[shutdown] destroyed ${destroyed} cert-auth agent pool(s)\n`
          );
        }
      } catch (e: any) {
        process.stderr.write(
          `[shutdown] cert-auth destroy error: ${e?.message ?? e}\n`
        );
      }
      process.stderr.write(`[shutdown] drain complete in ${elapsed}s — exit 0\n`);
      process.exit(0);
    });

    // Drop keep-alive sockets between requests so the close() callback can
    // resolve once active requests finish. Without this, idle keep-alives
    // hold the server open until the OS times them out.
    if (typeof server.closeIdleConnections === 'function') {
      server.closeIdleConnections();
    }

    // Tear down MCP transports. Each transport may have open SSE streams or
    // session state that needs explicit cleanup.
    for (const [sessionId, transport] of Object.entries(transports)) {
      try {
        process.stderr.write(`[shutdown] closing transport ${sessionId}\n`);
        transport.close();
      } catch (e: any) {
        process.stderr.write(
          `[shutdown] error closing transport ${sessionId}: ${e?.message ?? e}\n`
        );
      }
    }
  };

  process.on('SIGINT', () => drain('SIGINT'));
  process.on('SIGTERM', () => drain('SIGTERM'));

  // Cert rotation hook (feat #7). SIGHUP triggers a reload of every live
  // CertAuthStrategy: re-read PEMs, atomic Agent swap, 30s drain on the old
  // Agent. Stderr-only (unconditional) so SREs see the transition without
  // needing MCP_LOGGER. No-op when no cert-mode strategy is active.
  const doReloadCerts = async () => {
    try {
      const { reloaded, errors } = await reloadAllCertStrategies();
      if (reloaded === 0 && errors.length === 0) {
        process.stderr.write('[cert-reload] no cert-auth strategies live; nothing to reload\n');
      } else if (reloaded > 0) {
        process.stderr.write(`[cert-reload] reloaded ${reloaded} cert-auth strategy(ies)\n`);
      }
      for (const err of errors) {
        process.stderr.write(`[cert-reload] error: ${err}\n`);
      }
    } catch (e: any) {
      process.stderr.write(`[cert-reload] fatal error: ${e?.message ?? e}\n`);
    }
  };
  const onSighup = async () => {
    if (shuttingDown) return;
    process.stderr.write('[cert-reload] SIGHUP received — reloading cert-auth strategies\n');
    await doReloadCerts();
  };
  process.on('SIGHUP', () => { void onSighup(); });

  // Optional mtime polling. When --cert-watch-interval-min N is non-zero AND
  // a cert path was supplied, poll cert mtime every N minutes; on change,
  // trigger the same reload flow as SIGHUP. setInterval.unref() so the timer
  // alone doesn't keep the process alive on shutdown.
  const watchMinutes = params?.certWatchIntervalMin ?? 0;
  const certPath = params?.cert;
  if (watchMinutes > 0 && !certPath) {
    process.stderr.write(
      '[cert-watch] certWatchIntervalMin is set but no cert path was supplied — watcher disabled\n'
    );
  }
  if (watchMinutes > 0 && certPath) {
    let lastMtimeMs: number | undefined;
    try {
      lastMtimeMs = fs.statSync(certPath).mtimeMs;
    } catch {
      // The cert path was already validated by CertAuthStrategy.init() at
      // boot; a stat failure here is unusual. Log and skip the watcher
      // rather than returning early — fatal-error fallbacks below must still
      // be registered regardless of watcher setup.
      process.stderr.write(`[cert-watch] cannot stat cert path at boot — watcher disabled\n`);
    }
    if (lastMtimeMs !== undefined) {
      const intervalMs = watchMinutes * 60_000;
      process.stderr.write(
        `[cert-watch] watching cert mtime every ${watchMinutes} minute(s)\n`
      );
      const watchTimer = setInterval(async () => {
        if (shuttingDown) return;
        let currentMtimeMs: number;
        try {
          currentMtimeMs = fs.statSync(certPath).mtimeMs;
        } catch (e: any) {
          process.stderr.write(`[cert-watch] stat error: ${e?.message ?? e}\n`);
          return;
        }
        if (currentMtimeMs !== lastMtimeMs) {
          process.stderr.write(
            `[cert-watch] cert mtime changed (was ${new Date(lastMtimeMs!).toISOString()}, ` +
            `now ${new Date(currentMtimeMs).toISOString()}) — reloading cert-auth strategies\n`
          );
          lastMtimeMs = currentMtimeMs;
          await doReloadCerts();
        }
      }, intervalMs);
      watchTimer.unref();
    }
  }

  // Fatal-error fallbacks. Node docs are explicit that the process is in an
  // undefined state after `uncaughtException` — we MUST NOT try to resume
  // normal work or run the full async drain. Do sync-only cleanup (close
  // transports, write a stderr breadcrumb) and exit non-zero so the
  // orchestrator restarts the container instead of leaving a half-dead pod.
  const fatal = (kind: string, err: unknown) => {
    if (shuttingDown) return;
    shuttingDown = true;
    const message =
      err instanceof Error ? err.stack || err.message : String(err);
    process.stderr.write(`[fatal] ${kind}: ${message}\n`);
    for (const transport of Object.values(transports)) {
      try {
        transport.close();
      } catch {
        // best-effort sync cleanup; process state is already suspect
      }
    }
    process.exit(1);
  };
  process.on('uncaughtException', (err) => fatal('uncaughtException', err));
  process.on('unhandledRejection', (reason) => fatal('unhandledRejection', reason));
};

/**
 * Stdio transport entry point (feat: stdio mode). The sibling of startServer():
 * it serves the SAME MCP tool surface over newline-delimited JSON-RPC on
 * stdin/stdout instead of HTTP. Used by Claude Desktop, Cursor, and VS Code,
 * which spawn the binary as a subprocess. No Express, no CORS, no Origin
 * allowlist, no session map, NO port bound — cli.ts dispatches this XOR
 * startServer(), never both.
 *
 * stdout is the JSON-RPC wire here, so it MUST stay byte-clean. Two layers of
 * protection are installed BEFORE the transport connects:
 *   1. LOGGER.useStderr() — our logger never writes to stdout.
 *   2. console.log/info/debug → stderr — backstops stray stdout writes from
 *      *dependencies*, the subtlest corruption vector. A single non-framed
 *      byte on stdout makes the client reject the frame and drop the link.
 */
export const startStdioServer = async (params: CliParams = {}) => {
  LOGGER.useStderr();
  const toStderr = console.error.bind(console);
  console.log = toStderr;
  console.info = toStderr;
  console.debug = toStderr;

  LOGGER.log('Starting stdio MCP server with CLI params:', redactCliParams(params));

  const server = createMCPServer(params);
  const transport = new StdioServerTransport();

  // Resolve when the connection closes OR when a signal requests shutdown.
  // Use the Server's public `onclose` callback rather than transport.onclose —
  // Protocol.connect() overwrites transport.onclose with its own internal
  // cleanup handler, but invokes server.onclose afterwards.
  // resolveClose! — the Promise executor runs synchronously so it is always
  // assigned before any async code can reference it.
  let resolveClose!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClose = resolve;
    server.onclose = resolve;
  });

  const shutdown = (signal: string) => {
    process.stderr.write(`[stdio] ${signal} received — closing\n`);
    destroyAllCertStrategies();
    resolveClose();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    process.stderr.write(`[stdio] uncaughtException: ${err.stack ?? err.message}\n`);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    const msg = reason instanceof Error ? reason.stack : String(reason);
    process.stderr.write(`[stdio] unhandledRejection: ${msg}\n`);
    process.exit(1);
  });

  await server.connect(transport);
  await closed;
};
