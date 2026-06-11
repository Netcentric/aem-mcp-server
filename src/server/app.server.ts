import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { handleRequest } from '../mcp/mcp.server-handler.js';
// import { useBasicAuth } from './app.auth.js';
import { AEMConnector } from '../aem/aem.connector.js';
import { config } from '../config.js';
import { CliParams } from '../types.js';
import { LOGGER } from '../utils/logger.js';

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
  const { mcpPort = 8502 } = params || {};
  const app = createServer(params);
  app.listen(mcpPort, (error) => {
    if (error) {
      LOGGER.error('Failed to start server:', error);
      process.exit(1);
    }
    LOGGER.log(`0. AEM MCP Server listening on port ${mcpPort}`);
  });
};

process.on('SIGINT', async () => {
  LOGGER.log('Shutting down server...');
  process.exit(0);
});
