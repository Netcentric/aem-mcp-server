# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
npm run build         # build:types (tsc, .d.ts only) + build:ts (esbuild bundle to dist/)
npm run build:ts      # esbuild only — fastest iteration when types are unchanged
npm run build:types   # tsc --emitDeclarationOnly (also doubles as the typecheck)
npm start             # node dist/cli.js with MCP_LOGGER=true
npm run test:dev      # node ./dist/cli.js (no logger)
npm run test:npm      # pack + global install + smoke-run on port 5502
```

No test runner, linter, or formatter is configured. `npm run build:types` is the only available typecheck.

Single-process run with custom params (mirrors the `aem-mcp` bin):
```sh
node dist/cli.js -H=https://author.example.com -u=user -p=pass         # Basic auth
node dist/cli.js -H=https://author.example.com -i=<clientId> -s=<clientSecret>  # AEMaaCS OAuth S2S
MCP_USERNAME=foo MCP_PASSWORD=bar node dist/cli.js                     # gate /mcp with HTTP Basic
```

`MCP_LOGGER=true` enables logging. Without it, `LOGGER` is a no-op — this is intentional (stdout must stay clean for MCP stdio clients; see `src/utils/logger.ts`).

## Architecture

The server is a Model Context Protocol (MCP) gateway that translates JSON-RPC tool calls into AEM HTTP operations (Sling/QueryBuilder/JCR). Request flow:

```
MCP client ──HTTP POST /mcp──▶ Express (server/app.server.ts)
                              │
                              ▼
                         server-handler.ts ──per-session──▶ StreamableHTTPServerTransport
                              │                                       │
                              ▼                                       ▼
                         mcp.server.ts (MCP SDK Server)        transports map (mcp.transports.ts)
                              │ CallToolRequest
                              ▼
                         mcp.aem-handler.ts (switch on method name)
                              │
                              ▼
                         aem.connector.ts ──▶ aem.fetch.ts ──HTTP──▶ AEM
```

Key seams:

- **`src/cli.ts`** — yargs entry. Parses `--host/--user/--pass/--id/--secret/--mcpPort` into `CliParams` (see `src/types.ts`) and calls `startServer`.
- **`src/server/app.server.ts`** — Express app. Exposes `GET /` (info), `GET /health`, `POST /mcp`. `GET/DELETE /mcp` return 405. CORS is wide open (`origin: '*'`). Optional Basic auth middleware exists in `app.auth.ts` but is **currently commented out** at the `useBasicAuth(app)` line — re-enable by uncommenting both the import and call. The middleware only activates if both `MCP_USERNAME` and `MCP_PASSWORD` env vars are set.
- **`src/mcp/mcp.server-handler.ts`** — Per-request session routing. New `StreamableHTTPServerTransport` is created on `initialize`; subsequent requests reuse the transport by `mcp-session-id` header. A new `MCPRequestHandler` (and therefore a new `AEMConnector`) is constructed per session — there's no global AEM client.
- **`src/mcp/mcp.server.ts`** — Wires MCP SDK handlers: `ListTools` returns the static `tools` array; `CallTool` dispatches via `MCPRequestHandler.handleRequest`. Has special-case handling for `OAUTH_REQUIRED` errors that surface an `authUrl` back to the client.
- **`src/mcp/mcp.tools.ts`** — The single source of truth for the MCP tool surface (~46 tools, JSON-Schema input definitions). When adding a tool you must update **both** this file (schema) and `mcp.aem-handler.ts` (the switch statement that routes `method` → `AEMConnector.xxx`). They are not auto-derived from each other.
- **`src/aem/aem.connector.ts`** — The big file (~3700 lines). All AEM domain logic — pages, components, assets, workflows, replication, search. Every public method wraps its body in `safeExecute` (from `aem.errors.ts`) and returns either `createSuccessResponse(...)` or throws an `AEMOperationError` with a code from `AEM_ERROR_CODES`. Path inputs are validated against `isValidContentPath` (must start with `/content`, `/content/dam`, `/conf`, or `/content/experience-fragments` — see `aem.config.ts`).
- **`src/aem/aem.fetch.ts`** — Thin fetch wrapper. Two auth modes selected by `loadConfig` in the connector: Basic (`user`/`pass`) sends `Authorization: Basic <b64>`; OAuth S2S (`id`/`secret`) calls Adobe IMS (`aem.auth.ts`) to mint a Bearer token, caches it with `expires_in - 60s` headroom, and retries once on 401 by refreshing the token. Form posts use `URLSearchParams` and set `Content-Type: application/x-www-form-urlencoded` (required for SlingPostServlet).

## Component update conventions

Two behaviors are non-obvious and worth knowing before touching component code paths:

1. **Dialog-driven property validation.** `updateComponent` and `addComponent` fetch the component's `cq:dialog` (and walk `sling:resourceSuperType` recursively) to build a `fieldDefinitions` map, then validate provided properties against it — select fields check against the dialog's option values, checkboxes against boolean coercion, numberfields against `Number(...)`. See `getComponentDefinition` and `validateComponentProperties` in `aem.connector.ts`.
2. **`cq:template` materialization.** When `addComponent` finds a `cq:template` node under the component definition (e.g., column controls), it merges template properties into the new node and creates the template's child nodes via separate POSTs. See `getComponentTemplate` and `applyTemplateChildNodes`.

## Important constraints

- **ESM-only** (`"type": "module"` in `package.json`). Internal imports use `.js` suffixes even in `.ts` files — this is required, not a mistake.
- **AGPL-3.0** license — avoid copying code from sources incompatible with this license.
- Releases are driven by **semantic-release** parsing Angular-style commits (`feat:`, `fix:`, `BREAKING CHANGE:` footer); see `docs/CONTRIBUTING.md`. Do not bump versions manually.
- `executeJCRQuery` is **not** a JCR SQL2 executor despite the name — it's a thin wrapper around QueryBuilder fulltext (see the docstring on the method). Don't change its behavior to actually run SQL2 without coordinating with callers.
- The `src/test/` directory contains certificate-generation and mTLS test-server scripts for in-progress cert-auth work, not unit tests.
