# Phase 1 Smoke Test Audit — Transport Compliance & Bug Fixes

**Date:** 2026-06-11  
**Branch:** fix/DDE-365-security-hardening  
**Node:** v20.19.4  
**Build:** `npm run build` (esbuild, ESM)

---

## Test Results

| ID | Area | Command / Harness | Expected | Result |
|----|------|-------------------|----------|--------|
| T1 | Loopback binding (BF2) | `lsof -nP -iTCP:8520 -sTCP:LISTEN` | `127.0.0.1:8520 LISTEN` | **PASS** |
| T2 | Credential in `--host` rejected | `node dist/cli.js -H http://admin:admin@localhost:4502` | exit 1 + error message | **PASS** |
| T3 | Health check — live AEM | `GET /health` (AEM at localhost:4502) | `auth: authorized` | **PASS** |
| T4 | MCP initialize — session ID | `POST /mcp` initialize body | HTTP 200 + `Mcp-Session-Id` header | **PASS** |
| T5 | OAuth single-flight storm | `node src/test/smoke-single-flight.mjs` (4 assertions) | ALL PASS | **PASS** |
| T6 | Blocked origin (BF3) | `Origin: http://evil.test` | HTTP 403 | **PASS** |
| T6b | Port-fuzzing variant | `Origin: http://localhost:9999` | HTTP 403 | **PASS** |
| T7 | Inspector origins allowed | Origins `localhost/127.0.0.1` on ports 6274 + 6277 | HTTP 200 (all 4) | **PASS** |
| T8 | No `Origin` passthrough | `curl` without Origin header | HTTP 200 | **PASS** |
| T9 | Invalid JSON-RPC → 400 (BF4) | Missing `method` field; wrong `jsonrpc` version | HTTP 400 (both) | **PASS** |
| T10 | Stale session (BF5/leak #18) | `Mcp-Session-Id: 00000000-...` on non-initialize | HTTP 404 | **PASS** |
| T11 | SIGINT clean drain (BF8) | `test-leak-17.mjs` Test 1 | exit 0, `drain complete` in stderr | **PASS** |
| T12 | SIGTERM clean drain (BF8) | `test-leak-17.mjs` Test 2 | exit 0, `drain complete` in stderr | **PASS** |
| T13 | Drain deadline → exit 1 | `test-leak-17.mjs` Test 3 (`--shutdown-drain-seconds 1` + stuck request) | exit 1, `drain deadline reached` within ~1s | **PASS** |
| T14 | `uncaughtException` / `unhandledRejection` | `test-leak-17.mjs` Tests 7–8 | exit 1, `[fatal]` log | **PASS** |
| T15 | Raw password never in stderr | `grep SUPERSECRET_DO_NOT_LOG /tmp/t15-stderr.txt` | no match | **PASS** |

**Total: 16/16 PASS** (T13 drain sub-tests + T14 fatal-error sub-tests covered by 19 assertions in `test-leak-17.mjs`)

---

## Automated Test Harnesses

| File | What it covers | Run |
|------|---------------|-----|
| `src/test/smoke-single-flight.mjs` | OAuth single-flight token mint (3 scenarios, 4 assertions) | `npm run build && node src/test/smoke-single-flight.mjs` |
| `src/test/test-leak-17.mjs` | SIGINT/SIGTERM drain, drain deadline, uncaughtException, unhandledRejection (8 scenarios, 19 assertions) | `npm run build && node src/test/test-leak-17.mjs` |
| `src/test/test-leak-18.mjs` | Stale session → 404, error code -32001, re-initialize path (4 scenarios, 8 assertions) | `npm run build && node src/test/test-leak-18.mjs` |

---

## Findings

### ✅ T10 — Stale session now returns 404 (fixed as leak #18)

- **Location:** `src/mcp/mcp.server-handler.ts:66`
- **Was:** `res.status(400)` with JSON-RPC code `-32000`
- **Fixed:** `res.status(404)` with JSON-RPC code `-32001` and message "Session not found."
- **Impact:** MCP Inspector auto-reinitialization loop now triggers correctly on server restart.
- **Test:** `src/test/test-leak-18.mjs` — 8/8 assertions PASS

### ℹ Accept header requirement (SDK enforcement, not a bug)

The MCP SDK's `StreamableHTTPServerTransport` returns **406 Not Acceptable** when the `POST /mcp` request is missing `Accept: application/json, text/event-stream`. This is correct per the MCP StreamableHTTP spec. All runbook `curl` commands must include this header — commands without it are invalid clients, not a server bug.

Correct curl baseline:
```sh
curl -X POST http://127.0.0.1:8502/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{...}'
```