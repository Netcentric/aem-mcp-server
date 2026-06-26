# @netcentric/aem-mcp-server
AEM MCP Server

[![Version](https://img.shields.io/npm/v/@netcentric/aem-mcp-server.svg)](https://npmjs.org/package/@netcentric/aem-mcp-server)
[![Build Status](https://github.com/netcentric/aem-mcp-server/workflows/CI/badge.svg?branch=main)](https://github.com/netcentric/aem-mcp-server/actions)
[![CodeQL Analysis](https://github.com/netcentric/aem-mcp-server/workflows/CodeQL/badge.svg?branch=main)](https://github.com/netcentric/aem-mcp-server/actions)
[![semver: semantic-release](https://img.shields.io/badge/semver-semantic--release-blue.svg)](https://github.com/semantic-release/semantic-release)
[![AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)



AEM MCP Server is a full-featured Model Context Protocol (MCP) server for Adobe Experience Manager (AEM). 
It provides a simple integration with any AI Agent.
This project is designed for non-technical persons who want to manage AEM via natural language.

---

## Overview

- **Chat with your AEM instance** for content, component, and asset operations.
- **AI IDEs integration** (Cursor, Copilot, Webstorm, VS Code, etc.)
- **Supports both AEMaaCS and self-hosted instances**
- **Modern, TypeScript-based AEM MCP server**
- **REST/JSON-RPC API** with latest MCP features.

---

## Quick Start

### Prerequisites
- Node.js 20.19.0+ || 22.12.0+ || 23+
- Access to an AEM instance (local or remote)

### Installation

```sh
npm install @netcentric/aem-mcp-server -g
```

### Start the Server

With default settings (admin:admin credentials for http://localhost:4502):
```sh
aem-mcp
```

### Configuration

```
Options:
  -H, --host                                                            [string] [default: "http://localhost:4502"]
  -u, --user                                                                            [string] [default: "admin"]
  -p, --pass                                                                            [string] [default: "admin"]
  -i, --id                       clientId                                                  [string] [default: ""]
  -s, --secret                   clientSecret                                              [string] [default: ""]
  -C, --cert                     path to client certificate PEM file for mTLS to AEM.    [string]
  -k, --key                      path to private key PEM file for mTLS to AEM.            [string]
      --ca                       path to CA bundle PEM file (self-signed AEM tenants).    [string]
      --cert-watch-interval-min  poll cert mtime every N minutes; reload on change. 0 disables (default).
                                                                                 [number] [default: 0]
  -m, --mcpPort                                                                  [number] [default: 8502]
      --bind                     host interface to bind. Default 127.0.0.1 (loopback only).
                                                                       [string] [default: "127.0.0.1"]
      --shutdown-drain-seconds   max seconds to wait for in-flight requests on SIGINT/SIGTERM.
                                                                                [number] [default: 60]
      --allow-origin             extra Origin header value to allow on /mcp (repeatable).
                                                                                 [array] [default: []]
  -h, --help                     Show help                                            [boolean]
```

### Authentication modes

The server supports three auth modes for talking to AEM. The factory picks
the strongest one available, with cert-auth taking priority over OAuth and
OAuth over Basic:

| Mode | Flags | When to use |
|---|---|---|
| **Basic** | `-u/-p` (defaults `admin/admin`) | Local AEM, on-prem AEM where Basic is still enabled |
| **OAuth (Adobe IMS S2S)** | `-i <clientId> -s <clientSecret>` | AEMaaCS tenants. [More info](https://developer.adobe.com/developer-console/docs/guides/authentication/ServerToServerAuthentication/implementation). |
| **mTLS (client certificate)** | `--cert <path> --key <path> [--ca <path>]` | Air-gapped AEM, enterprise mTLS gateways, compliance-driven tenants (PCI-DSS, FedRAMP, HIPAA), org-issued per-developer client certs |

If you supply both `--cert/--key` and `--id/--secret`, cert-auth wins and a
warning is logged that OAuth params will be ignored.

> **Trust boundary** — mTLS authenticates the **server → AEM** leg only. It
> does **not** authenticate the **MCP client → server** leg. The `/mcp`
> endpoint stays open to anyone who can reach the bind interface; the
> server defaults to loopback (`127.0.0.1`) precisely because of this. If
> you change `--bind` to a non-loopback address, you must put a reverse
> proxy with auth in front yourself.

#### Encrypted private keys

If your private key is PKCS#8-encrypted (`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
supply the passphrase via the `AEM_KEY_PASSPHRASE` env var. There is
intentionally **no `--passphrase` CLI flag** — CLI arguments are visible
to any user on the machine through `ps aux`, env vars are not. For org
PKIs that mandate encrypted-key export (Venafi, internal CAs), this is
the supported path.

#### Cert rotation (production deployments)

Production PKIs (cert-manager, HashiCorp Vault, ACM) rotate client certs
every 60–90 days. Two rotation paths are supported, both without a
process restart:

- **SIGHUP-driven** — replace the PEM files on disk, then
  `kill -HUP <pid>`. The server re-reads the PEMs, validates the keypair,
  and atomically swaps the cached `undici.Agent`. The previous Agent's
  keep-alive sockets drain for 30 s before being destroyed. Bad PEM
  material is rejected before the swap, so the old cert keeps serving.
- **mtime-driven** — start the server with `--cert-watch-interval-min N`
  (env: `AEM_CERT_WATCH_INTERVAL_MIN`). Every N minutes the server polls
  the cert file's mtime; on change, the same reload code path runs.
  Off by default (`0`).

Both paths emit a stderr line like
`[cert-reload] strategy reloaded: SHA256(old)=<hash> → SHA256(new)=<hash>`
so SREs can correlate rotations in their logs.

#### Revocation (CRL / OCSP)

The server does **not** perform CRL or OCSP revocation checks of the
AEM server cert. This is a deliberate scope decision — handle
revocation at the upstream layer (Dispatcher, reverse proxy, mTLS
gateway) where you already have central PKI configuration. The TLS
handshake still validates the AEM server cert chain against the CA
bundle (`--ca` or the OS trust store).

#### Environment variables

| Variable | Purpose |
|---|---|
| `MCP_LOGGER` | Set to `true` to enable diagnostic logging on stdout (off by default — required off for MCP stdio clients). |
| `MCP_USERNAME` / `MCP_PASSWORD` | Optional HTTP Basic auth gate on `POST /mcp` (only active when both are set). |
| `MCP_BIND` | Default bind interface (overrides built-in `127.0.0.1`). CLI `--bind` takes precedence. |
| `MCP_ALLOWED_ORIGINS` | Comma-separated extra `Origin` values allowed on `/mcp`. Inspector ports 6274/6277 on `localhost`/`127.0.0.1` are always allowed. |
| `MCP_SHUTDOWN_DRAIN_SECONDS` | Default SIGINT/SIGTERM drain budget. CLI `--shutdown-drain-seconds` takes precedence. |
| `AEM_IMS_URL` | Override the Adobe IMS token endpoint. Defaults to `https://ims-na1.adobelogin.com/ims/token`. Set to `https://ims-eu1.adobelogin.com/ims/token` (EMEA) or `https://ims-jp1.adobelogin.com/ims/token` (APAC) for non-NA AEMaaCS tenants. |
| `AEM_CERT_PATH` / `AEM_KEY_PATH` / `AEM_CA_PATH` | Cert-auth paths (env-var alternatives to `--cert/--key/--ca`). |
| `AEM_KEY_PASSPHRASE` | Passphrase for an encrypted private key. **Env-only — no CLI equivalent.** |
| `AEM_CERT_WATCH_INTERVAL_MIN` | Default cert mtime poll interval in minutes. CLI `--cert-watch-interval-min` takes precedence. |

> **Production recommendation** — prefer env vars over CLI flags for
> credential paths. Env vars are visible only to the process owner (and
> root) via `/proc/<pid>/environ`; CLI args appear in `ps aux` for
> anyone on the host.

### Example Commands

```sh
# Basic auth (default — local AEM)
aem-mcp -u=user@domain.com -p=mypass -H=https://author-qa.domain.com

# OAuth (AEMaaCS)
aem-mcp -i=<clientId> -s=<clientSecret> -H=https://author-pXXX.adobeaemcloud.com

# mTLS with explicit CA bundle
aem-mcp --cert=/etc/aem-mcp/client.crt --key=/etc/aem-mcp/client.key \
        --ca=/etc/aem-mcp/ca.crt \
        -H=https://author.internal.example.com

# mTLS via env vars (production — keeps paths out of ps aux)
export AEM_CERT_PATH=/etc/aem-mcp/client.crt
export AEM_KEY_PATH=/etc/aem-mcp/client.key
export AEM_CA_PATH=/etc/aem-mcp/ca.crt
export AEM_KEY_PASSPHRASE='...'   # only if the key is encrypted
aem-mcp -H=https://author.internal.example.com --cert-watch-interval-min=15
```

### Add AEM MCP to AI IDE
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=AEM&config=eyJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjg1MDIvbWNwIn0%3D)

---

## Features

- **AEM Page & Asset Management**: Create, update, delete, activate, deactivate, and replicate pages and assets
- **Component Operations**: Validate, update, scan, and manage AEM components (including Experience Fragments)
- **Advanced Search**: QueryBuilder, fulltext, fuzzy, and enhanced page search
- **Replication & Rollout**: Publish/unpublish content, roll out changes to language copies
- **Text & Image Extraction**: Extract all text and images from pages, including fragments
- **Template & Structure Discovery**: List templates, analyze page/component structure
- **Workflow and Inbox Operations**: Manage workflow operation like List, start, advance workflow stages
- **JCR Node Access**: Legacy and modern node/content access
- **AI/LLM Integration**: Natural language interface for AEM via OpenAI, Anthropic, Ollama, or custom LLMs
- **Security**: Auth, environment-based config, and safe operation defaults

---

## AI IDE Integration (Cursor, Copilot, etc.)

AEM MCP Server is compatible with modern AI IDEs and code editors that support MCP protocol, such as **Cursor** and **Copilot** (eg in WebStorm or VS Code).

### How to Connect:
1. **Install and run the AEM MCP Server** as described above.
2. **Configure your IDE** to connect to the MCP server:
   - Open your IDE's MCP server settings.
   - Add a new server with:
     - **Type:** Custom MCP
     - **url:** `http://127.0.0.1:8502/mcp`

3. **Restart your IDE** if needed. The IDE will now be able to:
   - List, search, and manage AEM content
   - Run MCP methods (CRUD, search, rollout, etc.)

Sample for AI-based code editors or custom clients:

```json
{
  "mcpServers": {
    "AEM": {
      "url": "http://127.0.0.1:8502/mcp"
    }
  }
}
```

## Usage

```
List all components on MyPage
```

## API Documentation

For detailed API documentation, please refer to the [API Docs](docs/API.md).

## Similar Projects

1. https://github.com/easingthemes/aem-mcp-server (Used as a base for this project)
1. https://github.com/indrasishbanerjee/aem-mcp-server (Used as a base for #1)
1. https://www.npmjs.com/package/@myea/aem-mcp-handler (Looks like an original source of #2)
