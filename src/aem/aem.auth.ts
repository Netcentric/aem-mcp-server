import fs from 'node:fs';
import tls from 'node:tls';
import { Agent, Dispatcher } from 'undici';
import { LOGGER } from '../utils/logger.js';

// IMS endpoint defaults to NA. Override with AEM_IMS_URL for EMEA
// (https://ims-eu1.adobelogin.com/ims/token) or APAC (https://ims-jp1.adobelogin.com/ims/token).
const IMS_URL = process.env.AEM_IMS_URL || "https://ims-na1.adobelogin.com/ims/token";
const SCOPES = "openid,AdobeID,read_organizations,additional_info.projectedProductContext,aem_author_read,aem_author_write";

type AccessTokenResponse = {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  token_type?: string;
}

const getScopes = (scopes?: string | string[]): string => {
  if (!scopes) {
    return SCOPES;
  }
  if (Array.isArray(scopes)) {
    return scopes.join(',');
  }
  return scopes;
}

/**
 * Get access token using client credentials (server-to-server OAuth)
 */
export async function getAccessToken(clientId: string, clientSecret: string, scopes?: string | string[]): Promise<AccessTokenResponse> {
  if (!clientId || !clientSecret) {
    throw new Error("Client ID and Client Secret must be provided");
  }
  const scope = getScopes(scopes);
  const params = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "client_credentials",
    scope,
  });

  const res = await fetch(IMS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!res.ok) {
    throw new Error(`IMS token request failed: ${res.status} ${await res.text()}`);
  }

  return res.json();
}

// ----------------------------------------------------------------------------
// Auth Strategy interface + implementations
// ----------------------------------------------------------------------------
//
// AuthStrategy encapsulates how the server authenticates to AEM. Three concrete
// strategies exist (or will exist):
//   - BasicAuthStrategy : username/password, sent as `Authorization: Basic ...`
//   - OAuthStrategy     : Adobe IMS S2S, sent as `Authorization: Bearer ...`
//   - CertAuthStrategy  : mTLS client cert handshake; no Authorization header
//                         (added in feat #3)
//
// In feat #1 the interface + Basic/OAuth strategies are introduced; AEMFetch
// delegates to them internally. feat #2 completes the refactor by removing the
// AEMAuth union and consuming AuthStrategy directly from AEMFetch.

export type AuthFactoryInput = {
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string | string[];
};

export interface AuthStrategy {
  /**
   * Headers to merge into outgoing AEM requests (e.g., `Authorization`).
   * Cert strategy returns `{}` since identity lives in the TLS handshake.
   */
  getHeaders(): Promise<Record<string, string>>;

  /**
   * Optional undici `Dispatcher` (Agent) — only set by `CertAuthStrategy` for
   * mTLS. Header-based strategies return undefined; the caller falls back to
   * the default global Dispatcher. Typed as `Dispatcher` from undici 7.x.
   */
  getAgent?(): Dispatcher | undefined;

  /**
   * One-time idempotent setup. Called once by `AEMFetch.init()`. For
   * `OAuthStrategy` this primes the token cache via the first IMS mint. For
   * `CertAuthStrategy` (feat #3) this reads PEM files from disk, validates
   * them, and builds the singleton `undici.Agent`. `BasicAuthStrategy` does
   * not implement this — the encoded credential is computed in its
   * constructor.
   */
  init?(): Promise<void>;

  /**
   * Force a credential refresh on 401. Only `OAuthStrategy` implements this
   * (mint a fresh IMS token). `BasicAuthStrategy` deliberately does not — re-
   * encoding the same credentials produces the same Base64, so a 401-retry is
   * a wasted round-trip and the `request()` path short-circuits when
   * `refresh` is undefined. `CertAuthStrategy` also does not implement this —
   * mTLS cert rotation is SIGHUP-driven via `reload()` (feat #7), not 401-
   * driven; re-reading the same PEM files on a TLS failure would burn disk
   * I/O without changing the handshake material.
   */
  refresh?(): Promise<void>;

  /**
   * Release resources on shutdown. Only `CertAuthStrategy` implements this
   * (destroy the cached `undici.Agent` socket pool, releasing keep-alive
   * sockets ahead of `process.exit`). Called by the graceful drain path in
   * `app.server.ts` (feat #6).
   */
  destroy?(): Promise<void>;
}

export class BasicAuthStrategy implements AuthStrategy {
  /**
   * Precomputed base64 of `user:pass` in Latin-1 (ISO-8859-1) — AEM Sling
   * decodes Basic credentials as Latin-1, not UTF-8. Encoding the source as
   * 'latin1' keeps ASCII identical while making 0x80-0xFF code points
   * (é/ü/ñ/etc.) round-trip correctly. Passwords with code points > 0xFF still
   * can't be expressed in Basic auth and are out of scope.
   */
  readonly encodedToken: string;

  constructor(username: string, password: string) {
    if (!username || !password) {
      throw new Error('BasicAuthStrategy requires both username and password');
    }
    this.encodedToken = Buffer.from(`${username}:${password}`, 'latin1').toString('base64');
  }

  async getHeaders(): Promise<Record<string, string>> {
    return { Authorization: `Basic ${this.encodedToken}` };
  }
}

export class OAuthStrategy implements AuthStrategy {
  private token: string = '';
  private tokenExpiry: number = 0;
  private inflightToken: Promise<string> | null = null;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scope?: string | string[];

  constructor(clientId: string, clientSecret: string, scope?: string | string[]) {
    if (!clientId || !clientSecret) {
      throw new Error('OAuthStrategy requires both clientId and clientSecret');
    }
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scope = scope;
  }

  async getHeaders(): Promise<Record<string, string>> {
    const token = await this.ensureToken();
    return { Authorization: `Bearer ${token}` };
  }

  /**
   * Prime the token cache at startup. Idempotent — repeated calls with a
   * valid cached token return immediately. Called by `AEMFetch.init()`.
   */
  async init(): Promise<void> {
    await this.ensureToken();
  }

  /**
   * Force a fresh IMS mint, discarding any cached token. Called from
   * `AEMFetch.refreshAuthToken()` after a 401 with `expired_token`.
   */
  async refresh(): Promise<void> {
    this.token = '';
    this.tokenExpiry = 0;
    await this.ensureToken();
  }

  /**
   * Returns the current bearer token, minting a new one when the cache is
   * empty or expired. Single-flight dedup: concurrent post-expiry callers
   * share a single IMS round-trip via `inflightToken`.
   */
  async ensureToken(): Promise<string> {
    const now = Date.now();
    if (this.token && now < this.tokenExpiry) {
      return this.token;
    }
    // Dedup concurrent mints: if another caller has already kicked off the
    // IMS request, ride on its promise instead of issuing a parallel mint.
    // Without this, N concurrent post-expiry callers trigger N IMS calls.
    if (this.inflightToken) {
      return this.inflightToken;
    }
    this.inflightToken = (async () => {
      try {
        const token = await getAccessToken(this.clientId, this.clientSecret, this.scope);
        // Reject expires_in <= 60: a value at-or-below the 60s headroom would place
        // tokenExpiry in the past, forcing an IMS mint on every request. Single-flight
        // dedups within a tick but still burns a round-trip per call. NaN/undefined
        // fail this check too (NaN > 60 is false).
        if (!(token.expires_in > 60)) {
          throw new Error(
            `IMS returned invalid expires_in (${token.expires_in}); must be > 60 seconds to leave refresh headroom.`
          );
        }
        this.token = token.access_token;
        this.tokenExpiry = now + (token.expires_in - 60) * 1000;
        return this.token;
      } finally {
        this.inflightToken = null;
      }
    })();
    return this.inflightToken;
  }
}

// ----------------------------------------------------------------------------
// CertAuthStrategy — mTLS via client certificate handshake (feat #3)
// ----------------------------------------------------------------------------
//
// The mTLS identity lives entirely in the TLS handshake; no `Authorization`
// header is sent. `getAgent()` returns a cached `undici.Agent` (singleton,
// built once in `init()`) whose `connect` options carry the cert/key/CA/
// passphrase + `minVersion: 'TLSv1.2'`. AEMFetch passes that Agent to
// Node's native `fetch` via the `dispatcher` field.
//
// Wiring CLI flags + factory selection lands in feat #4 / feat #5; in feat #3
// the class is exported and instantiated directly by tests.

export type CertAuthParams = {
  /** Path to the client certificate PEM file. Read once in `init()`. */
  certPath: string;
  /** Path to the private key PEM file. Read once in `init()`. */
  keyPath: string;
  /** Optional path to a CA bundle PEM file (for self-signed AEM tenants). */
  caPath?: string;
  /**
   * Optional passphrase for an encrypted private key. Per the cert-auth plan
   * this is read ONLY from `AEM_KEY_PASSPHRASE` env var (never a CLI flag)
   * to keep secrets out of `ps aux` — the wiring happens in feat #4.
   */
  passphrase?: string;
};

const MAX_PEM_BYTES = 1_048_576; // 1 MB; rejects accidental binary blobs / DoS
const PEM_BEGIN_PREFIX = '-----BEGIN ';
const ENCRYPTED_KEY_MARKER = '-----BEGIN ENCRYPTED PRIVATE KEY-----';

export class CertAuthStrategy implements AuthStrategy {
  private cachedAgent: Agent | null = null;
  private readonly params: CertAuthParams;

  constructor(params: CertAuthParams) {
    if (!params.certPath || !params.keyPath) {
      throw new Error('CertAuthStrategy requires both certPath and keyPath');
    }
    this.params = params;
  }

  /**
   * Returns an empty header set — mTLS identity is carried by the TLS
   * handshake material, not an `Authorization` header.
   */
  async getHeaders(): Promise<Record<string, string>> {
    return {};
  }

  /**
   * Returns the cached singleton `undici.Agent` built in `init()`. NEVER
   * constructs a new Agent here — per-request Agent construction allocates a
   * fresh keep-alive socket pool every call, leaking FDs until `ulimit -n` is
   * exhausted (mcp-cert-auth-plan.md §"🔴 HIGH — undici.Agent mora biti
   * keširani singleton").
   */
  getAgent(): Dispatcher | undefined {
    return this.cachedAgent ?? undefined;
  }

  /**
   * One-time setup: read + validate PEM files, build the singleton Agent.
   * Safe to call only once per instance — repeated calls will rebuild the
   * Agent and orphan the previous socket pool. The rotation path (feat #7)
   * uses an explicit `reload()` with an atomic swap + 30s drain.
   */
  async init(): Promise<void> {
    const { certPath, keyPath, caPath, passphrase } = this.params;

    const cert = this.readAndGuardPem(certPath, 'cert');
    const key = this.readAndGuardPem(keyPath, 'key');
    const ca = caPath ? this.readAndGuardPem(caPath, 'CA') : undefined;

    // Encrypted-key guard: detect `-----BEGIN ENCRYPTED PRIVATE KEY-----`
    // before tls.createSecureContext throws an unreadable OpenSSL trace.
    if (key.includes(ENCRYPTED_KEY_MARKER) && !passphrase) {
      throw new Error('Encrypted PEM key requires AEM_KEY_PASSPHRASE env variable');
    }

    // Keypair consistency: cert and key must belong to the same pair.
    // `tls.createSecureContext` throws synchronously on mismatch — re-throw
    // with a sanitized message (no OpenSSL trace, no file paths).
    try {
      tls.createSecureContext({ cert, key, passphrase });
    } catch {
      throw new Error('Certificate and private key do not match (keypair mismatch)');
    }

    // World-readable key warning (defense-in-depth — not a hard reject so
    // ephemeral CI/secret-mount scenarios continue to work).
    try {
      const mode = fs.statSync(keyPath).mode;
      if ((mode & 0o004) !== 0) {
        LOGGER.warn('Private key file is world-readable. Consider `chmod 600` for production deployments.');
      }
    } catch {
      // already-failing readAndGuardPem would have surfaced this earlier
    }

    // Singleton Agent. `connect` is the tls.connect options bag; passing
    // `minVersion: 'TLSv1.2'` explicitly because Node's default still allows
    // TLS 1.0/1.1 in some build configurations — unacceptable for mTLS.
    // NEVER set `rejectUnauthorized: false` (defeats the entire mTLS chain).
    this.cachedAgent = new Agent({
      connect: { cert, key, ca, passphrase, minVersion: 'TLSv1.2' },
    });
  }

  /**
   * Release the keep-alive socket pool. Called by the graceful drain path
   * (feat #6) before `process.exit` so lingering connections don't confuse
   * `lsof`-based leak detectors. Idempotent.
   */
  async destroy(): Promise<void> {
    if (this.cachedAgent) {
      await this.cachedAgent.destroy();
      this.cachedAgent = null;
    }
  }

  /**
   * Read a PEM file with all defensive guards. Returns the file contents as
   * a Buffer (binary-safe). Errors are sanitized to omit filesystem paths so
   * they don't leak through `handleAEMHttpError` to MCP clients.
   *
   * Guards (in order — cheapest first):
   *   1. Path traversal: reject any `..` segment in the user-supplied path
   *      BEFORE `path.resolve` flattens it. `/etc/ssl/../shadow` would
   *      otherwise silently resolve to `/etc/shadow`.
   *   2. File size: reject > 1 MB (PEM bundles are well under 100 KB; a
   *      multi-MB file is either an accident or a DoS attempt).
   *   3. PEM format: first 64 bytes must start with `-----BEGIN ` — catches
   *      binary blobs, plain text, and `echo not-pem > x.pem` mistakes.
   */
  private readAndGuardPem(p: string, kind: 'cert' | 'key' | 'CA'): Buffer {
    const segments = p.split(/[/\\]/);
    if (segments.includes('..')) {
      throw new Error(`Path traversal detected in ${kind} path`);
    }

    let size: number;
    try {
      size = fs.statSync(p).size;
    } catch {
      throw new Error(`${kind} file not found or not readable`);
    }

    if (size > MAX_PEM_BYTES) {
      throw new Error(`${kind} file too large (limit: 1 MB)`);
    }

    let buf: Buffer;
    try {
      buf = fs.readFileSync(p);
    } catch {
      throw new Error(`${kind} file not readable`);
    }

    const head = buf.subarray(0, 64).toString('utf8');
    if (!head.startsWith(PEM_BEGIN_PREFIX)) {
      throw new Error(`Not a PEM-encoded ${kind} file`);
    }

    return buf;
  }
}

/**
 * Resolve which auth strategy to use based on supplied credentials.
 *   - `clientId` + `clientSecret` → `OAuthStrategy`
 *   - `username` + `password`     → `BasicAuthStrategy`
 *   - otherwise                   → throws
 *
 * `CertAuthStrategy` is slotted in at the top of this chain in feat #5
 * (cert + key takes priority over OAuth).
 */
export function createAuthStrategy(input: AuthFactoryInput): AuthStrategy {
  if (input.clientId && input.clientSecret) {
    return new OAuthStrategy(input.clientId, input.clientSecret, input.scope);
  }
  if (input.username && input.password) {
    return new BasicAuthStrategy(input.username, input.password);
  }
  throw new Error('No authentication credentials provided');
}
