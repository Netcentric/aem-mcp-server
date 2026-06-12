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
   * Optional undici Dispatcher (Agent) — only set by CertAuthStrategy for mTLS.
   * Header-based strategies return undefined; the caller falls back to the
   * default global Dispatcher. Typed loosely here to avoid pulling undici into
   * the surface in feat #1; the concrete `undici.Dispatcher` lands with
   * `CertAuthStrategy` in feat #3.
   */
  getAgent?(): unknown | undefined;

  /**
   * Mint or re-mint credentials. Called by `AEMFetch.init()` and on 401 retry.
   * Noop for BasicAuthStrategy (re-encoding the same credentials produces the
   * same base64). For OAuthStrategy this resets the cached token and triggers
   * a fresh IMS mint. For CertAuthStrategy this re-reads PEM files and rebuilds
   * the Agent (added in feat #7).
   */
  refresh?(): Promise<void>;
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

/**
 * Resolve which auth strategy to use based on supplied credentials.
 *   - `clientId` + `clientSecret` → `OAuthStrategy`
 *   - `username` + `password`     → `BasicAuthStrategy`
 *   - otherwise                   → throws
 *
 * CertAuthStrategy is added in feat #3 and slotted in at the top of the chain
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
