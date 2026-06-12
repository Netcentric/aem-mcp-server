import { AuthStrategy } from './aem.auth.js';
import { LOGGER } from '../utils/logger.js';
import { sanitizeUrl, hasUrlCredentials } from '../utils/sanitize.js';

export type AEMFetchConfig = {
  host: string;
  authStrategy: AuthStrategy;
  timeout?: number;
}

type FetchInstance = (input: RequestInfo, init?: RequestInit) => Promise<Response>;

/**
 * Same-origin check for redirect handling: a redirect is treated as same-origin
 * only when scheme + host + port all match. Unparseable inputs are treated as
 * cross-origin (fail safer — strip credentials rather than risk leaking them).
 */
function isSameOrigin(from: string, to: string): boolean {
  try {
    return new URL(from).origin === new URL(to).origin;
  } catch {
    return false;
  }
}

/**
 * Decide whether a 401 response should trigger a token refresh + retry.
 * Inspects the `WWW-Authenticate` header for an OAuth Bearer `error=` directive
 * (RFC 6750). Retries are only useful for `invalid_token`/`expired_token`;
 * `insufficient_scope`, `invalid_request`, `insufficient_user_authentication`
 * cannot be solved by a fresh token, so we fail fast instead of burning a
 * round-trip. Absence of the header or unknown error codes fall back to retry.
 */
function shouldRetryOn401(response: Response): boolean {
  const wwwAuth = response.headers.get('WWW-Authenticate');
  if (!wwwAuth) return true;
  const match = wwwAuth.match(/error\s*=\s*"([^"]+)"|error\s*=\s*([^\s,]+)/i);
  if (!match) return true;
  const err = (match[1] || match[2]).toLowerCase();
  if (err === 'invalid_token' || err === 'expired_token') return true;
  if (
    err === 'insufficient_scope' ||
    err === 'invalid_request' ||
    err === 'insufficient_user_authentication'
  ) {
    return false;
  }
  return true;
}

export class AEMFetch {
  private fetch: FetchInstance | null;
  private readonly config: AEMFetchConfig;
  private readonly strategy: AuthStrategy;

  constructor(config: AEMFetchConfig) {
    if (hasUrlCredentials(config.host)) {
      throw new Error('AEM host URL must not contain embedded credentials. Pass credentials via the AuthStrategy (BasicAuthStrategy / OAuthStrategy / CertAuthStrategy).');
    }
    this.config = config;
    this.strategy = config.authStrategy;
    this.fetch = null;
  }

  /**
   * Initializes the fetch instance. Triggers the strategy's `refresh()` once
   * to prime any cached credentials (OAuth: mint IMS token; Basic: noop;
   * Cert: read PEMs + build undici.Agent in feat #3). Must be called before
   * making requests.
   */
  async init() {
    if (this.strategy.refresh) {
      await this.strategy.refresh();
    }
    this.fetch = this.getFetchInstance();
  }

  /**
   * Whether a 401 response should trigger a credential refresh + retry. Only
   * strategies that implement `refresh()` participate (OAuth mints a new IMS
   * token; Basic short-circuits because re-encoding the same credentials
   * produces the same Base64; Cert handles rotation via SIGHUP/reload(), not
   * 401-driven refresh — see feat #7).
   */
  private get supportsRefreshOn401(): boolean {
    return typeof this.strategy.refresh === 'function';
  }

  /**
   * Returns a fetch instance that injects the strategy's headers on every
   * request and, for cert-mode, attaches the strategy's `undici.Agent` as the
   * fetch dispatcher.
   */
  private getFetchInstance(): FetchInstance {
    return async (input: RequestInfo, init: RequestInit = {}): Promise<Response> => {
      const headers = init.headers instanceof Headers
        ? new Headers(init.headers)
        : new Headers(init.headers || {});

      const authHeaders = await this.strategy.getHeaders();
      for (const [k, v] of Object.entries(authHeaders)) {
        headers.set(k, v);
      }

      if (!headers.has('Accept')) {
        headers.set('Accept', 'application/json');
      }
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }

      const { headers: _, ...initWithoutHeaders } = init;
      const fetchInit: RequestInit = { ...initWithoutHeaders, headers };
      // CertAuthStrategy (feat #3) returns an undici.Agent; native fetch
      // accepts it via the `dispatcher` field. `dispatcher` is not in the
      // standard RequestInit, so cast through `any` at this single seam.
      const agent = this.strategy.getAgent?.();
      if (agent) {
        (fetchInit as RequestInit & { dispatcher?: unknown }).dispatcher = agent;
      }
      return fetch(input, fetchInit);
    }
  }

  /**
   * Force a credential refresh. Called from `request()` on 401 (gated by
   * `supportsRefreshOn401`) and exposed publicly so tests / external callers
   * can trigger a refresh without going through a 401.
   */
  async refreshAuthToken() {
    if (this.strategy.refresh) {
      await this.strategy.refresh();
    }
  }
  /**
   * Returns timeout options for fetch requests, including AbortController and timeoutId.
   * @param requestTimeout Optional timeout in ms (overrides config.timeout)
   */
  private getTimeoutOptions(requestTimeout?: number) {
    let controller: AbortController | undefined;
    let timeoutId: NodeJS.Timeout | undefined;
    let signal: AbortSignal | undefined;
    const timeout = requestTimeout || this.config.timeout;
    if (timeout) {
      controller = new AbortController();
      signal = controller.signal;
      timeoutId = setTimeout(() => controller!.abort(), timeout);
    }
    return {
      signal,
      timeoutId,
    };
  }

  /**
   * Builds a URL with query parameters.
   * @param url Relative URL string
   * @param params Optional key-value pairs to append as query params
   * @returns Absolute URL string with query parameters
   */
  private buildUrlWithParams(url: string, params?: Record<string, any>): string {
    const baseUrl = this.config.host.endsWith('/') ? this.config.host.slice(0, -1) : this.config.host;
    const relUrl = url.startsWith('/') ? url : `/${url}`;
    const absUrl = `${baseUrl}${relUrl}`;
    if (!params || Object.keys(params).length === 0) return absUrl;
    const urlObj = new URL(absUrl);
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) urlObj.searchParams.append(k, String(v));
    });
    return urlObj.toString();
  }

  /**
   * Internal request method with timeout and error handling.
   * If a 401 Unauthorized is received, refreshes the auth token and retries once.
   * @param url Absolute URL string
   * @param options Fetch options
   * @param timeout Optional timeout in ms
   * @param isHtml Optional flag to indicate if response is HTML
   * @returns Parsed JSON response
   */
  private async request(url: string, options: RequestInit = {}, timeout?: number, isHtml?: boolean): Promise<any> {
    if (!this.fetch) {
      throw new Error('AEMFetch not initialized. Call await init(config) before making requests.');
    }
    const { timeoutId, signal } = this.getTimeoutOptions(timeout);
    if (timeout) {
      options.signal = signal;
    }
    // Explicitly set redirect to follow (default behavior, but making it explicit)
    options.redirect = options.redirect || 'follow';
    let response: Response;
    let retryTimeoutId: NodeJS.Timeout | undefined;
    try {
      response = await this.fetch(url, options);
      if (response.status === 401 && this.supportsRefreshOn401 && shouldRetryOn401(response)) {
        LOGGER.warn(`AEM request to ${sanitizeUrl(url)} returned 401 Unauthorized. Attempting to refresh token...`);
        await this.refreshAuthToken();
        // Fresh timeout window for the retry: the original signal may already be aborted
        // if the refresh took longer than the original `timeout`.
        const retry = this.getTimeoutOptions(timeout);
        retryTimeoutId = retry.timeoutId;
        const retryOptions = timeout ? { ...options, signal: retry.signal } : options;
        response = await this.fetch(url, retryOptions);
      }
      // Handle redirect status codes (300-399) - fetch should follow automatically, but log if it doesn't
      if (response.status >= 300 && response.status < 400 && !response.ok) {
        const location = response.headers.get('Location');
        if (location) {
          const redirectUrl = location.startsWith('http') ? location : `${this.config.host}${location}`;
          const sameOrigin = isSameOrigin(url, redirectUrl);
          LOGGER.warn(
            `Redirect detected (${response.status}) from ${sanitizeUrl(url)} to ${sanitizeUrl(redirectUrl)}` +
            (sameOrigin ? '' : ' (cross-origin: Authorization stripped)')
          );
          if (sameOrigin) {
            response = await this.fetch(redirectUrl, { ...options, redirect: 'follow' });
          } else {
            // Cross-origin: do NOT use this.fetch (it would re-inject Authorization via
            // getFetchInstance). Use bare fetch and explicitly drop any Authorization header.
            const safeHeaders = new Headers(options.headers || {});
            safeHeaders.delete('Authorization');
            response = await fetch(redirectUrl, { ...options, headers: safeHeaders, redirect: 'follow' });
          }
        }
      }
      if (!response.ok) {
        // Try to get error message from response body
        // Clone response before reading to avoid consuming the stream
        const clonedResponse = response.clone();
        let errorMessage = `AEM ${options.method || 'GET'} failed: ${response.status}`;
        let errorText: string | null = null;
        try {
          errorText = await clonedResponse.text();
          if (errorText && errorText.trim().length > 0) {
            try {
              const errorJson = JSON.parse(errorText);
              errorMessage = `AEM ${options.method || 'GET'} failed: ${response.status} - ${JSON.stringify(errorJson)}`;
            } catch {
              errorMessage = `AEM ${options.method || 'GET'} failed: ${response.status} - ${errorText}`;
            }
          }
        } catch (readError) {
          // If we can't read error, use default message
        }
        const error: any = new Error(errorMessage);
        error.status = response.status;
        error.response = { status: response.status, data: errorText || null };
        throw error;
      }

      // Handle empty responses (common for DELETE operations)
      // 204 No Content or empty body should return null/empty object
      if (response.status === 204 || response.status === 200) {
        const contentType = response.headers.get('content-type') || '';
        const contentLength = response.headers.get('content-length');

        // If it's a DELETE operation and no content, return empty object
        if (options.method === 'DELETE' && (!contentLength || contentLength === '0')) {
          return {};
        }

        // If content-type is not JSON and no content, return empty object
        if (!contentType.includes('application/json') && (!contentLength || contentLength === '0')) {
          return {};
        }
      }

      if (isHtml) {
        return response.text();
      }

      // Check if response has content before parsing JSON
      const text = await response.text();
      if (!text || text.trim().length === 0) {
        return {};
      }

      // Try to parse as JSON, but handle non-JSON responses gracefully
      try {
        return JSON.parse(text);
      } catch (parseError: any) {
        // If it's not JSON and we expected JSON, log a warning but return the text
        // This handles cases where AEM returns HTML error pages
        if (options.method === 'DELETE') {
          // For DELETE, if we can't parse JSON, assume success if status is 2xx
          if (response.status >= 200 && response.status < 300) {
            LOGGER.warn(`DELETE response was not JSON, but status ${response.status} indicates success`);
            return { success: true, status: response.status };
          }
        }
        throw new Error(`Failed to parse response as JSON: ${parseError.message}. Response: ${text.substring(0, 200)}`);
      }
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      if (retryTimeoutId) clearTimeout(retryTimeoutId);
    }
  }

  /**
   * Performs a GET request with optional query parameters and timeout.
   * @param url Absolute URL string
   * @param params Optional query parameters
   * @param options Fetch options
   * @param timeout Optional timeout in ms
   * @param isHtml Optional flag to indicate if response is HTML
   * @returns Parsed JSON response
   */
  async get(url: string, params?: Record<string, any>, options: RequestInit = {}, timeout?: number, isHtml?: boolean): Promise<any> {
    const fullUrl = this.buildUrlWithParams(url, params);
    return this.request(fullUrl, options, timeout, isHtml);
  }

  /**
   * Performs a POST request with JSON or form data and optional timeout.
   * @param url Absolute URL string
   * @param data Request body (object or URLSearchParams)
   * @param options Fetch options
   * @param timeout Optional timeout in ms
   * @returns Parsed JSON response
   */
  async post(url: string, data: any, options: RequestInit = {}, timeout?: number, isHtml?: boolean): Promise<any> {
    let body: BodyInit;
    // Start with headers from options - handle both Headers object and plain object
    const headers = options.headers instanceof Headers
      ? new Headers(options.headers)
      : new Headers(options.headers || {});

    if (data instanceof URLSearchParams) {
      body = data;
      // Set Content-Type for form data - this must be set explicitly
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
    } else {
      body = JSON.stringify(data);
      // Only set JSON Content-Type if not already set
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
    }

    const fullUrl = this.buildUrlWithParams(url);
    // Remove headers from options to avoid conflicts, then set our merged headers
    const { headers: _, ...optionsWithoutHeaders } = options;
    return this.request(fullUrl, { ...optionsWithoutHeaders, method: 'POST', body, headers }, timeout, isHtml);
  }

  /**
   * Performs a DELETE request with optional timeout.
   * @param url Absolute URL string
   * @param options Fetch options
   * @param timeout Optional timeout in ms
   * @returns Parsed JSON response
   */
  async delete(url: string, options: RequestInit = {}, timeout?: number): Promise<any> {
    const fullUrl = this.buildUrlWithParams(url);
    return this.request(fullUrl, { ...options, method: 'DELETE' }, timeout);
  }

  /**
   * Performs a POST request and returns the raw Response object to access headers.
   * Useful for endpoints that return Location headers (like workflow creation).
   * @param url Relative URL string
   * @param data Request body (object or URLSearchParams)
   * @param options Fetch options
   * @param timeout Optional timeout in ms
   * @returns Raw Response object
   */
  async postWithHeaders(url: string, data: any, options: RequestInit = {}, timeout?: number): Promise<Response> {
    if (!this.fetch) {
      throw new Error('AEMFetch not initialized. Call await init() before making requests.');
    }

    let body: BodyInit;
    const headers = options.headers instanceof Headers
      ? new Headers(options.headers)
      : new Headers(options.headers || {});

    if (data instanceof URLSearchParams) {
      body = data;
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
    } else {
      body = JSON.stringify(data);
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
    }

    const fullUrl = this.buildUrlWithParams(url);
    const { timeoutId, signal } = this.getTimeoutOptions(timeout);
    if (timeout) {
      options.signal = signal;
    }

    let retryTimeoutId: NodeJS.Timeout | undefined;
    try {
      const response = await this.fetch(fullUrl, {
        ...options,
        method: 'POST',
        body,
        headers
      });

      if (response.status === 401 && this.supportsRefreshOn401 && shouldRetryOn401(response)) {
        await this.refreshAuthToken();
        // Fresh timeout window for the retry: the original signal may already be aborted
        // if the refresh took longer than the original `timeout`.
        const retry = this.getTimeoutOptions(timeout);
        retryTimeoutId = retry.timeoutId;
        const retryInit: RequestInit = {
          ...options,
          method: 'POST',
          body,
          headers: new Headers(headers),
        };
        if (timeout) retryInit.signal = retry.signal;
        return await this.fetch(fullUrl, retryInit);
      }

      return response;
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      if (retryTimeoutId) clearTimeout(retryTimeoutId);
    }
  }
}
