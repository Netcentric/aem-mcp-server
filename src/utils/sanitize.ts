/**
 * Strip userinfo (`user:pass@`) from a URL before it is logged, interpolated
 * into an error message, or otherwise rendered to a place the credential
 * should not reach. Returns `'<unparseable-url>'` if the input is not a valid
 * URL — never echo the raw input back, since the whole point is to not leak.
 */
export function sanitizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.username = '';
    u.password = '';
    return u.toString();
  } catch {
    return '<unparseable-url>';
  }
}

/**
 * Strip userinfo from every URL-like substring embedded in an error message.
 * Node fetch's TypeError ("Request cannot be constructed from a URL that
 * includes credentials: http://user:pass@host/...") is the motivating case,
 * but any error whose `.message` interpolates a URL benefits from this.
 */
export function sanitizeErrorMessage(msg: string): string {
  if (!msg) return msg;
  // Match `scheme://userinfo@` and drop the userinfo segment.
  return msg.replace(/(\bhttps?:\/\/)[^\s@/]+@/gi, '$1');
}

/**
 * Collapse embedded CR/LF into single spaces so a string renders as one line.
 * The MCP transport JSON.stringify's outgoing messages, which already escapes
 * newlines inside JSON string values — so this is a readability + defense-in-
 * depth measure, not required for wire framing. Worth applying anywhere an
 * error message is interpolated into a plain text field (e.g.
 * `` `Error: ${err.message}` ``) so logs and clients show a single clean line.
 * Safe to call in HTTP mode too — it only touches CR/LF.
 */
export function sanitizeForWire(s: string): string {
  if (!s) return s;
  return s.replace(/\r\n|\r|\n/g, ' ');
}

/**
 * True when the given URL string carries embedded credentials (`user:pass@`).
 * Used at config-load time to reject misconfigured hosts before any fetch is
 * attempted.
 */
export function hasUrlCredentials(url: string): boolean {
  try {
    const u = new URL(url);
    return !!u.username || !!u.password;
  } catch {
    return false;
  }
}

/**
 * Reduce an AEM error response body to a short, safe summary suitable for
 * inclusion in an `AEMOperationError.details` field that may be serialized
 * back to an MCP client. HTML pages (Sling error pages) collapse to a
 * placeholder; JSON bodies surface only the `message`/`error` field; plain
 * text is truncated and stripped of control characters.
 *
 * Returns `null` when there is nothing usable.
 */
export function summarizeAemBody(data: unknown, maxLen = 200): string | null {
  if (data == null) return null;

  if (typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    if (typeof obj.message === 'string') return truncate(obj.message, maxLen);
    if (typeof obj.error === 'string') return truncate(obj.error, maxLen);
    try {
      return truncate(JSON.stringify(obj), maxLen);
    } catch {
      return null;
    }
  }

  if (typeof data !== 'string') return null;
  const str = data.trim();
  if (!str) return null;

  if (/^<(?:!doctype|html|\?xml)/i.test(str)) {
    return '<html error page>';
  }

  try {
    const parsed = JSON.parse(str);
    if (parsed && typeof parsed === 'object') {
      const msg = (parsed as Record<string, unknown>).message;
      const err = (parsed as Record<string, unknown>).error;
      if (typeof msg === 'string') return truncate(msg, maxLen);
      if (typeof err === 'string') return truncate(err, maxLen);
    }
  } catch {
    /* not JSON — fall through to plain-text handling */
  }

  // Normalize C0 control chars (incl. TAB/CR/LF) to single spaces so the error
  // summary renders as one readable line. The transport JSON.stringify's this
  // value for the wire, so newlines are already escaped — this is readability +
  // defense-in-depth, not required for JSON-RPC framing.
  // eslint-disable-next-line no-control-regex
  const cleaned = str.replace(/[\x00-\x1F]/g, ' ');
  return truncate(cleaned, maxLen);
}

function truncate(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen) + '…' : s;
}

export type RedactedCliParams = {
  host: string;
  authMode: 'cert' | 'basic' | 'oauth' | 'none';
  mcpPort?: number;
  hasUser: boolean;
  hasPass: boolean;
  hasId: boolean;
  hasSecret: boolean;
  hasCert: boolean;
  hasKey: boolean;
  hasCa: boolean;
  hasPassphrase: boolean;
};

/**
 * Render `CliParams` in a form safe to log. Strips userinfo from `host`,
 * collapses credential presence to booleans, and surfaces the auth mode
 * without echoing any secret value. Selection order matches
 * `createAuthStrategy` (feat #5): cert+key > id+secret > user+pass.
 */
export function redactCliParams(p: {
  host?: string;
  user?: string;
  pass?: string;
  id?: string;
  secret?: string;
  cert?: string;
  key?: string;
  ca?: string;
  passphrase?: string;
  mcpPort?: number;
}): RedactedCliParams {
  const hasUser = !!p.user;
  const hasPass = !!p.pass;
  const hasId = !!p.id;
  const hasSecret = !!p.secret;
  const hasCert = !!p.cert;
  const hasKey = !!p.key;
  const hasCa = !!p.ca;
  const hasPassphrase = !!p.passphrase;
  const authMode: RedactedCliParams['authMode'] =
    hasCert && hasKey ? 'cert'
      : hasId && hasSecret ? 'oauth'
      : hasUser && hasPass ? 'basic'
      : 'none';
  return {
    host: p.host ? sanitizeUrl(p.host) : '<unset>',
    authMode,
    mcpPort: p.mcpPort,
    hasUser,
    hasPass,
    hasId,
    hasSecret,
    hasCert,
    hasKey,
    hasCa,
    hasPassphrase,
  };
}
