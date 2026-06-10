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

export type RedactedCliParams = {
  host: string;
  authMode: 'basic' | 'oauth' | 'none';
  mcpPort?: number;
  hasUser: boolean;
  hasPass: boolean;
  hasId: boolean;
  hasSecret: boolean;
};

/**
 * Render `CliParams` in a form safe to log. Strips userinfo from `host`,
 * collapses credential presence to booleans, and surfaces the auth mode
 * without echoing any secret value.
 */
export function redactCliParams(p: {
  host?: string;
  user?: string;
  pass?: string;
  id?: string;
  secret?: string;
  mcpPort?: number;
}): RedactedCliParams {
  const hasUser = !!p.user;
  const hasPass = !!p.pass;
  const hasId = !!p.id;
  const hasSecret = !!p.secret;
  const authMode: RedactedCliParams['authMode'] =
    hasId && hasSecret ? 'oauth' : hasUser && hasPass ? 'basic' : 'none';
  return {
    host: p.host ? sanitizeUrl(p.host) : '<unset>',
    authMode,
    mcpPort: p.mcpPort,
    hasUser,
    hasPass,
    hasId,
    hasSecret,
  };
}
