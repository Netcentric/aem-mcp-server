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
