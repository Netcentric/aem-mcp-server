/**
 * Simple logger utility.
 * Must be disabled for production use to not interfere with Cursor stdio/stdout.
 * Set MCP_LOGGER=true in env to enable logging (default: disabled).
 *
 * stdout safety: `LOGGER.log`/`LOGGER.info` default to `console.log`/
 * `console.info`, which write to stdout. In stdio transport mode stdout is the
 * JSON-RPC wire — any non-framed byte there corrupts the stream and drops the
 * client. `useStderr()` flips an internal switch so all levels route to
 * `console.error` (stderr); `startStdioServer()` calls it before connecting.
 */

const link = (text: string, url: string) => {
  return `\u001b]8;;${url}\u0007${text}\u001b]8;;\u0007`;
}
function getCallerInfo() {
  const err = new Error();
  const stack = err.stack?.split('\n') || [];
  // stack[0] = Error, stack[1] = this function, stack[2] = logger method, stack[3] = caller
  const callerLine = stack[3] || '';
  // Extract file:line info
  const match = callerLine.match(/\(([^)]+)\)/);
  const fileLine = match ? match[1] : callerLine.trim();
  const name = fileLine.split('/').pop() || 'unknown';
  return link(`${name}`, `${fileLine}`);
}

const ENABLE_LOGGER = !!process.env.MCP_LOGGER;

// When true, every level is forced onto stderr regardless of its usual console
// method. Set once at startup via LOGGER.useStderr(); never flipped back.
let forceStderr = false;

export const LOGGER = {
  /**
   * Force all log output onto stderr. Required before connecting a
   * StdioServerTransport so logging never contaminates the stdout JSON-RPC
   * stream. Idempotent and one-way.
   */
  useStderr: () => {
    forceStderr = true;
  },
  log: (...args: any[]) => {
    if (ENABLE_LOGGER) {
      (forceStderr ? console.error : console.log)(`[${getCallerInfo()}]`, ...args);
    }
  },
  info: (...args: any[]) => {
    if (ENABLE_LOGGER) {
      (forceStderr ? console.error : console.info)(`[${getCallerInfo()}]`, ...args);
    }
  },
  warn: (...args: any[]) => {
    if (ENABLE_LOGGER) {
      (forceStderr ? console.error : console.warn)(`[${getCallerInfo()}]`, ...args);
    }
  },
  error: (...args: any[]) => {
    if (ENABLE_LOGGER) {
      console.error(`[${getCallerInfo()}]`, ...args);
    }
  },
};
