// Auth factory selection smoke test for feat #5.
//
// Covers test cases from `plan/mcp-cert-auth-implementation.md` § feat #5:
//   - cert+key → CertAuthStrategy (highest priority)
//   - id+secret → OAuthStrategy
//   - user+pass → BasicAuthStrategy
//   - cert+key + id+secret → CertAuthStrategy + conflict warning logged
//   - partial OAuth (only id, no secret) with cert+key → also warns
//
// The conflict warning now uses process.stderr.write unconditionally (no longer
// gated by MCP_LOGGER) so it is visible in default deployments. We capture
// stderr.write to intercept these lines without needing MCP_LOGGER at all.
//
// Run:
//   npm run build && node src/test/smoke-feat-5.mjs

const warnings = [];
const origStderrWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  warnings.push(typeof chunk === 'string' ? chunk : chunk.toString());
  return origStderrWrite(chunk, ...rest);
};

const { createAuthStrategy, BasicAuthStrategy, OAuthStrategy, CertAuthStrategy } =
  await import('../../dist/aem/aem.auth.js');

const pass = [];
const fail = [];
const check = (cond, msg) => (cond ? pass : fail).push(msg);

const clearWarnings = () => { warnings.length = 0; };

// ============================================================
// (1) user+pass only → BasicAuthStrategy
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({ username: 'admin', password: 'admin' });
  check(s instanceof BasicAuthStrategy,
    `(1) user+pass → BasicAuthStrategy (got ${s.constructor.name})`);
  check(warnings.length === 0,
    `(1) no warning emitted for Basic-only (got ${warnings.length} warnings)`);
}

// ============================================================
// (2) id+secret only → OAuthStrategy
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({ clientId: 'cid', clientSecret: 'csec' });
  check(s instanceof OAuthStrategy,
    `(2) id+secret → OAuthStrategy (got ${s.constructor.name})`);
  check(warnings.length === 0,
    `(2) no warning emitted for OAuth-only`);
}

// ============================================================
// (3) cert+key only → CertAuthStrategy, no warning
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({ certPath: '/tmp/c.crt', keyPath: '/tmp/c.key' });
  check(s instanceof CertAuthStrategy,
    `(3) cert+key → CertAuthStrategy (got ${s.constructor.name})`);
  check(warnings.length === 0,
    `(3) no warning emitted for cert-only`);
}

// ============================================================
// (4) cert+key + id+secret → CertAuthStrategy, conflict warning
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', keyPath: '/tmp/c.key',
    clientId: 'cid', clientSecret: 'csec',
  });
  check(s instanceof CertAuthStrategy,
    `(4) cert+key + OAuth → CertAuthStrategy wins (got ${s.constructor.name})`);
  const joined = warnings.join(' | ');
  const mentionsPriority = /priority|precedence/i.test(joined);
  const mentionsIgnored = /ignored/i.test(joined);
  const mentionsCert = /cert/i.test(joined);
  const mentionsOAuth = /OAuth/i.test(joined);
  check(warnings.length >= 1 && mentionsPriority && mentionsIgnored && mentionsCert && mentionsOAuth,
    `(4) conflict warning logged with priority/ignored/cert/OAuth language (count=${warnings.length}, msg="${joined}")`);
}

// ============================================================
// (5) cert+key + partial OAuth (only id, no secret) → also warns
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', keyPath: '/tmp/c.key',
    clientId: 'cid', // no secret
  });
  check(s instanceof CertAuthStrategy,
    `(5) cert+key + partial OAuth → CertAuthStrategy`);
  check(warnings.length >= 1,
    `(5) partial OAuth (id only) still triggers conflict warning (got ${warnings.length})`);
}
{
  clearWarnings();
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', keyPath: '/tmp/c.key',
    clientSecret: 'csec', // no id
  });
  check(s instanceof CertAuthStrategy,
    `(5b) cert+key + partial OAuth (secret only) → CertAuthStrategy`);
  check(warnings.length >= 1,
    `(5b) partial OAuth (secret only) still triggers conflict warning`);
}

// ============================================================
// (6) cert+key + user+pass (non-default) → CertAuthStrategy, NO warning
//     (Basic always defaults to admin/admin in CLI, we can't distinguish
//     explicit-default from "user didn't pass" — silent precedence is correct)
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', keyPath: '/tmp/c.key',
    username: 'someone', password: 'else',
  });
  check(s instanceof CertAuthStrategy,
    `(6) cert+key + user+pass → CertAuthStrategy`);
  check(warnings.length === 0,
    `(6) no warning emitted for cert + Basic (plan: only cert-vs-OAuth warns)`);
}

// ============================================================
// (7) No credentials → throws
// ============================================================
{
  let threw = false;
  let msg = '';
  try { createAuthStrategy({}); } catch (e) { threw = true; msg = e.message; }
  check(threw && /no authentication/i.test(msg),
    `(7) empty input throws "no authentication credentials" (got: "${msg}")`);
}

// ============================================================
// (8) Cert without key → falls through (not handled by factory; CLI catches via Zod)
// ============================================================
{
  clearWarnings();
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', // no keyPath
    username: 'admin', password: 'admin',
  });
  check(s instanceof BasicAuthStrategy,
    `(8) cert without key → falls through to Basic (Zod catches this at CLI; factory just doesn't pick cert)`);
}

// ============================================================
// (9) Cert params (ca + passphrase) pass through to CertAuthStrategy
// ============================================================
{
  const s = createAuthStrategy({
    certPath: '/tmp/c.crt', keyPath: '/tmp/c.key',
    caPath: '/tmp/ca.crt', passphrase: 'secret',
  });
  check(s instanceof CertAuthStrategy,
    `(9) cert+key+ca+passphrase → CertAuthStrategy`);
  // Tested via private `params` would be invasive; the fact that init() works
  // with passphrase is already covered by smoke-cert-auth.mjs (f.2). Here we
  // only verify the factory routed through.
}

process.stderr.write = origStderrWrite;

// ============================================================
// (10) redactCliParams correctly identifies cert mode (log fidelity)
//      Bug fixed in feat #5: sanitize used to fall back to 'basic' when
//      cert/key were supplied because it never inspected those fields.
// ============================================================
{
  const { redactCliParams } = await import('../../dist/utils/sanitize.js');
  {
    const r = redactCliParams({ host: 'https://aem.example.com', user: 'admin', pass: 'admin' });
    check(r.authMode === 'basic', `(10a) user+pass → authMode 'basic' (got '${r.authMode}')`);
  }
  {
    const r = redactCliParams({ host: 'https://aem.example.com', id: 'cid', secret: 'csec' });
    check(r.authMode === 'oauth', `(10b) id+secret → authMode 'oauth' (got '${r.authMode}')`);
  }
  {
    const r = redactCliParams({
      host: 'https://aem.example.com',
      user: 'admin', pass: 'admin',
      cert: '/tmp/c.crt', key: '/tmp/c.key', ca: '/tmp/ca.crt',
    });
    check(r.authMode === 'cert',
      `(10c) cert+key (with default user+pass) → authMode 'cert' (got '${r.authMode}')`);
    check(r.hasCert && r.hasKey && r.hasCa,
      `(10c) hasCert/hasKey/hasCa surfaced (got cert=${r.hasCert} key=${r.hasKey} ca=${r.hasCa})`);
  }
  {
    const r = redactCliParams({
      host: 'https://aem.example.com',
      cert: '/tmp/c.crt', key: '/tmp/c.key',
      passphrase: 'super-secret',
    });
    check(r.hasPassphrase === true,
      `(10d) hasPassphrase = true when passphrase supplied`);
    // Make sure the passphrase value itself is NEVER in the output
    const dump = JSON.stringify(r);
    check(!dump.includes('super-secret'),
      `(10d) redacted output does NOT contain the passphrase value (defense-in-depth)`);
  }
  {
    const r = redactCliParams({ host: 'https://aem.example.com' });
    check(r.authMode === 'none', `(10e) no creds → authMode 'none' (got '${r.authMode}')`);
  }
}

console.log('');
console.log(`PASS (${pass.length}):`);
pass.forEach((p) => console.log(`  PASS  ${p}`));
if (fail.length > 0) {
  console.log(`FAIL (${fail.length}):`);
  fail.forEach((f) => console.log(`  FAIL  ${f}`));
}
console.log('');
console.log(`Result: ${fail.length === 0 ? 'ALL PASS' : `${fail.length} FAILED`}`);
process.exit(fail.length === 0 ? 0 : 1);
