import { z } from 'zod';

// ----------------------------------------------------------------------------
// CliParamsSchema — shape validation for the non-cert CLI inputs (feat: stdio, B2)
// ----------------------------------------------------------------------------
//
// Cert-auth inputs are validated separately by CertParamsSchema (feat #4); this
// schema covers the transport-selection + host shape that both modes share:
//   - stdio: optional boolean (mode selector).
//   - host:  must be a syntactically valid URL.
//
// Embedded credentials in `--host` (`user:pass@`) are rejected earlier in
// cli.ts via `hasUrlCredentials` — this schema only enforces URL shape: strings
// without any scheme (e.g. `author.example.com`) are caught early; wrong-scheme
// or unreachable hosts surface as a network error at fetch time.
//
// Callers MUST use `safeParse(...)`, never `.parse()`, and must NOT echo the
// raw input back: zod's `.url()` message is value-free ("Invalid url"), but the
// cli.ts error path additionally runs the message through `sanitizeErrorMessage`
// so a credential in any future value-bearing issue never reaches stderr.

export const CliParamsSchema = z.object({
  stdio: z.boolean().optional(),
  host: z.string().url({ message: 'must be a valid URL (e.g. https://author.example.com)' }).optional(),
});

export type ValidatedCliParams = z.infer<typeof CliParamsSchema>;
