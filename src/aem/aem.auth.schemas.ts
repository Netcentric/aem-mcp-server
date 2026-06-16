import { z } from 'zod';

// ----------------------------------------------------------------------------
// CertParamsSchema — shape validation for cert-auth CLI / env inputs (feat #4)
// ----------------------------------------------------------------------------
//
// Validates the cert-auth inputs BEFORE they reach `CertAuthStrategy.init()`.
// Shape-only — file reads, PEM-format checks, keypair validation, encrypted-
// key detection, and Agent construction all live in `CertAuthStrategy.init()`
// (feat #3). This schema catches the cheap-to-detect mistakes:
//   - Empty-string flags (`--cert ""`)
//   - Partial config (cert without key, or key without cert)
//
// `passphrase` intentionally has NO matching CLI flag — it MUST be sourced from
// the `AEM_KEY_PASSPHRASE` env var to keep the secret out of `ps aux` and
// shell history. The CLI surface only exposes `cert`, `key`, `ca`.
//
// Callers should use `safeParse(...)`, never `.parse()`, and must NOT echo
// `error.issues[].received` back to stdout/stderr — that would leak path
// values into CI logs.

export const CertParamsSchema = z
  .object({
    cert: z.string().min(1).optional(),
    key: z.string().min(1).optional(),
    ca: z.string().min(1).optional(),
    passphrase: z.string().min(1).optional(),
  })
  .refine((d) => (d.cert && d.key) || (!d.cert && !d.key), {
    message: '--cert and --key must be provided together',
  });

export type CertParams = z.infer<typeof CertParamsSchema>;
