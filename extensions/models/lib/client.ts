/**
 * Pi-hole v6 (FTL) HTTP adapter for the exact-deny list: the I/O boundary.
 *
 * Session handling follows the same contract as `@magistr/pihole`: POST
 * /api/auth with the web password, check `session.valid` (FTL answers 200 even
 * on a bad password), send `sid` as a cookie plus the CSRF header, and ALWAYS
 * DELETE /api/auth afterwards so the appliance's concurrent-session limit is
 * never exhausted. Every error string is redacted before it leaves this file.
 *
 * @module
 */

import { baseUrl, type DenyEntry, redact } from "./plan.ts";

const REQUEST_TIMEOUT_MS = 30_000;
const DENY_EXACT = "/api/domains/deny/exact";

/** Connection settings for one appliance. */
export interface PiholeConfig {
  host: string;
  password: string;
  scheme: "http" | "https";
  caCert?: string;
}

/** Outcome of one write, never thrown so a converge can report partial failure. */
export interface WriteOutcome {
  domain: string;
  ok: boolean;
  error?: string;
}

/** Operations available inside an authenticated session. */
export interface DenylistSession {
  list(): Promise<DenyEntry[]>;
  add(domains: string[], comment: string, groups: number[]): Promise<
    WriteOutcome[]
  >;
  enable(domain: string, comment: string, groups: number[]): Promise<
    WriteOutcome
  >;
  remove(domain: string): Promise<WriteOutcome>;
}

function buildClient(
  base: string,
  caCert: string | undefined,
): Deno.HttpClient | undefined {
  if (base.startsWith("https://") && caCert) {
    if (!/-----BEGIN CERTIFICATE-----/.test(caCert)) {
      throw new Error(
        "caCert must be inline PEM content beginning with -----BEGIN CERTIFICATE-----",
      );
    }
    return Deno.createHttpClient({ caCerts: [caCert] });
  }
  return undefined;
}

/**
 * Open a session, run `fn`, then always log out and close the client. A
 * logout failure never masks the original outcome.
 */
export async function withDenylistSession<T>(
  cfg: PiholeConfig,
  fn: (s: DenylistSession) => Promise<T>,
  warn: (msg: string) => void = () => {},
): Promise<T> {
  const base = baseUrl(cfg.host, cfg.scheme);
  if (base.startsWith("http://")) {
    warn(
      "Pi-hole web password is sent over cleartext HTTP; use scheme https (or a tunnel) to protect it.",
    );
  }
  const client = buildClient(base, cfg.caCert);
  let sid: string | undefined;
  let csrf: string | undefined;
  const secrets = () => [cfg.password, sid, csrf];

  const call = (path: string, init: RequestInit = {}) =>
    fetch(`${base}${path}`, {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        ...(sid ? { "Cookie": `sid=${sid}`, "X-CSRF-Token": csrf ?? "" } : {}),
      },
      client,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    } as RequestInit);

  const failText = async (what: string, res: Response) =>
    redact(
      `${what}: HTTP ${res.status} ${await res.text().catch(() => "")}`.trim(),
      secrets(),
    );

  try {
    const auth = await call("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: cfg.password }),
    });
    if (!auth.ok) throw new Error(await failText("Auth failed", auth));
    const body = await auth.json();
    if (!body?.session?.valid) {
      throw new Error(
        `Auth failed: ${body?.session?.message ?? "invalid credentials"}`,
      );
    }
    sid = body.session.sid;
    csrf = body.session.csrf;
    if (!sid || !csrf) throw new Error("Auth failed: no session returned");

    const session: DenylistSession = {
      async list() {
        const res = await call(DENY_EXACT);
        if (!res.ok) throw new Error(await failText("List failed", res));
        const data = await res.json();
        const rows: unknown[] = Array.isArray(data?.domains)
          ? data.domains
          : [];
        return rows.map((r) => {
          const e = r as Record<string, unknown>;
          if (e.type !== "deny" || e.kind !== "exact") {
            throw new Error(
              `List returned a non deny/exact entry (${String(e.type)}/${
                String(e.kind)
              }); refusing to plan against it`,
            );
          }
          return {
            domain: String(e.domain),
            enabled: e.enabled === true,
            comment: typeof e.comment === "string" ? e.comment : null,
          };
        });
      },

      async add(domains, comment, groups) {
        if (domains.length === 0) return [];
        try {
          const res = await call(DENY_EXACT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              domain: domains,
              comment,
              groups,
              enabled: true,
            }),
          });
          if (!res.ok) {
            const err = await failText("add", res);
            return domains.map((domain) => ({ domain, ok: false, error: err }));
          }
          const data = await res.json().catch(() => ({}));
          const errors = new Map<string, string>();
          for (const e of data?.processed?.errors ?? []) {
            errors.set(String(e.item), redact(String(e.error), secrets()));
          }
          return domains.map((domain) =>
            errors.has(domain)
              ? { domain, ok: false, error: errors.get(domain) }
              : { domain, ok: true }
          );
        } catch (e) {
          const err = redact(
            e instanceof Error ? e.message : String(e),
            secrets(),
          );
          return domains.map((domain) => ({ domain, ok: false, error: err }));
        }
      },

      async enable(domain, comment, groups) {
        try {
          const res = await call(
            `${DENY_EXACT}/${encodeURIComponent(domain)}`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ comment, groups, enabled: true }),
            },
          );
          return res.ok
            ? { domain, ok: true }
            : { domain, ok: false, error: await failText("enable", res) };
        } catch (e) {
          return {
            domain,
            ok: false,
            error: redact(
              e instanceof Error ? e.message : String(e),
              secrets(),
            ),
          };
        }
      },

      async remove(domain) {
        try {
          const res = await call(
            `${DENY_EXACT}/${encodeURIComponent(domain)}`,
            { method: "DELETE" },
          );
          await res.body?.cancel();
          return res.ok
            ? { domain, ok: true }
            : { domain, ok: false, error: `remove: HTTP ${res.status}` };
        } catch (e) {
          return {
            domain,
            ok: false,
            error: redact(
              e instanceof Error ? e.message : String(e),
              secrets(),
            ),
          };
        }
      },
    };
    return await fn(session);
  } catch (e) {
    throw new Error(
      redact(e instanceof Error ? e.message : String(e), secrets()),
    );
  } finally {
    if (sid) {
      try {
        const res = await call("/api/auth", { method: "DELETE" });
        await res.body?.cancel();
      } catch {
        // best-effort session release
      }
    }
    client?.close();
  }
}
