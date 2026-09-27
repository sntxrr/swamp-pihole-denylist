/**
 * Pure planning logic for @sntxrr/pihole-denylist: domain normalisation,
 * the declared-vs-live diff, and secret redaction. No I/O lives here, so every
 * decision the model makes about what to add, re-enable or remove is testable
 * without an appliance.
 *
 * @module
 */

/** One exact-deny entry as the Pi-hole v6 API reports it. */
export interface DenyEntry {
  domain: string;
  enabled: boolean;
  comment: string | null;
}

/** The change set a converge would make. */
export interface DenyPlan {
  /** Declared, absent on the appliance: will be POSTed. */
  add: string[];
  /** Declared, present but disabled: will be re-enabled. */
  enable: string[];
  /** Declared and present and enabled: nothing to do. */
  unchanged: string[];
  /** On the appliance, not declared, and prune is on: will be DELETEd. */
  remove: string[];
  /** On the appliance, not declared, and prune is off: left alone. */
  unmanaged: string[];
}

// RFC 1123 labels, at least two of them, no trailing dot. Pi-hole accepts
// punycode for IDNs, so `xn--` labels pass as ordinary LDH labels.
const HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Lower-case and trim one domain, dropping a trailing root dot. */
export function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Normalise and de-duplicate a declared list, preserving first-seen order.
 * Throws on the first entry that is not a plain hostname, because an exact
 * deny entry with a wildcard or a URL in it silently blocks nothing.
 */
export function normalizeDomains(raw: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of raw) {
    const d = normalizeDomain(r);
    if (!HOSTNAME_RE.test(d)) {
      throw new Error(
        `Not a valid exact domain: ${
          JSON.stringify(r)
        } (no wildcards, schemes, paths or ports)`,
      );
    }
    if (!seen.has(d)) {
      seen.add(d);
      out.push(d);
    }
  }
  return out;
}

/**
 * Diff the declared list against the appliance's exact-deny entries.
 *
 * `prune` decides the fate of undeclared entries: removed when true, reported
 * as `unmanaged` when false. Nothing undeclared is ever touched without it.
 */
export function planDenylist(
  declared: readonly string[],
  live: readonly DenyEntry[],
  prune: boolean,
): DenyPlan {
  const want = normalizeDomains(declared);
  const wantSet = new Set(want);
  const liveByDomain = new Map<string, DenyEntry>();
  for (const e of live) liveByDomain.set(normalizeDomain(e.domain), e);

  const plan: DenyPlan = {
    add: [],
    enable: [],
    unchanged: [],
    remove: [],
    unmanaged: [],
  };
  for (const d of want) {
    const e = liveByDomain.get(d);
    if (!e) plan.add.push(d);
    else if (!e.enabled) plan.enable.push(d);
    else plan.unchanged.push(d);
  }
  for (const d of [...liveByDomain.keys()].sort()) {
    if (wantSet.has(d)) continue;
    (prune ? plan.remove : plan.unmanaged).push(d);
  }
  return plan;
}

/** Replace every non-empty secret in `text` with `[REDACTED]`. */
export function redact(
  text: string,
  secrets: ReadonlyArray<string | undefined>,
): string {
  let out = text;
  for (const s of secrets) {
    if (s && s.length > 0) out = out.split(s).join("[REDACTED]");
  }
  return out;
}

/** Resolve `host` (which may carry a scheme and port) to a base URL. */
export function baseUrl(host: string, scheme: "http" | "https"): string {
  const h = host.trim().replace(/\/+$/, "");
  return /^https?:\/\//i.test(h) ? h : `${scheme}://${h}`;
}
