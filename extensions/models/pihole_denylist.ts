/**
 * `@sntxrr/pihole-denylist`: declare a Pi-hole v6 exact-deny list in swamp and
 * converge an appliance to it.
 *
 * A converge is a PLAN by default (`dryRun: true`): it reads the appliance and
 * records what it would add, re-enable and remove, and writes nothing. Pass
 * `dryRun: false` to apply. Undeclared entries are only ever removed with
 * `prune: true`, and a prune larger than `maxRemovals` is refused outright.
 *
 * @module
 */

import { z } from "npm:zod@4";
import { type DenyPlan, normalizeDomains, planDenylist } from "./lib/plan.ts";
import {
  type PiholeConfig,
  withDenylistSession,
  type WriteOutcome,
} from "./lib/client.ts";

const GlobalArgsSchema = z.object({
  host: z.string().describe(
    "Pi-hole host, e.g. 192.0.2.53 or dns.example.lan:8080 (a scheme may be included)",
  ),
  password: z.string().meta({ sensitive: true }).describe(
    "Pi-hole web/app password; use a vault reference",
  ),
  scheme: z.enum(["http", "https"]).default("http").describe(
    "URL scheme when host carries none",
  ),
  caCert: z.string().optional().describe(
    "Inline PEM CA certificate for a self-signed HTTPS appliance",
  ),
  domains: z.array(z.string()).min(1).describe(
    "Declared exact-deny domains (hostnames only; normalised to lower case, de-duplicated)",
  ),
  comment: z.string().default("managed by swamp @sntxrr/pihole-denylist")
    .describe("Comment written on entries this model adds or re-enables"),
  groups: z.array(z.number().int().nonnegative()).default([0]).describe(
    "Pi-hole group ids for added entries (0 = Default)",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const ConvergeArgsSchema = z.object({
  dryRun: z.boolean().default(true).describe(
    "Plan only (default). Set false to apply the changes.",
  ),
  prune: z.boolean().default(false).describe(
    "Remove exact-deny entries on the appliance that are not declared",
  ),
  maxRemovals: z.number().int().nonnegative().default(20).describe(
    "Refuse a prune that would remove more than this many entries",
  ),
});

const FailureSchema = z.object({ domain: z.string(), error: z.string() });

const ConvergeResultSchema = z.object({
  host: z.string(),
  dryRun: z.boolean(),
  prune: z.boolean(),
  declared: z.number(),
  plan: z.object({
    add: z.array(z.string()),
    enable: z.array(z.string()),
    unchanged: z.array(z.string()),
    remove: z.array(z.string()),
    unmanaged: z.array(z.string()),
  }),
  applied: z.object({
    added: z.array(z.string()),
    enabled: z.array(z.string()),
    removed: z.array(z.string()),
  }),
  failed: z.array(FailureSchema),
  summary: z.object({
    add: z.number(),
    enable: z.number(),
    unchanged: z.number(),
    remove: z.number(),
    unmanaged: z.number(),
    failed: z.number(),
  }),
  timestamp: z.string(),
});

const DenyListSchema = z.object({
  host: z.string(),
  entries: z.array(z.object({
    domain: z.string(),
    enabled: z.boolean(),
    comment: z.string().nullable(),
  })),
  count: z.number(),
  timestamp: z.string(),
});

interface Logger {
  info(msg: string, props?: Record<string, unknown>): void;
  warn(msg: string, props?: Record<string, unknown>): void;
}

interface MethodContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

function configFrom(g: GlobalArgs): PiholeConfig {
  return {
    host: g.host,
    password: g.password,
    scheme: g.scheme ?? "http",
    caCert: g.caCert,
  };
}

function summarise(plan: DenyPlan, failed: number) {
  return {
    add: plan.add.length,
    enable: plan.enable.length,
    unchanged: plan.unchanged.length,
    remove: plan.remove.length,
    unmanaged: plan.unmanaged.length,
    failed,
  };
}

/** The model definition. */
export const model = {
  type: "@sntxrr/pihole-denylist",
  version: "2026.09.27.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "deny-list": {
      description: "The appliance's exact-deny entries at the time of reading",
      schema: DenyListSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "converge-result": {
      description:
        "What a converge planned and (unless dryRun) applied, with any failures",
      schema: ConvergeResultSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    list: {
      description: "Read the appliance's exact-deny list (read-only)",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: MethodContext) => {
        const g = context.globalArgs;
        const entries = await withDenylistSession(
          configFrom(g),
          (s) => s.list(),
          (m) => context.logger.warn(m),
        );
        const handle = await context.writeResource("deny-list", "deny-list", {
          host: g.host,
          entries,
          count: entries.length,
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    converge: {
      description:
        "Converge the exact-deny list to globalArguments.domains. Plans only unless dryRun=false; removes undeclared entries only with prune=true.",
      arguments: ConvergeArgsSchema,
      execute: async (
        rawArgs: Partial<z.infer<typeof ConvergeArgsSchema>>,
        context: MethodContext,
      ) => {
        const args = ConvergeArgsSchema.parse(rawArgs ?? {});
        const g = context.globalArgs;
        const declared = normalizeDomains(g.domains);
        const comment = g.comment ?? "managed by swamp @sntxrr/pihole-denylist";
        const groups = g.groups ?? [0];

        const result = await withDenylistSession(
          configFrom(g),
          async (s) => {
            const live = await s.list();
            const plan = planDenylist(declared, live, args.prune);
            if (plan.remove.length > args.maxRemovals) {
              throw new Error(
                `Refusing to prune ${plan.remove.length} entries (maxRemovals=${args.maxRemovals}). ` +
                  "Check the declared list, or raise maxRemovals deliberately.",
              );
            }
            const applied = {
              added: [] as string[],
              enabled: [] as string[],
              removed: [] as string[],
            };
            const failed: Array<{ domain: string; error: string }> = [];
            if (!args.dryRun) {
              const record = (o: WriteOutcome, bucket: string[]) =>
                o.ok ? bucket.push(o.domain) : failed.push({
                  domain: o.domain,
                  error: o.error ?? "unknown",
                });
              for (const o of await s.add(plan.add, comment, groups)) {
                record(o, applied.added);
              }
              for (const d of plan.enable) {
                record(await s.enable(d, comment, groups), applied.enabled);
              }
              for (const d of plan.remove) {
                record(await s.remove(d), applied.removed);
              }
            }
            return { plan, applied, failed };
          },
          (m) => context.logger.warn(m),
        );

        const { plan, applied, failed } = result;
        context.logger.info(
          "{mode} {host}: add={add} enable={enable} unchanged={unchanged} remove={remove} unmanaged={unmanaged} failed={failed}",
          {
            mode: args.dryRun ? "PLAN" : "APPLY",
            host: g.host,
            ...summarise(plan, failed.length),
          },
        );
        const handle = await context.writeResource(
          "converge-result",
          args.dryRun ? "plan" : "apply",
          {
            host: g.host,
            dryRun: args.dryRun,
            prune: args.prune,
            declared: declared.length,
            plan,
            applied,
            failed,
            summary: summarise(plan, failed.length),
            timestamp: new Date().toISOString(),
          },
        );
        if (failed.length > 0) {
          throw new Error(
            `converge: ${failed.length} operation(s) failed: ${
              failed.map((f) => `${f.domain} (${f.error})`).join("; ")
            }`,
          );
        }
        return { dataHandles: [handle] };
      },
    },
  },
};
