// extensions/models/pihole_denylist_test.ts
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  createModelTestContext,
  withMockedFetch,
} from "jsr:@swamp-club/swamp-testing@0.20260928.39";
import { model } from "./pihole_denylist.ts";
import {
  baseUrl,
  normalizeDomains,
  planDenylist,
  redact,
} from "./lib/plan.ts";

type ConvergeContext = Parameters<typeof model.methods.converge.execute>[1];

const PASSWORD = "correct-horse-battery-staple";
const SID = "sid-0123456789abcdef";
const CSRF = "csrf-fedcba9876543210";

const GLOBAL_ARGS = {
  host: "192.0.2.53:8080",
  password: PASSWORD,
  scheme: "http" as const,
  domains: [
    "telemetry.example.com",
    "Update.Example.com.",
    "ota.vendor.example",
    "telemetry.example.com",
  ],
  comment: "managed by swamp @sntxrr/pihole-denylist",
  groups: [0],
};

function convergeContext(globalArgs: Record<string, unknown> = GLOBAL_ARGS) {
  const ctx = createModelTestContext({ globalArgs, methodName: "converge" });
  return { ...ctx, context: ctx.context as unknown as ConvergeContext };
}

interface Row {
  domain: string;
  enabled: boolean;
  comment?: string | null;
}

/** A fake FTL that records every call and mutates its own list. */
function fakePihole(initial: Row[], opts: { authValid?: boolean } = {}) {
  const rows = new Map(initial.map((r) => [r.domain, { ...r }]));
  const calls: string[] = [];
  let loggedOut = false;
  const handler = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = decodeURIComponent(url.pathname);
    calls.push(`${req.method} ${path}`);
    if (path === "/api/auth" && req.method === "POST") {
      const body = JSON.parse(await req.text());
      const valid = (opts.authValid ?? true) && body.password === PASSWORD;
      return Response.json({
        session: valid
          ? { valid: true, sid: SID, csrf: CSRF }
          : { valid: false, message: "password incorrect" },
      });
    }
    if (path === "/api/auth" && req.method === "DELETE") {
      loggedOut = true;
      return new Response(null, { status: 204 });
    }
    // Everything else must carry the session.
    if (req.headers.get("Cookie") !== `sid=${SID}`) {
      return new Response("unauthorized", { status: 401 });
    }
    if (path === "/api/domains/deny/exact" && req.method === "GET") {
      return Response.json({
        domains: [...rows.values()].map((r, i) => ({
          id: i + 1,
          domain: r.domain,
          type: "deny",
          kind: "exact",
          enabled: r.enabled,
          comment: r.comment ?? null,
          groups: [0],
        })),
      });
    }
    if (path === "/api/domains/deny/exact" && req.method === "POST") {
      const body = JSON.parse(await req.text());
      const list: string[] = Array.isArray(body.domain)
        ? body.domain
        : [body.domain];
      for (const d of list) {
        rows.set(d, { domain: d, enabled: true, comment: body.comment });
      }
      return Response.json({
        processed: { success: list.map((item) => ({ item })), errors: [] },
      }, { status: 201 });
    }
    const m = path.match(/^\/api\/domains\/deny\/exact\/(.+)$/);
    if (m && req.method === "DELETE") {
      rows.delete(m[1]);
      return new Response(null, { status: 204 });
    }
    if (m && req.method === "PUT") {
      const body = JSON.parse(await req.text());
      rows.set(m[1], { domain: m[1], enabled: body.enabled, comment: body.comment });
      return Response.json({ domains: [] });
    }
    throw new Error(`unexpected request: ${req.method} ${req.url}`);
  };
  return {
    handler,
    calls,
    rows,
    get loggedOut() {
      return loggedOut;
    },
  };
}

const writes = (calls: string[]) =>
  calls.filter((c) => !c.startsWith("GET") && !c.includes("/api/auth"));

// ---- pure logic ----------------------------------------------------------

Deno.test("normalizeDomains lower-cases, strips the root dot and de-duplicates", () => {
  assertEquals(
    normalizeDomains(GLOBAL_ARGS.domains),
    ["telemetry.example.com", "update.example.com", "ota.vendor.example"],
  );
});

Deno.test("normalizeDomains refuses wildcards, URLs, ports and bare labels", () => {
  for (const bad of ["*.example.com", "https://a.example.com", "a.example.com:443", "localhost", ""]) {
    assertThrows(() => normalizeDomains([bad]), Error, "Not a valid exact domain");
  }
});

Deno.test("planDenylist without prune never removes undeclared entries", () => {
  const plan = planDenylist(
    ["a.example.com", "b.example.com", "c.example.com"],
    [
      { domain: "b.example.com", enabled: true, comment: null },
      { domain: "c.example.com", enabled: false, comment: null },
      { domain: "hand-added.example.org", enabled: true, comment: null },
    ],
    false,
  );
  assertEquals(plan.add, ["a.example.com"]);
  assertEquals(plan.enable, ["c.example.com"]);
  assertEquals(plan.unchanged, ["b.example.com"]);
  assertEquals(plan.remove, []);
  assertEquals(plan.unmanaged, ["hand-added.example.org"]);
});

Deno.test("planDenylist with prune removes exactly the undeclared entries", () => {
  const plan = planDenylist(
    ["a.example.com"],
    [
      { domain: "a.example.com", enabled: true, comment: null },
      { domain: "gone.example.com", enabled: true, comment: null },
    ],
    true,
  );
  assertEquals(plan.remove, ["gone.example.com"]);
  assertEquals(plan.unmanaged, []);
  assertEquals(plan.unchanged, ["a.example.com"]);
});

Deno.test("redact and baseUrl", () => {
  assertEquals(redact("x secret y secret", ["secret", undefined, ""]), "x [REDACTED] y [REDACTED]");
  assertEquals(baseUrl("192.0.2.53:8080", "http"), "http://192.0.2.53:8080");
  assertEquals(baseUrl("https://dns.example.lan/", "http"), "https://dns.example.lan");
});

// ---- model against a fake appliance -------------------------------------

Deno.test("converge defaults to a plan: reads, writes nothing, logs out", async () => {
  const fake = fakePihole([]);
  const { context, getWrittenResources } = convergeContext();
  await withMockedFetch(fake.handler, async () => {
    await model.methods.converge.execute({}, context);
  });
  assertEquals(writes(fake.calls), []);
  assertEquals(fake.rows.size, 0);
  assert(fake.loggedOut);
  const r = getWrittenResources()[0];
  assertEquals(r.name, "plan");
  assertEquals(r.data.dryRun, true);
  assertEquals((r.data.plan as { add: string[] }).add.length, 3);
});

Deno.test("converge dryRun=false applies adds and re-enables, and is idempotent", async () => {
  const fake = fakePihole([{ domain: "ota.vendor.example", enabled: false }]);
  const first = convergeContext();
  await withMockedFetch(fake.handler, async () => {
    await model.methods.converge.execute({ dryRun: false }, first.context);
  });
  assertEquals(writes(fake.calls), [
    "POST /api/domains/deny/exact",
    "PUT /api/domains/deny/exact/ota.vendor.example",
  ]);
  assertEquals([...fake.rows.values()].every((r) => r.enabled), true);
  assertEquals(fake.rows.size, 3);

  fake.calls.length = 0;
  const second = convergeContext();
  await withMockedFetch(fake.handler, async () => {
    await model.methods.converge.execute({ dryRun: false }, second.context);
  });
  assertEquals(writes(fake.calls), []);
  const summary = second.getWrittenResources()[0].data.summary as Record<string, number>;
  assertEquals(summary.unchanged, 3);
});

Deno.test("prune removes only undeclared entries; without prune they survive", async () => {
  const initial = [
    { domain: "telemetry.example.com", enabled: true },
    { domain: "hand-added.example.org", enabled: true },
  ];
  const keep = fakePihole(initial);
  await withMockedFetch(keep.handler, async () => {
    await model.methods.converge.execute({ dryRun: false }, convergeContext().context);
  });
  assert(keep.rows.has("hand-added.example.org"));

  const prune = fakePihole(initial);
  await withMockedFetch(prune.handler, async () => {
    await model.methods.converge.execute(
      { dryRun: false, prune: true },
      convergeContext().context,
    );
  });
  assert(!prune.rows.has("hand-added.example.org"));
  assert(writes(prune.calls).includes("DELETE /api/domains/deny/exact/hand-added.example.org"));
});

Deno.test("a prune above maxRemovals is refused before any write", async () => {
  const fake = fakePihole([
    { domain: "x1.example.org", enabled: true },
    { domain: "x2.example.org", enabled: true },
  ]);
  await withMockedFetch(fake.handler, async () => {
    await assertRejects(
      () =>
        model.methods.converge.execute(
          { dryRun: false, prune: true, maxRemovals: 1 },
          convergeContext().context,
        ),
      Error,
      "Refusing to prune 2",
    );
  });
  assertEquals(writes(fake.calls), []);
  assert(fake.loggedOut);
});

Deno.test("a bad password fails without leaking it, and nothing is written", async () => {
  const fake = fakePihole([], { authValid: false });
  const { context, getWrittenResources } = convergeContext();
  await withMockedFetch(fake.handler, async () => {
    const err = await assertRejects(
      () => model.methods.converge.execute({ dryRun: false }, context),
      Error,
      "Auth failed",
    );
    assert(!err.message.includes(PASSWORD));
  });
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("per-domain add errors are recorded and fail the method", async () => {
  const fake = fakePihole([]);
  const failing = async (req: Request) => {
    if (req.method === "POST" && new URL(req.url).pathname === "/api/domains/deny/exact") {
      return Response.json({
        processed: {
          success: [{ item: "telemetry.example.com" }, { item: "ota.vendor.example" }],
          errors: [{ item: "update.example.com", error: `db locked ${SID}` }],
        },
      }, { status: 201 });
    }
    return await fake.handler(req);
  };
  const { context, getWrittenResources } = convergeContext();
  await withMockedFetch(failing, async () => {
    const err = await assertRejects(
      () => model.methods.converge.execute({ dryRun: false }, context),
      Error,
      "1 operation(s) failed",
    );
    assertStringIncludes(err.message, "[REDACTED]");
    assert(!err.message.includes(SID));
  });
  const data = getWrittenResources()[0].data;
  assertEquals((data.applied as { added: string[] }).added.length, 2);
  assertEquals((data.failed as unknown[]).length, 1);
});
