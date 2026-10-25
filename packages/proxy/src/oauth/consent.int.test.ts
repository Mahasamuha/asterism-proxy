import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { failInTransactions } from "../test-helpers/oauth-faults.js";
import { REDIRECT_URI, RESOURCE, getPath, postForm, startRouterApp, type RouterApp } from "../test-helpers/oauth-harness.js";
import { cookieClient, csrfFrom } from "../test-helpers/http.js";
import { bindBrowser, bindRouter } from "../test-helpers/fix-f-bind.js";
import { disconnectDb, truncateAll } from "../test-helpers/db.js";
import { seedClient, seedDeniedClient, seedDeviceCode, seedGrant, seedUser, sha256Hex } from "../test-helpers/seed.js";

vi.mock("../resource-registry.js", async () => (await import("../test-helpers/oauth-harness.js")).fakeResourceRegistry());

import { prisma } from "../db.js";
import { DEVICE_FLOW_REDIRECT_URI_SENTINEL } from "./device.js";
import { consentRouter } from "./consent.js";

let app: RouterApp;
beforeAll(async () => {
  app = await startRouterApp(consentRouter, bindRouter);
});
afterAll(async () => {
  await app.close();
  await disconnectDb();
});
beforeEach(truncateAll);
afterEach(() => vi.restoreAllMocks());

async function flow(over: { scopes?: string[]; device?: { userCode: string }; clientId?: string } = {}) {
  const user = await seedUser();
  const client = await seedClient(over.clientId ? { clientId: over.clientId } : {});
  const handle = `flow-${Math.random().toString(36).slice(2)}`;
  await prisma.authorizationRequest.create({
    data: {
      handle, flowType: over.device ? "device" : "oauth", clientId: client.clientId, resource: RESOURCE, scopes: over.scopes ?? ["read"], subject: user.id, state: over.device?.userCode ?? "st",
      redirectUri: over.device ? DEVICE_FLOW_REDIRECT_URI_SENTINEL : REDIRECT_URI, codeChallenge: "c".repeat(43), expiresAt: new Date(Date.now() + 60_000),
    },
  });
  return { user, client, handle };
}

/** Loads the consent page (CSRF cookie) and returns a function that submits the form. */
async function consentForm(handle: string) {
  const c = cookieClient();
  // The flow's own browser: bound to the flow and signed in as its subject.
  const row = await prisma.authorizationRequest.findUniqueOrThrow({ where: { handle } });
  await bindBrowser(app.baseUrl, c, handle, row.subject!);
  const page = await getPath(app.baseUrl, `/oauth/consent?flow=${handle}`, c.fetch);
  expect(page.status).toBe(200);
  const csrf = csrfFrom(page.text);
  return (action: "approve" | "deny" = "approve") => postForm(app.baseUrl, "/oauth/consent", { flow: handle, action, csrf_token: csrf }, c.fetch);
}

function failAuthCodeCreateInTransactions() {
  failInTransactions(prisma, "authCode", "create");
}

describe("authorization_code consent (P0)", () => {
  it("20 concurrent approvals of one flow produce exactly one code", async () => {
    const { handle, user, client } = await flow();
    const submit = await consentForm(handle);
    const replies = await Promise.all(Array.from({ length: 20 }, () => submit()));
    const redirects = replies.filter((r) => r.status === 302);
    expect(redirects).toHaveLength(1);
    // Losers either lose the delete race ("already been used") or arrive after
    // the winner committed and find no flow ("invalid or has expired").
    expect(replies.filter((r) => r.status === 400 && /already been used|invalid or has expired/.test(r.text))).toHaveLength(19);

    const code = new URL(redirects[0]!.headers.get("location")!).searchParams.get("code")!;
    const codes = await prisma.authCode.findMany();
    expect(codes).toHaveLength(1);
    expect(codes[0]!.codeHash).toBe(sha256Hex(code));
    expect(await prisma.authorizationRequest.count()).toBe(0);
    const grants = await prisma.grant.findMany();
    expect(grants).toHaveLength(1);
    expect(codes[0]!.grantId).toBe(grants[0]!.id);
    expect(grants[0]).toMatchObject({ userId: user.id, clientId: client.clientId, resource: RESOURCE, scopes: ["read"], revokedAt: null });
  });

  it("the grant, the consumed request and the code roll back together when code creation fails", async () => {
    const { handle } = await flow();
    const submit = await consentForm(handle);
    failAuthCodeCreateInTransactions();
    expect((await submit()).status).toBe(500);
    expect(await prisma.grant.count()).toBe(0);
    expect(await prisma.authCode.count()).toBe(0);
    expect(await prisma.authorizationRequest.count()).toBe(1);

    vi.restoreAllMocks();
    expect((await submit()).status).toBe(302);
    expect(await prisma.grant.count()).toBe(1);
    expect(await prisma.authCode.count()).toBe(1);
  });

  it("deny consumes the request, creates no grant and cannot be followed by an approval", async () => {
    const { handle } = await flow();
    const submit = await consentForm(handle);
    const denied = await submit("deny");
    expect(new URL(denied.headers.get("location")!).searchParams.get("error")).toBe("access_denied");
    expect((await submit("approve")).status).toBe(400);
    expect(await prisma.grant.count()).toBe(0);
    expect(await prisma.authCode.count()).toBe(0);
  });

  it("a client denylisted after the form was shown cannot be approved (re-validation on POST)", async () => {
    const { handle, client } = await flow();
    const submit = await consentForm(handle);
    await seedDeniedClient({ kind: "client_id", value: client.clientId });
    const r = await submit();
    expect(r.status).toBe(400);
    expect(r.text).toContain("could not be verified");
    expect(await prisma.authCode.count()).toBe(0);
    expect(await prisma.grant.count()).toBe(0);
    expect(await prisma.authorizationRequest.count()).toBe(1);
  });

  it("approving accumulates scopes and un-revokes without resurrecting old scopes", async () => {
    const live = await flow({ scopes: ["read"] });
    await seedGrant({ userId: live.user.id, clientId: live.client.clientId, scopes: ["write"] });
    expect((await (await consentForm(live.handle))()).status).toBe(302);
    expect((await prisma.grant.findFirstOrThrow()).scopes.sort()).toEqual(["read", "write"]);

    await truncateAll();
    const revoked = await flow({ scopes: ["read"] });
    await seedGrant({ userId: revoked.user.id, clientId: revoked.client.clientId, scopes: ["write", "admin"], revokedAt: new Date() });
    expect((await (await consentForm(revoked.handle))()).status).toBe(302);
    const g = await prisma.grant.findFirstOrThrow();
    expect(g.scopes).toEqual(["read"]);
    expect(g.revokedAt).toBeNull();
  });

  it("an existing grant covering the scopes still shows the form (no auto-approve) and is reused on approve", async () => {
    const f = await flow({ scopes: ["read"] });
    const grant = await seedGrant({ userId: f.user.id, clientId: f.client.clientId, scopes: ["read", "write"] });
    const submit = await consentForm(f.handle);
    expect(await prisma.authCode.count()).toBe(0);
    expect((await submit()).status).toBe(302);
    expect((await prisma.authCode.findFirstOrThrow()).grantId).toBe(grant.id);
  });
});

describe("device flow consent over real rows (P0)", () => {
  async function deviceFlow(codeOver: Record<string, unknown> = {}, flowOver: { clientId?: string } = {}) {
    const f = await flow({ device: { userCode: "ABCD2345" }, ...flowOver });
    const { row } = await seedDeviceCode({ clientId: f.client.clientId, userCode: "ABCD2345", ...codeOver } as never);
    return { ...f, code: row };
  }

  it("approve: the device code becomes approved for the user and the grant exists", async () => {
    const f = await deviceFlow();
    const r = await (await consentForm(f.handle))();
    expect(r.text).toContain("Access granted.");
    expect(await prisma.deviceCode.findUniqueOrThrow({ where: { userCode: "ABCD2345" } })).toMatchObject({ status: "approved", userId: f.user.id });
    expect(await prisma.grant.count({ where: { userId: f.user.id, revokedAt: null } })).toBe(1);
    expect(await prisma.authorizationRequest.count()).toBe(0);
  });

  it("deny: the device code becomes denied and no grant is created", async () => {
    const f = await deviceFlow();
    const r = await (await consentForm(f.handle))("deny");
    expect(r.text).toContain("Access denied.");
    expect((await prisma.deviceCode.findUniqueOrThrow({ where: { userCode: "ABCD2345" } })).status).toBe("denied");
    expect(await prisma.grant.count()).toBe(0);
  });

  it.each([
    ["already approved", { status: "approved" }],
    ["already consumed", { status: "consumed" }],
    ["denied", { status: "denied" }],
  ])("a stale device code (%s) is an error, creates no grant and leaves the device code untouched", async (_n, over) => {
    const f = await deviceFlow(over);
    const r = await (await consentForm(f.handle))();
    expect(r.status).toBe(400);
    expect(r.text).toContain("already been used or has expired");
    expect(await prisma.grant.count()).toBe(0);
    expect((await prisma.deviceCode.findUniqueOrThrow({ where: { userCode: "ABCD2345" } })).status).toBe(over.status);
  });

  it("an expired device code cannot be approved (agent-reported)", async () => {
    const f = await deviceFlow({ expiresAt: new Date(Date.now() - 1000) });
    const r = await (await consentForm(f.handle))();
    expect(r.status).toBe(400);
    expect(await prisma.grant.count()).toBe(0);
    expect((await prisma.deviceCode.findUniqueOrThrow({ where: { userCode: "ABCD2345" } })).status).toBe("pending");
  });

  it("a flow cannot approve a device code issued to a different client (agent-reported)", async () => {
    const f = await flow({ device: { userCode: "ABCD2345" } });
    const other = await seedClient();
    await seedDeviceCode({ clientId: other.clientId, userCode: "ABCD2345" });
    const r = await (await consentForm(f.handle))();
    expect(r.status).toBe(400);
    expect(await prisma.grant.count()).toBe(0);
    expect(await prisma.deviceCode.findUniqueOrThrow({ where: { userCode: "ABCD2345" } })).toMatchObject({ status: "pending", userId: null });
  });

  it("concurrent approvals of one device flow approve it once and create one grant", async () => {
    const f = await deviceFlow();
    const submit = await consentForm(f.handle);
    const replies = await Promise.all(Array.from({ length: 10 }, () => submit()));
    expect(replies.filter((r) => r.status === 200 && r.text.includes("Access granted."))).toHaveLength(1);
    expect(await prisma.grant.count()).toBe(1);
  });
});
