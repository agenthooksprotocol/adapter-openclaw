import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthError } from "agenthooksprotocol/client";
import type { StoredRecord } from "agenthooksprotocol/oauth";
import { Logins, type LoginHost } from "../../src/oauth/logins";
import { privateAddress } from "../../src/oauth/network";
import { fileSecretStore, resolveSecret } from "../../src/oauth/secrets";
import { backendSettings, trustedIssuer } from "../../src/oauth/settings";
import { keyedTokenStore, type KeyedStore } from "../../src/oauth/store";
import { callbackRoute } from "../../src/oauth/surfaces";

const dir = mkdtempSync(join(tmpdir(), "ahp-openclaw-oauth-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** OpenClaw's keyed plugin state as far as the store uses it: one table, shared by
 * every "process" that opens it, with opaque comparisons and expiring rows. */
class Table<T> implements KeyedStore<T> {
  readonly rows = new Map<string, { value: T; version: number; expiresAt?: number }>();
  #version = 0;
  #live(key: string) {
    const row = this.rows.get(key);
    if (row?.expiresAt !== undefined && row.expiresAt <= Date.now()) this.rows.delete(key);
    return this.rows.get(key);
  }
  #set(key: string, value: T, ttlMs?: number) {
    this.rows.set(key, { value, version: ++this.#version, ...(ttlMs ? { expiresAt: Date.now() + ttlMs } : {}) });
  }
  async lookup(key: string) { return this.#live(key)?.value; }
  async register(key: string, value: T, opts?: { ttlMs?: number }) { this.#set(key, value, opts?.ttlMs); }
  async registerIfAbsent(key: string, value: T, opts?: { ttlMs?: number }) {
    if (this.#live(key)) return false;
    this.#set(key, value, opts?.ttlMs);
    return true;
  }
  async delete(key: string) { return this.rows.delete(key); }
  async deleteIfEqual(key: string, expected: unknown) {
    if (this.#live(key)?.value !== expected) return false;
    return this.rows.delete(key);
  }
  async observe(key: string) {
    const row = this.#live(key);
    return { value: row?.value, comparison: String(row?.version ?? "absent") };
  }
  async compareAndApply(key: string, comparison: string, intent: { action: string; value?: T }) {
    const current = await this.observe(key);
    if (current.comparison !== comparison) return { status: "conflict" as const, current };
    if (intent.action === "set") this.#set(key, intent.value as T);
    else if (intent.action === "delete") this.rows.delete(key);
    return { status: intent.action === "keep" ? "unchanged" as const : "applied" as const };
  }
}

const grant = (generation: string): StoredRecord => ({ kind: "grant", generation, scopes: [] });
const signal = () => new AbortController().signal;

describe("the token store", () => {
  test("compareAndSet writes only over the generation it expects", async () => {
    const store = keyedTokenStore(new Table<StoredRecord>(), new Table<string>());
    expect(await store.compareAndSet("k", undefined, grant("1"), signal())).toBe(true);
    expect(await store.compareAndSet("k", undefined, grant("2"), signal())).toBe(false);
    expect(await store.compareAndSet("k", "0", grant("2"), signal())).toBe(false);
    expect(await store.compareAndSet("k", "1", grant("2"), signal())).toBe(true);
    expect((await store.load("k", signal()))?.generation).toBe("2");
    expect(await store.compareAndSet("k", "2", undefined, signal())).toBe(true);
    expect(await store.load("k", signal())).toBeUndefined();
    // Deleting what is absent, expecting absence, holds.
    expect(await store.compareAndSet("k", undefined, undefined, signal())).toBe(true);
  });

  test("keys are stored as digests, never as given", async () => {
    const records = new Table<StoredRecord>();
    const store = keyedTokenStore(records, new Table<string>());
    await store.compareAndSet("ahp.oauth.grant:secret-looking", undefined, grant("1"), signal());
    expect([...records.rows.keys()][0]).toMatch(/^[0-9a-f]{64}$/);
  });

  test("two instances sharing the state serialize one key, and not two", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const gateway = keyedTokenStore(records, leases), cli = keyedTokenStore(records, leases);
    const events: string[] = [];
    const work = (name: string, ms: number) => async () => {
      events.push(`${name} in`);
      await Bun.sleep(ms);
      events.push(`${name} out`);
      return name;
    };
    const results = await Promise.all([
      gateway.coordinate("same", signal(), work("a", 80)),
      cli.coordinate("same", signal(), work("b", 10)),
    ]);
    expect(results).toEqual(["a", "b"]);
    expect(events).toEqual(["a in", "a out", "b in", "b out"]);
    // The lease is released.
    expect(leases.rows.size).toBe(0);
    events.length = 0;
    await Promise.all([gateway.coordinate("x", signal(), work("x", 60)), cli.coordinate("y", signal(), work("y", 10))]);
    expect(events.indexOf("y out")).toBeLessThan(events.indexOf("x out"));
  });

  test("a waiter that is cancelled never runs, and a crashed holder's lease expires", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const store = keyedTokenStore(records, leases, { leaseMs: 150 });
    // Another process took the lease and died.
    await leases.registerIfAbsent(createHash("sha256").update("k").digest("hex"), "dead", { ttlMs: 150 });
    const controller = new AbortController();
    let ran = false;
    const waiting = store.coordinate("k", controller.signal, async () => { ran = true; });
    setTimeout(() => controller.abort(new Error("cancelled")), 30);
    await expect(waiting).rejects.toThrow("cancelled");
    expect(ran).toBe(false);
    expect(await store.coordinate("k", signal(), async () => "after expiry")).toBe("after expiry");
  });
});

describe("secrets", () => {
  test("issued secrets are 0600 files in a 0700 directory, apart from tokens", async () => {
    const directory = join(dir, "secrets");
    const secrets = fileSecretStore(directory);
    await secrets.put("ref-1", "s3cret", signal());
    expect(await secrets.get("ref-1", signal())).toBe("s3cret");
    expect(statSync(directory).mode & 0o777).toBe(0o700);
    const [file] = readdirSync(directory);
    expect(file).toMatch(/^[0-9a-f]{64}$/);
    expect(statSync(join(directory, file!)).mode & 0o777).toBe(0o600);
    await secrets.delete("ref-1", signal());
    await secrets.delete("ref-1", signal());
    expect(await secrets.get("ref-1", signal())).toBeUndefined();
  });

  test("a configured secret is a literal or an env or file reference", () => {
    expect(resolveSecret("x", {})).toBe("x");
    expect(resolveSecret({ source: "env", provider: "default", id: "A" }, { A: "from env" })).toBe("from env");
    expect(resolveSecret({ source: "exec", provider: "vault", id: "a" }, {})).toBeUndefined();
  });
});

describe("network policy", () => {
  test("private, loopback and link-local addresses are refused by default", () => {
    for (const address of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0"]) expect(privateAddress(address)).toBe(true);
    for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]) expect(privateAddress(address)).toBe(false);
  });
});

describe("settings", () => {
  test("the backend's oauth object, with what is wrong named and ignored", () => {
    const { settings, problems } = backendSettings({ id: "b", oauth: { issuer: "http://insecure", registration: true, loginLifetimeMinutes: 99, scopes: ["a"], redirectPort: 4000 } });
    expect(settings.issuer).toBeUndefined();
    expect(settings.registration).toBeUndefined();
    expect(settings.scopes).toEqual(["a"]);
    expect(settings.loginLifetimeMs).toBe(600_000);
    expect(problems).toEqual([
      "b: oauth.issuer is not an https URL; ignored",
      "b: oauth.registration needs oauth.issuer; ignored",
      "b: oauth.loginLifetimeMinutes is not more than 0 and at most 10; ignored",
    ]);
  });

  test("an advertised issuer is trusted only by opt-in, for a public browser sign-in", () => {
    const base = { configured: undefined, flow: "authorization_code_pkce" as const, confidential: false, advertised: ["https://as"] };
    expect(trustedIssuer({ ...base, trustAdvertised: false })).toBeUndefined();
    expect(trustedIssuer({ ...base, trustAdvertised: true })).toBe("https://as");
    expect(trustedIssuer({ ...base, trustAdvertised: true, confidential: true })).toBeUndefined();
    expect(trustedIssuer({ ...base, trustAdvertised: true, flow: "client_credentials" })).toBeUndefined();
    expect(trustedIssuer({ ...base, trustAdvertised: true, advertised: ["https://a", "https://b"] })).toBeUndefined();
    expect(trustedIssuer({ ...base, trustAdvertised: false, configured: "https://as" })).toBe("https://as");
    expect(trustedIssuer({ ...base, trustAdvertised: true, configured: "https://other" })).toBeUndefined();
  });
});

function logins(backends: Record<string, unknown>[], settings = {}): Logins {
  const host: LoginHost = {
    store: keyedTokenStore(new Table<StoredRecord>(), new Table<string>()),
    secrets: fileSecretStore(join(dir, "s")),
    settings: { secrets: { "the-secret": "shh" }, ...settings },
    environment: {},
    port: () => 18789,
    backends: () => backends as never,
    log: () => {},
    warn: () => {},
  };
  return new Logins(host);
}

describe("client selection", () => {
  const http = (id: string, oauth?: unknown, authentication?: unknown) => ({ id, transport: { type: "http", url: "https://hooks.example/ahp" }, ...(oauth ? { oauth } : {}), ...(authentication ? { authentication } : {}) });
  const context = (id: string, authentication?: unknown) => ({ backendId: id, purpose: "event" as const, url: "https://hooks.example/ahp", ...(authentication ? { authentication: authentication as never } : {}) });
  const issuers = ["https://as.example"];

  test("a backend with no OAuth settings is refused: an advertisement creates no trust", () => {
    expect(() => logins([http("a")]).selectClient(issuers, "https://hooks.example/ahp", context("a"))).toThrow(AuthError);
  });

  test("pre-registered, partitioned by backend, redirected to the Gateway", () => {
    const client = logins([http("a", { issuer: "https://as.example", clientId: "oc", scopes: ["hooks"] })]).selectClient(issuers, "https://hooks.example/ahp", context("a"));
    expect(client).toMatchObject({ issuer: "https://as.example", clientId: "oc", flow: "authorization_code_pkce", scopes: ["hooks"], grantPartition: "a", redirectUri: "http://127.0.0.1:18789/ahp/oauth/callback" });
    const other = logins([http("b", { issuer: "https://as.example", clientId: "oc" })]).selectClient(issuers, "https://hooks.example/ahp", context("b"));
    expect(other.grantPartition).toBe("b");
  });

  test("a public URL replaces the loopback redirect", () => {
    const client = logins([http("a", { issuer: "https://as.example" })], { publicUrl: "https://gw.example.ts.net/" }).selectClient(issuers, "r", context("a"));
    expect(client.redirectUri).toBe("https://gw.example.ts.net/ahp/oauth/callback");
  });

  test("a metadata document or a registration permission, for the configured issuer", () => {
    const document = { url: "https://oc.example/client.json", redirectUris: ["http://127.0.0.1:18789/ahp/oauth/callback"] };
    const cimd = logins([http("a", { issuer: "https://as.example", clientMetadataDocument: document })]).selectClient(issuers, "r", context("a"));
    expect(cimd.clientMetadataDocument).toEqual(document);
    expect(cimd.clientId).toBeUndefined();
    const dcr = logins([http("a", { issuer: "https://as.example", registration: { clientName: "Mine", initialAccessTokenRef: "iat" } })]).selectClient(issuers, "r", context("a"));
    expect(dcr.registration).toMatchObject({ clientName: "Mine", initialAccessTokenRef: "iat" });
  });

  test("the preset's issuer and client, with the oauth object winning", () => {
    const preset = { type: "oauth", issuer: "https://as.example", resource: "https://hooks.example/ahp", clientId: "preset", flow: "client_credentials", clientSecretRef: "the-secret" };
    const client = logins([http("a", undefined, preset)]).selectClient(issuers, "ignored", context("a", preset));
    expect(client).toMatchObject({ clientId: "preset", flow: "client_credentials", clientSecret: "shh", resource: "https://hooks.example/ahp" });
    const overridden = logins([http("a", { clientId: "mine" }, preset)]).selectClient(issuers, "r", context("a", preset));
    expect(overridden.clientId).toBe("mine");
  });

  test("a secret that does not resolve, or an untrusted issuer, is refused", () => {
    const missing = logins([http("a", { issuer: "https://as.example", flow: "client_credentials", clientId: "c", clientSecretRef: "nope" })]);
    expect(() => missing.selectClient(issuers, "r", context("a"))).toThrow(AuthError);
    const confidential = logins([http("a", { trustAdvertisedIssuer: true, clientId: "c", clientSecretRef: "the-secret" })]);
    expect(() => confidential.selectClient(issuers, "r", context("a"))).toThrow(AuthError);
    const browser = logins([http("a", { trustAdvertisedIssuer: true, clientId: "c" })]).selectClient(issuers, "r", context("a"));
    expect(browser.issuer).toBe("https://as.example");
  });
});

describe("the callback receiver", () => {
  function response() {
    const sent = { status: 0, headers: {} as Record<string, string>, body: "" };
    return {
      sent,
      get statusCode() { return sent.status; },
      set statusCode(value: number) { sent.status = value; },
      setHeader(name: string, value: string) { sent.headers[name] = value; },
      end(body = "") { sent.body = body; },
    };
  }
  const receiver = (complete: (url: string) => Promise<string>) => callbackRoute(() => ({ redirectUri: "http://127.0.0.1:18789/ahp/oauth/callback", complete } as never));

  test("completes the login the callback answers, at the redirect's own address", async () => {
    let seen = "";
    const res = response();
    await receiver(async (url) => { seen = url; return "org.example.<b>"; })({ method: "GET", url: "/ahp/oauth/callback?code=c&state=s" } as never, res as never);
    expect(seen).toBe("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s");
    expect(res.sent.status).toBe(200);
    expect(res.sent.body).toContain("You can close this tab");
    expect(res.sent.body).toContain("org.example.&#60;b&#62;");
    expect(res.sent.headers["cache-control"]).toBe("no-store");
  });

  test("a spent or unknown callback says so, and only GET is answered", async () => {
    const res = response();
    await receiver(async () => { throw new AuthError("interaction_required"); })({ method: "GET", url: "/ahp/oauth/callback?state=x" } as never, res as never);
    expect(res.sent.status).toBe(400);
    expect(res.sent.body).toContain("expired or was already used");
    const post = response();
    await receiver(async () => "x")({ method: "POST", url: "/ahp/oauth/callback" } as never, post as never);
    expect(post.sent.status).toBe(405);
  });
});
