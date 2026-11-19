import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthError } from "agenthooksprotocol/client";
import { bindingKey, frame, managedOAuth, type StoredRecord } from "agenthooksprotocol/oauth";
import { configuredPort, Logins, type Completion, type LoginHost } from "../../src/oauth/logins";
import { privateAddress } from "../../src/oauth/network";
import { fileSecretStore, resolveSecret } from "../../src/oauth/secrets";
import { backendSettings, trustedIssuer } from "../../src/oauth/settings";
import { keyedTokenStore, sweepLegacy, type KeyedStore } from "../../src/oauth/store";
import { callbackRoute, chatCommand, cliCommands, gatewayRunning, gatewayStopped } from "../../src/oauth/surfaces";

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
  async entries() {
    return [...this.rows.keys()].flatMap((key) => {
      const row = this.#live(key);
      return row ? [{ key, value: row.value }] : [];
    });
  }
  async deleteIfEqual(key: string, expected: unknown) {
    if (this.#live(key)?.value !== expected) return false;
    return this.rows.delete(key);
  }
  /** Runs between an observation and what follows it: another process acting. */
  afterObserve?: (key: string) => void;
  /** The next compare-and-apply fails as busy storage would. */
  failNextApply = false;
  async observe(key: string) {
    const row = this.#live(key);
    queueMicrotask(() => this.afterObserve?.(key));
    return { value: row?.value, comparison: String(row?.version ?? "absent") };
  }
  async compareAndApply(key: string, comparison: string, intent: { action: string; value?: T; ttlMs?: number }) {
    if (this.failNextApply) {
      this.failNextApply = false;
      throw new Error("database is locked");
    }
    const row = this.#live(key);
    const current = { value: row?.value, comparison: String(row?.version ?? "absent") };
    if (current.comparison !== comparison) return { status: "conflict" as const, current };
    if (intent.action === "set") this.#set(key, intent.value as T, intent.ttlMs);
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

  test("a pending login, which holds the PKCE verifier, is kept apart and expires with the login; a grant does not expire", async () => {
    const records = new Table<StoredRecord>(), pending = new Table<StoredRecord>();
    const store = keyedTokenStore(records, new Table<string>(), { pending });
    const key = frame("ahp.oauth.pending:", ["openclaw", "s"]);
    const login: StoredRecord = { kind: "pending_login", generation: "1", state: "s", grantKey: "k", expiresAt: Date.now() + 100, authorizationUrl: "https://as.example/authorize?state=s", verifier: "v", client: {} as never, metadata: {} as never, context: { backendId: "a", purpose: "event", url: "https://hooks.example/a" }, source: "dcr" };
    expect(await store.compareAndSet(key, undefined, login, signal())).toBe(true);
    expect(await store.compareAndSet(frame("ahp.oauth.pending-index:", ["k"]), undefined, { kind: "pending_index", generation: "1", states: ["s"] }, signal())).toBe(true);
    expect(await store.compareAndSet("ahp.oauth.grant:k", undefined, grant("1"), signal())).toBe(true);
    const [row] = [...pending.rows.values()];
    expect(pending.rows.size).toBe(1);
    expect(row!.expiresAt! - Date.now()).toBeGreaterThan(0);
    expect(row!.expiresAt! - Date.now()).toBeLessThanOrEqual(100);
    // The index and the grant are retained, with no expiry.
    expect(records.rows.size).toBe(2);
    expect([...records.rows.values()].every((stored) => stored.expiresAt === undefined)).toBe(true);
    expect((await store.load(key, signal()))?.kind).toBe("pending_login");
    await Bun.sleep(120);
    expect(await store.load(key, signal())).toBeUndefined();
    expect(pending.rows.size).toBe(0);
    expect(await store.load("ahp.oauth.grant:k", signal())).toBeDefined();
    // A claimed login is deleted from where it is kept.
    expect(await store.compareAndSet(key, undefined, { ...login, expiresAt: Date.now() + 60_000 }, signal())).toBe(true);
    expect(await store.compareAndSet(key, "1", undefined, signal())).toBe(true);
    expect(pending.rows.size).toBe(0);
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

describe("lease loss", () => {
  test("a holder whose lease was taken says so, and still commits a generation nobody changed", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const warnings: string[] = [];
    const store = keyedTokenStore(records, leases, { leaseMs: 90, warn: (text) => warnings.push(text) });
    const key = "ahp.oauth.grant:k";
    const result = await store.coordinate(key, signal(), async () => {
      // Another process takes the lease, as after a stall past its expiry.
      const lease = [...leases.rows.keys()][0]!;
      leases.rows.set(lease, { value: "someone else", version: 999 });
      await Bun.sleep(80);
      // A rotated refresh token is kept: the generation, not the lease, guards it.
      return store.compareAndSet(key, undefined, grant("late"), signal());
    });
    expect(result).toBe(true);
    expect((await store.load(key, signal()))?.generation).toBe("late");
    expect(warnings).toHaveLength(1);
    // The other holder's lease is not released by the one that lost it.
    expect([...leases.rows.values()][0]?.value).toBe("someone else");
  });

  test("a renewal that fails on busy storage loses nothing", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const warnings: string[] = [];
    const store = keyedTokenStore(records, leases, { leaseMs: 90, warn: (text) => warnings.push(text) });
    const key = "ahp.oauth.grant:busy";
    leases.failNextApply = true;
    const written = await store.coordinate(key, signal(), async () => {
      await Bun.sleep(200);
      expect(leases.failNextApply).toBe(false);
      // Renewed after the failure: still this holder's.
      expect([...leases.rows.values()][0]?.value).not.toBe("someone else");
      return store.compareAndSet(key, undefined, grant("1"), signal());
    });
    expect(written).toBe(true);
    expect(warnings).toEqual([]);
  });

  test("renewal is one compare-and-apply: a lease taken in between is not overwritten, and is noticed at once", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const warnings: string[] = [];
    const store = keyedTokenStore(records, leases, { leaseMs: 90, warn: (text) => warnings.push(text) });
    let stolen = false;
    leases.afterObserve = (key) => {
      if (stolen) return;
      stolen = true;
      leases.rows.set(key, { value: "someone else", version: 999 });
    };
    await store.coordinate("ahp.oauth.grant:race", signal(), async () => {
      // The first renewal runs at 30ms; the next would not before 60ms.
      await Bun.sleep(45);
      expect(warnings).toHaveLength(1);
    });
    expect(stolen).toBe(true);
    expect([...leases.rows.values()][0]?.value).toBe("someone else");
  });

  test("renewal keeps a long holder's lease, atomically", async () => {
    const records = new Table<StoredRecord>(), leases = new Table<string>();
    const store = keyedTokenStore(records, leases, { leaseMs: 60 });
    const key = "ahp.oauth.grant:long";
    const written = await store.coordinate(key, signal(), async () => {
      await Bun.sleep(200);
      return store.compareAndSet(key, undefined, grant("1"), signal());
    });
    expect(written).toBe(true);
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
    for (const address of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "255.255.255.255", "::1", "::", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "0.0.0.0"]) expect(privateAddress(address)).toBe(true);
    for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "2a00:1450::1"]) expect(privateAddress(address)).toBe(false);
  });

  test("an IPv4 address inside IPv6 is checked as IPv4, and 6to4 is refused", () => {
    // The URL parser rewrites a mapped literal to hex groups: that form is checked too.
    expect(new URL("https://[::ffff:127.0.0.1]/").hostname).toBe("[::ffff:7f00:1]");
    for (const address of ["::ffff:127.0.0.1", "::ffff:7f00:1", "[::ffff:7f00:1]", "::ffff:a00:1", "::127.0.0.1", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::192.168.0.1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:808:808::1"]) expect(privateAddress(address)).toBe(true);
    for (const address of ["::ffff:8.8.8.8", "::ffff:808:808", "64:ff9b::808:808"]) expect(privateAddress(address)).toBe(false);
    expect(privateAddress("not an address")).toBe(true);
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

function logins(backends: Record<string, unknown>[], settings = {}, extra: Partial<LoginHost> = {}): Logins {
  const host: LoginHost = {
    store: keyedTokenStore(new Table<StoredRecord>(), new Table<string>()),
    stepUps: new Table<string>(),
    completions: new Table<Completion>(),
    secrets: fileSecretStore(join(dir, "s")),
    settings: { secrets: { "the-secret": "shh" }, ...settings },
    environment: {},
    port: () => 18789,
    backends: () => backends as never,
    log: () => {},
    warn: () => {},
    ...extra,
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

  test("pre-registered, partitioned by backend; each login names its own redirect", () => {
    const client = logins([http("a", { issuer: "https://as.example", clientId: "oc", scopes: ["hooks"] })]).selectClient(issuers, "https://hooks.example/ahp", context("a"));
    expect(client).toMatchObject({ issuer: "https://as.example", clientId: "oc", flow: "authorization_code_pkce", scopes: ["hooks"], grantPartition: "a" });
    expect(client.redirectUri).toBeUndefined();
    const other = logins([http("b", { issuer: "https://as.example", clientId: "oc" })]).selectClient(issuers, "https://hooks.example/ahp", context("b"));
    expect(other.grantPartition).toBe("b");
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

describe("Hooks' re-attempts", () => {
  test("the provider Hooks gets tells it of prepared sign-ins, for every backend", () => {
    const provider = logins([{ id: "a", transport: { type: "http", url: "https://hooks.example/a" }, oauth: { issuer: "https://as.example" } }]).provider();
    expect(typeof provider.onPrepared).toBe("function");
    const unsubscribe = provider.onPrepared!(() => {});
    expect(typeof unsubscribe).toBe("function");
    unsubscribe();
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

  test("keeps a publicUrl's path prefix, which a proxy stripped, taking only the query from the request", async () => {
    let seen = "";
    const behindProxy = callbackRoute(() => ({ redirectUri: "https://gw.example/openclaw/ahp/oauth/callback", complete: async (url: string) => { seen = url; return "a"; } } as never));
    const res = response();
    await behindProxy({ method: "GET", url: "/ahp/oauth/callback?code=c&state=s" } as never, res as never);
    expect(seen).toBe("https://gw.example/openclaw/ahp/oauth/callback?code=c&state=s");
    expect(res.sent.status).toBe(200);
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

describe("redirect", () => {
  const http = { id: "a", transport: { type: "http", url: "https://hooks.example/ahp" }, oauth: { issuer: "https://as.example" } };

  test("publicUrl must be https, or http on loopback, and keeps a path prefix", () => {
    const warnings: string[] = [];
    const at = (publicUrl: string) => logins([http], { publicUrl }, { warn: (text) => warnings.push(text) }).redirectUri;
    expect(at("https://gw.example/openclaw/")).toBe("https://gw.example/openclaw/ahp/oauth/callback");
    expect(at("http://127.0.0.1:9000")).toBe("http://127.0.0.1:9000/ahp/oauth/callback");
    expect(at("http://gw.example")).toBe("http://127.0.0.1:18789/ahp/oauth/callback");
    expect(at("http://localhost:9000")).toBe("http://127.0.0.1:18789/ahp/oauth/callback");
    expect(at("https://user:pw@gw.example")).toBe("http://127.0.0.1:18789/ahp/oauth/callback");
    expect(at("https://gw.example/?x=1")).toBe("http://127.0.0.1:18789/ahp/oauth/callback");
    expect(warnings).toHaveLength(4);
  });

  test("is the Gateway's route, on the port OpenClaw's CLI reaches it on, unless publicUrl says otherwise", () => {
    expect(logins([http]).redirectUri).toBe("http://127.0.0.1:18789/ahp/oauth/callback");
    expect(logins([http], { publicUrl: "https://gw.example.ts.net/" }).redirectUri).toBe("https://gw.example.ts.net/ahp/oauth/callback");
    expect(configuredPort({ gateway: { port: 4242 } }, {})).toBe(4242);
    expect(configuredPort({ gateway: { port: 4242 } }, { OPENCLAW_GATEWAY_PORT: "5151" })).toBe(5151);
    expect(configuredPort(undefined, {})).toBe(18789);
  });
});

describe("logins", () => {
  const backend = (id: string) => ({ id, transport: { type: "http", url: `https://hooks.example/${id}` }, oauth: { issuer: "https://as.example" } });

  test("a callback completes only a stored login, of a backend still in hooks.json", async () => {
    const store = keyedTokenStore(new Table<StoredRecord>(), new Table<string>());
    const instance = logins([backend("a")], {}, { store });
    await expect(instance.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=unknown")).rejects.toMatchObject({ code: "interaction_required" });
    const context = { backendId: "gone", purpose: "event" as const, url: "https://hooks.example/gone" };
    await store.compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s-gone"]), undefined, { kind: "pending_login", generation: "g", state: "s-gone", grantKey: "k", expiresAt: Date.now() + 60_000, authorizationUrl: "https://as.example/authorize?state=s-gone", verifier: "v", client: {} as never, metadata: {} as never, context, source: "dcr" }, signal());
    await expect(instance.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s-gone")).rejects.toMatchObject({ code: "interaction_required" });
  });

  test("a backend skipped at initialization is prepared once after a sign-in elsewhere, so Hooks tries it again; otherwise a signed-in backend is not prepared", async () => {
    const prepared: string[] = [];
    const logged: string[] = [];
    class Signed extends Logins {
      override async status() { return { state: "authorized" as const }; }
      override managed(id: string) { return { prepare: async () => { prepared.push(id); return { type: "ready" }; } } as never; }
    }
    const instance = new Signed({ store: keyedTokenStore(new Table<StoredRecord>(), new Table<string>()), stepUps: new Table<string>(), completions: new Table<Completion>(), secrets: fileSecretStore(join(dir, "s3")), settings: {}, environment: {}, port: () => 18789, backends: () => [backend("a")] as never, log: (text) => logged.push(text), warn: (text) => logged.push(text) });
    instance.initializationFailed.add("a");
    await instance.hint();
    expect(prepared).toEqual(["a"]);
    await instance.hint();
    expect(prepared).toEqual(["a"]);
    expect(logged).toEqual([]);
  });

  test("resuming a skipped backend asks for no scopes, and a login it would start is cancelled, with only a hint", async () => {
    const asked: unknown[] = [];
    const cancelled: string[] = [];
    const warnings: string[] = [];
    class Signed extends Logins {
      override async status() { return { state: "authorized" as const }; }
      override managed() {
        return {
          prepare: async (_context: unknown, _budget: unknown, options: unknown) => {
            asked.push(options);
            return { type: "pending_login", state: "s", authorizationUrl: "https://as.example/authorize?state=s", expiresAt: Date.now() + 60_000 };
          },
          cancel: async (pending: { state: string }) => { cancelled.push(pending.state); },
        } as never;
      }
    }
    const instance = new Signed({ store: keyedTokenStore(new Table<StoredRecord>(), new Table<string>()), stepUps: new Table<string>(), completions: new Table<Completion>(), secrets: fileSecretStore(join(dir, "s7")), settings: {}, environment: {}, port: () => 18789, backends: () => [backend("a")] as never, log: () => {}, warn: (text) => warnings.push(text) });
    // Scopes this process saw asked for, since signed in for elsewhere.
    await instance.needsLogin("a", ["hooks:admin"]);
    instance.initializationFailed.add("a");
    await instance.hint();
    expect(asked).toEqual([{ redirectUri: "http://127.0.0.1:18789/ahp/oauth/callback" }]);
    expect(cancelled).toEqual(["s"]);
    expect(instance.initializationFailed.has("a")).toBe(true);
    expect(warnings).toEqual(["Agent Hooks Protocol: sign-in needed for a: run `openclaw ahp login a` on the Gateway's host"]);
  });

  test("the Gateway log says a sign-in is needed once until it is signed in, never with a link, and prepares none", async () => {
    const warnings: string[] = [];
    const prepared: string[] = [];
    let state: "needs-login" | "authorized" = "needs-login";
    class Waiting extends Logins {
      override async status() { return { state }; }
      override async login(id: string) { prepared.push(id); return { type: "ready" as const }; }
    }
    const instance = new Waiting({ store: keyedTokenStore(new Table<StoredRecord>(), new Table<string>()), stepUps: new Table<string>(), completions: new Table<Completion>(), secrets: fileSecretStore(join(dir, "s4")), settings: {}, environment: {}, port: () => 18789, backends: () => [backend("a")] as never, log: () => {}, warn: (text) => warnings.push(text) });
    await instance.hint();
    await instance.hint();
    state = "authorized";
    await instance.hint();
    state = "needs-login";
    await instance.hint();
    expect(warnings).toEqual(Array(2).fill("Agent Hooks Protocol: sign-in needed for a: run `openclaw ahp login a` on the Gateway's host"));
    expect(prepared).toEqual([]);
  });
});

describe("logout", () => {
  const backend = { id: "a", transport: { type: "http", url: "https://hooks.example/a" }, oauth: { issuer: "https://as.example" } };
  const context = { backendId: "a", purpose: "event" as const, url: "https://hooks.example/a" };

  test("says signed out only when it cancelled a login that was still pending, or deleted a grant", async () => {
    const store = keyedTokenStore(new Table<StoredRecord>(), new Table<string>(), { pending: new Table<StoredRecord>() });
    const instance = logins([backend], {}, { store });
    await store.compareAndSet(bindingKey("openclaw", context), undefined, { kind: "binding", generation: "b", issuer: "https://as.example", resource: "https://hooks.example/a", discoveredAt: Date.now(), grantKey: "k" }, signal());
    // An index naming a login that has expired: nothing to cancel.
    await store.compareAndSet(frame("ahp.oauth.pending-index:", ["k"]), undefined, { kind: "pending_index", generation: "i", states: ["expired"] }, signal());
    expect(await instance.logout("a")).toEqual({ signedOut: false, forgotScopes: false });
    const pending = { kind: "pending_login", generation: "p", state: "live", grantKey: "k", expiresAt: Date.now() + 60_000, authorizationUrl: "https://as.example/authorize?state=live", verifier: "v", client: {} as never, metadata: {} as never, context, source: "dcr" } as StoredRecord;
    await store.compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "live"]), undefined, pending, signal());
    const index = await store.load(frame("ahp.oauth.pending-index:", ["k"]), signal());
    await store.compareAndSet(frame("ahp.oauth.pending-index:", ["k"]), index?.generation, { kind: "pending_index", generation: "j", states: ["live"] }, signal());
    expect(await instance.logout("a")).toEqual({ signedOut: true, forgotScopes: false });
    expect(await store.load(frame("ahp.oauth.pending:", ["openclaw", "live"]), signal())).toBeUndefined();
    expect(await instance.logout("a")).toEqual({ signedOut: false, forgotScopes: false });
  });
});

describe("an earlier version's state", () => {
  test("its pending logins and Gateway redirects are deleted once; grants and bindings stay", async () => {
    const records = new Table<StoredRecord>(), gateway = new Table<string>();
    const old = { kind: "pending_login", generation: "p", state: "s", verifier: "v" } as unknown as StoredRecord;
    await records.register("grant", grant("g"));
    await records.register("binding", { kind: "binding", generation: "b", issuer: "https://as", resource: "https://r", discoveredAt: 0 });
    await records.register("index", { kind: "pending_index", generation: "i", states: [] });
    await records.register("old-pending", old);
    await gateway.register("redirect", "http://127.0.0.1:18789/ahp/oauth/callback");
    await sweepLegacy(records, gateway);
    expect([...records.rows.keys()].sort()).toEqual(["binding", "grant", "index"]);
    expect([...gateway.rows.keys()]).toHaveLength(1);
    expect(await gateway.lookup("redirect")).toBeUndefined();
    // Once: a later open reads nothing.
    let read = false;
    records.entries = async () => { read = true; return []; };
    await sweepLegacy(records, gateway);
    expect(read).toBe(false);
  });
});

describe("openclaw ahp", () => {
  test("asks for the Gateway on its loopback port where publicUrl is set, which this host may not reach", async () => {
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("not signed in", { status: 400 }) });
    const http = { id: "a", transport: { type: "http", url: "https://hooks.example/a" }, oauth: { issuer: "https://as.example" } };
    const port = server.port;
    try {
      const behindProxy = logins([http], { publicUrl: "https://gw.invalid" }, { port: () => port! });
      expect(behindProxy.redirectUri).toBe("https://gw.invalid/ahp/oauth/callback");
      expect(behindProxy.loopbackUri).toBe(`http://127.0.0.1:${port}/ahp/oauth/callback`);
      expect(await gatewayStopped(behindProxy)).toBeUndefined();
    } finally {
      server.stop(true);
    }
    const stopped = await gatewayStopped(logins([http], { publicUrl: "https://gw.invalid" }, { port: () => port! }), 500);
    expect(stopped).toContain(`No Gateway answers at http://127.0.0.1:${port} or at https://gw.invalid (publicUrl)`);
    expect(stopped).toContain("OPENCLAW_GATEWAY_PORT");
  });

  test("knows whether the Gateway answers at the redirect", async () => {
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("not signed in", { status: 400 }) });
    try {
      expect(await gatewayRunning(`http://127.0.0.1:${server.port}/ahp/oauth/callback`)).toBe(true);
    } finally {
      server.stop(true);
    }
    expect(await gatewayRunning(`http://127.0.0.1:${server.port}/ahp/oauth/callback`, 500)).toBe(false);
  });
});

describe("step-up", () => {
  const backend = { id: "a", transport: { type: "http", url: "https://hooks.example/a" }, oauth: { issuer: "https://as.example", scopes: ["hooks:read", "hooks:write"] } };
  /** A process with an old grant, and a fake managed OAuth that grants what a login required. */
  class Process extends Logins {
    readonly prepared: (readonly string[] | undefined)[] = [];
    signedIn = true;
    override credential() { return Promise.resolve(this.signedIn ? { type: "bearer" as const } as never : undefined); }
    override managed() {
      return {
        prepare: async (_context: unknown, _budget: unknown, options: { requiredScopes?: readonly string[] }) => {
          this.prepared.push(options.requiredScopes);
          // An issuer the settings do not trust: refused, naming no scopes.
          if (this.untrustedIssuer) throw new AuthError("access_denied");
          // Settings that no longer allow a scope asked for: the SDK names them.
          const refused = options.requiredScopes?.filter((scope) => !this.allowed.includes(scope)) ?? [];
          if (refused.length) throw new AuthError("access_denied", refused);
          return this.ready ? { type: "ready" } : { type: "pending_login", state: "s", authorizationUrl: "https://as.example/authorize?state=s", expiresAt: Date.now() + 60_000 };
        },
        complete: async () => {
          // Consent refused: the SDK deletes the pending login before it would exchange.
          if (this.denied) throw new AuthError("access_denied");
          return { type: "ready" };
        },
      } as never;
    }
    ready = false;
    denied = false;
    untrustedIssuer = false;
    allowed = ["hooks:read", "hooks:write", "hooks:admin"];
  }
  const pendingLogin = (state: string, requiredScopes: string[]): StoredRecord => ({ kind: "pending_login", generation: "g", state, grantKey: "k", expiresAt: Date.now() + 60_000, authorizationUrl: `https://as.example/authorize?state=${state}`, verifier: "v", client: { requiredScopes } as never, metadata: {} as never, context: { backendId: "a", purpose: "event", url: "https://hooks.example/a" }, source: "dcr" } as StoredRecord);
  const shared = () => ({ records: new Table<StoredRecord>(), stepUps: new Table<string>(), completions: new Table<Completion>() });
  const open = (state: ReturnType<typeof shared>, warn: (text: string) => void = () => {}) => new Process({ store: keyedTokenStore(state.records, new Table<string>()), stepUps: state.stepUps, completions: state.completions, secrets: fileSecretStore(join(dir, "s5")), settings: {}, environment: {}, port: () => 18789, backends: () => [backend] as never, log: () => {}, warn });

  test("scopes a Gateway delivery asked for reach `openclaw ahp login` in another process, which prepares a step-up", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:write"]);
    await gateway.needsLogin("a", ["hooks:admin", "hooks:write"]);
    // Signed in, but not for what was asked: the CLI and /ahp both see it.
    expect(await cli.status(backend as never)).toEqual({ state: "needs-login", scopes: ["hooks:admin", "hooks:write"] });
    expect((await cli.waiting()).map((waiting) => waiting.id)).toEqual(["a"]);
    const result = await cli.login("a");
    expect(result.type).toBe("pending");
    expect(cli.prepared).toEqual([["hooks:admin", "hooks:write"]]);
  });

  test("a stored grant that covers them clears them: at the Gateway's completion, or at a prepare that finds it", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:write"]);
    // The Gateway completes a login that required the scopes.
    const context = { backendId: "a", purpose: "event" as const, url: "https://hooks.example/a" };
    await keyedTokenStore(state.records, new Table<string>()).compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), undefined, { kind: "pending_login", generation: "g", state: "s", grantKey: "k", expiresAt: Date.now() + 60_000, authorizationUrl: "https://as.example/authorize?state=s", verifier: "v", client: { requiredScopes: ["hooks:write"] } as never, metadata: {} as never, context, source: "dcr" }, signal());
    expect(await gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s")).toBe("a");
    expect(state.stepUps.rows.size).toBe(0);
    expect(await cli.status(backend as never)).toEqual({ state: "authorized" });

    // One a login did not require stays; a prepare that finds a grant covering it clears it.
    await gateway.needsLogin("a", ["hooks:admin"]);
    await keyedTokenStore(state.records, new Table<string>()).compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "t"]), undefined, { kind: "pending_login", generation: "g", state: "t", grantKey: "k", expiresAt: Date.now() + 60_000, authorizationUrl: "https://as.example/authorize?state=t", verifier: "v", client: { requiredScopes: ["hooks:write"] } as never, metadata: {} as never, context, source: "dcr" }, signal());
    await gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=t");
    expect(await cli.stepUp("a")).toEqual(["hooks:admin"]);
    cli.ready = true;
    expect(await cli.login("a")).toEqual({ type: "ready" });
    expect(cli.prepared).toEqual([["hooks:admin"]]);
    expect(await cli.stepUp("a")).toEqual([]);
  });

  test("step-ups the Gateway and the CLI record at once both keep their scopes", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state), other = open(state);
    await Promise.all([gateway.needsLogin("a", ["hooks:write"]), cli.needsLogin("a", ["hooks:admin"]), other.needsLogin("a", ["hooks:read"])]);
    expect(await cli.stepUp("a")).toEqual(["hooks:admin", "hooks:read", "hooks:write"]);
    // And in one process, a later step-up adds to the scopes an earlier one asked for.
    gateway.signedIn = false;
    await gateway.needsLogin("a");
    expect(await gateway.login("a")).toMatchObject({ type: "pending", requiredScopes: ["hooks:write", "hooks:admin", "hooks:read"] });
  });

  test("a sign-in clears only the scopes it was for: one asked for while it was open stays, and the sign-in still finishes", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    const store = keyedTokenStore(state.records, new Table<string>());
    await gateway.needsLogin("a", ["hooks:write"]);
    const login = await cli.login("a");
    expect(login).toMatchObject({ type: "pending", state: "s", requiredScopes: ["hooks:write"] });
    await store.compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), undefined, pendingLogin("s", ["hooks:write"]), signal());
    // While the link is open, a delivery asks for more.
    await gateway.needsLogin("a", ["hooks:admin"]);
    expect(await cli.finished(backend as never, login as never)).toEqual({ state: "pending" });
    expect(await gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s")).toBe("a");
    expect(await cli.stepUp("a")).toEqual(["hooks:admin"]);
    expect(await cli.finished(backend as never, login as never)).toEqual({ state: "completed" });
    // Another login is not finished by it.
    expect(await cli.finished(backend as never, { state: "t" })).toEqual({ state: "pending" });
  });

  test("a completion is recorded only after the scopes it answers are cleared", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:write"]);
    const login = await cli.login("a");
    await keyedTokenStore(state.records, new Table<string>()).compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), undefined, pendingLogin("s", ["hooks:write"]), signal());
    // What a CLI polling at the moment the completion lands would see.
    const seen: (readonly string[])[] = [];
    const register = state.completions.register.bind(state.completions);
    state.completions.register = async (key, value, opts) => {
      seen.push(await cli.stepUp("a"));
      return register(key, value, opts);
    };
    await gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s");
    expect(seen).toEqual([[]]);
    expect(await cli.finished(backend as never, login as never)).toEqual({ state: "completed" });
  });

  test("a sign-in finishes on its completion even if a delivery asks for its own scopes again", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:write"]);
    const login = await cli.login("a");
    await keyedTokenStore(state.records, new Table<string>()).compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), undefined, pendingLogin("s", ["hooks:write"]), signal());
    await gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?code=c&state=s");
    // A delivery with a token from before the sign-in is refused, and asks again.
    await gateway.needsLogin("a", ["hooks:write"]);
    expect(await cli.status(backend as never)).toMatchObject({ state: "needs-login", scopes: ["hooks:write"] });
    expect(await cli.finished(backend as never, login as never)).toEqual({ state: "completed" });
  });

  test("a sign-in refused at consent is reported as refused, whatever else is asked for", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:write"]);
    const login = await cli.login("a");
    const store = keyedTokenStore(state.records, new Table<string>());
    await store.compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), undefined, pendingLogin("s", ["hooks:write"]), signal());
    await gateway.needsLogin("a", ["hooks:admin"]);
    gateway.denied = true;
    await expect(gateway.complete("http://127.0.0.1:18789/ahp/oauth/callback?error=access_denied&state=s")).rejects.toMatchObject({ code: "access_denied" });
    // Its pending login is gone, and none of what is still asked for is its own.
    await store.compareAndSet(frame("ahp.oauth.pending:", ["openclaw", "s"]), "g", undefined, signal());
    await gateway.needsLogin("a", ["hooks:read"]);
    // The waiting CLI stops at once, with the reason, rather than waiting out the link.
    expect(await cli.finished(backend as never, login as never)).toEqual({ state: "failed", code: "access_denied" });
  });

  test("scopes the backend's settings no longer allow say how to recover, and logout forgets them", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:admin"]);
    cli.allowed = ["hooks:read", "hooks:write"];
    const refused = cli.login("a");
    await expect(refused).rejects.toThrow("asked for scopes its OAuth settings do not allow (hooks:admin)");
    await expect(refused).rejects.toThrow("openclaw ahp logout a");
    // Nothing else is stored: the step-up alone is what logout removes.
    expect(await cli.logout("a")).toEqual({ signedOut: false, forgotScopes: true });
    expect(state.stepUps.rows.size).toBe(0);
    expect(await cli.login("a")).toMatchObject({ type: "pending", requiredScopes: [] });
    expect(await cli.logout("a")).toEqual({ signedOut: false, forgotScopes: false });
  });

  test("a refusal that names no scopes, as of an untrusted issuer, is not blamed on the step-up", async () => {
    const state = shared();
    const gateway = open(state), cli = open(state);
    await gateway.needsLogin("a", ["hooks:admin"]);
    cli.untrustedIssuer = true;
    const refused = cli.login("a");
    await expect(refused).rejects.toBeInstanceOf(AuthError);
    await expect(refused).rejects.toMatchObject({ code: "access_denied", message: "Authentication failed: access_denied" });
    expect(await cli.stepUp("a")).toEqual(["hooks:admin"]);
  });

  /** The real managed OAuth, over a backend allowed `hooks:read hooks:write` and its
   * authorization server, as their metadata says: only the network is faked. The
   * backend's 401 asks for `challenge`, if given. */
  function sdkWorld(challenge?: string) {
    const real = { id: "a", transport: { type: "http", url: "https://hooks.example/a" }, oauth: { issuer: "https://as.example", clientId: "openclaw", scopes: ["hooks:read", "hooks:write"] } };
    const served = (url: string): Response => {
      const { origin, pathname } = new URL(url);
      if (origin === "https://hooks.example" && pathname.startsWith("/.well-known/oauth-protected-resource")) {
        return Response.json({ resource: "https://hooks.example/a", authorization_servers: ["https://as.example"], scopes_supported: ["hooks:read", "hooks:write", "hooks:admin"] });
      }
      if (origin === "https://as.example" && pathname === "/.well-known/oauth-authorization-server") {
        return Response.json({ issuer: "https://as.example", authorization_endpoint: "https://as.example/authorize", token_endpoint: "https://as.example/token", response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"] });
      }
      if (origin === "https://hooks.example") {
        return new Response(null, { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="https://hooks.example/.well-known/oauth-protected-resource/a"${challenge ? `, scope="${challenge}"` : ""}` } });
      }
      return new Response(null, { status: 404 });
    };
    class Sdk extends Logins {
      constructor(readonly host: LoginHost) { super(host); }
      override managed() {
        return managedOAuth({
          namespace: "openclaw",
          store: this.host.store,
          secrets: this.host.secrets,
          policyFetch: async (url) => served(url),
          checkDestination: () => {},
          selectClient: (issuers, resource, context) => this.selectClient(issuers, resource, context),
          persistPendingLogins: true,
        });
      }
    }
    const state = shared();
    const host: LoginHost = { store: keyedTokenStore(state.records, new Table<string>(), { pending: new Table<StoredRecord>() }), stepUps: state.stepUps, completions: state.completions, secrets: fileSecretStore(join(dir, "s6")), settings: {}, environment: {}, port: () => 18789, backends: () => [real] as never, log: () => {}, warn: () => {} };
    return () => new Sdk(host);
  }

  test("through the SDK: a step-up for a scope outside the backend's `oauth.scopes` names it, and says how to recover", async () => {
    const process = sdkWorld();
    // Within what the backend may be granted, the SDK prepares a login.
    expect(await process().login("a")).toMatchObject({ type: "pending", requiredScopes: [] });
    await process().needsLogin("a", ["hooks:admin"]);
    const refused = process().login("a");
    await expect(refused).rejects.toThrow("a asked for scopes its OAuth settings do not allow (hooks:admin): run `openclaw ahp logout a` to forget them, or add them to its `oauth.scopes` in hooks.json");
    await expect(refused).rejects.toMatchObject({ cause: { code: "access_denied", requiredScopes: ["hooks:admin"] } });
  });

  test("through the SDK: of a step-up's scopes, only the refused ones are named", async () => {
    const process = sdkWorld();
    await process().needsLogin("a", ["hooks:write", "hooks:admin"]);
    const refused = process().login("a");
    await expect(refused).rejects.toThrow("a asked for scopes its OAuth settings do not allow (hooks:admin): run `openclaw ahp logout a`");
    await expect(refused).rejects.toMatchObject({ cause: { requiredScopes: ["hooks:admin", "hooks:write"] } });
  });

  test("through the SDK: a scope the backend's own 401 asks for is refused at delivery, keeps no step-up, and needs no logout", async () => {
    const process = sdkWorld("hooks:read hooks:admin");
    const gateway = process();
    const response = new Response(null, { status: 401, headers: { "www-authenticate": 'Bearer resource_metadata="https://hooks.example/.well-known/oauth-protected-resource/a", scope="hooks:read hooks:admin"' } });
    const refused = await gateway.managed().challenge({ backendId: "a", purpose: "event", url: "https://hooks.example/a", response } as never, { signal: AbortSignal.timeout(5_000), deadline: Date.now() + 5_000 })
      .then(() => undefined, (error: AuthError) => error);
    // Not a login's to fix: the adapter records a step-up only for recovery "login".
    expect(refused).toMatchObject({ code: "access_denied", recovery: "none", requiredScopes: ["hooks:admin", "hooks:read"] });
    expect(await gateway.stepUp("a")).toEqual([]);
    expect(await process().login("a")).toMatchObject({ type: "pending", requiredScopes: [] });
  });

  test("a refusal for scopes no step-up kept says to allow them, not to log out", async () => {
    const state = shared();
    const cli = open(state);
    cli.managed = () => ({ prepare: async () => { throw new AuthError("access_denied", ["hooks:admin", "hooks:read"]); } }) as never;
    const refused = await cli.login("a").then(() => undefined, (error: Error) => error);
    expect(refused?.message).toBe("a asked for scopes its OAuth settings do not allow (hooks:admin): add them to its `oauth.scopes` in hooks.json");
  });

  test("a sign-in a 401 asked for, with no scopes, keeps nothing", async () => {
    const state = shared();
    const gateway = open(state);
    await gateway.needsLogin("a");
    gateway.signedIn = false;
    expect(state.stepUps.rows.size).toBe(0);
    expect(await gateway.status(backend as never)).toEqual({ state: "needs-login" });
  });
});

describe("/ahp in chat", () => {
  test("is for the Gateway's owner only, and reads nothing for anyone else", async () => {
    let read = false;
    const command = chatCommand(() => { read = true; return {} as never; }, () => []);
    for (const ctx of [{ args: "status" }, { args: "logout a", senderIsOwner: false }, { args: "login", gatewayClientScopes: ["operator.read"] }]) {
      expect((await command(ctx)).text).toBe("Only the Gateway's owner can manage Agent Hooks Protocol sign-in.");
    }
    expect(read).toBe(false);
    const owner = chatCommand(() => ({ status: async () => ({ state: "authorized" }) }) as never, () => [{ id: "a" }]);
    expect((await owner({ args: "status", senderIsOwner: true })).text).toBe("a: authorized");
    expect((await owner({ args: "status", gatewayClientScopes: ["operator.write"] })).text).toBe("a: authorized");
  });
});

describe("openclaw ahp login with no Gateway to return to", () => {
  /** commander, as far as cliCommands uses it: each command's action, by path. */
  function program() {
    const actions = new Map<string, (...args: any[]) => unknown>();
    const command = (path: string): any => ({
      command: (name: string) => command(`${path} ${name}`.trim()),
      description: function () { return this; },
      argument: function () { return this; },
      action: function (handler: (...args: any[]) => unknown) { actions.set(path, handler); return this; },
    });
    return { root: command(""), actions };
  }

  test("names where the port comes from, registers no client and prints no link", async () => {
    // A port nothing listens on.
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response() });
    const port = server.port;
    server.stop(true);
    const redirectUri = `http://127.0.0.1:${port}/ahp/oauth/callback`;
    let prepared = 0;
    const logins = { redirectUri, loopbackUri: redirectUri, login: async () => { prepared += 1; return { type: "pending", url: "https://as.example/authorize?state=s", expiresAt: Date.now() + 60_000 }; }, waiting: async () => [{ id: "a" }] };
    const { root, actions } = program();
    cliCommands(root, () => logins as never, () => [{ id: "a" }]);
    const printed: string[] = [];
    const log = console.log, exitCode = globalThis.process.exitCode;
    console.log = (...args: unknown[]) => { printed.push(args.join(" ")); };
    try {
      await actions.get("ahp login")!("a");
      expect(globalThis.process.exitCode).toBe(1);
    } finally {
      console.log = log;
      // Bun ignores `exitCode = undefined`, which would fail the whole run.
      globalThis.process.exitCode = exitCode ?? 0;
    }
    expect(prepared).toBe(0);
    expect(printed).toHaveLength(1);
    expect(printed[0]).toContain(`No Gateway answers at http://127.0.0.1:${port}`);
    for (const name of ["OPENCLAW_GATEWAY_PORT", "gateway.port", "publicUrl"]) expect(printed[0]).toContain(name);
    expect(printed.join("\n")).not.toContain("/authorize");
    expect(await gatewayStopped({ redirectUri, loopbackUri: redirectUri })).toBe(printed[0]);
  });
});
