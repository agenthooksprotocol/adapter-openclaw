// Browser sign-in for the backends in hooks.json. Every backend has its own OAuth
// state: one consent covers that backend's endpoints (its grant partition is its
// id), and is never shared with another backend.
//
// Deliveries never start a login. Only `openclaw ahp login` does, and only its
// terminal shows the link: not the Gateway log, which any operator with read
// access can tail, and never a chat reply, which OpenClaw keeps in the transcript
// the model reads. Whoever opens a link binds their account to this Gateway.
//
// The browser returns to the Gateway's own route, not to the CLI that started the
// login. So pending logins are kept in the shared store (the SDK's
// `persistPendingLogins`): the Gateway completes a login `openclaw ahp login`
// prepared, by its state, and its own Hooks then tries a backend it skipped again.
//
// A step-up (a delivery's 403 insufficient_scope) is seen by the Gateway, and signed
// in to by the CLI: the scopes it asked for are kept in plugin state per backend
// until a grant that covers them is stored.
import { createHash } from "node:crypto";
import { auth, AuthError, type DeliveryAuthContext, type DeliveryAuthProvider } from "agenthooksprotocol/client";
import { bindingKey, frame, managedOAuth, type ClientConfig, type PendingLogin, type SecretStore, type StoredRecord, type TokenStore } from "agenthooksprotocol/oauth";
import { checkDestination, policyFetch } from "./network.js";
import { resolveSecret } from "./secrets.js";
import { backendSettings, trustedIssuer, type BackendSettings } from "./settings.js";
import type { ComparingStore, KeyedStore } from "./store.js";

export const CALLBACK_PATH = "/ahp/oauth/callback";
export const NAMESPACE = "openclaw";
const DEFAULT_PORT = 18789;
const PREPARE_MS = 120_000;
const DELIVERY_MS = 30_000;
const CONFLICT_RETRIES = 5;

/** `plugins.entries.agent-hooks-protocol.config`: what is OpenClaw's alone. A
 * backend's OAuth settings are its `oauth` object in hooks.json, as for every harness. */
export interface PluginSettings {
  /** The Gateway as a browser reaches it, when not at 127.0.0.1 (a proxy, Tailscale). */
  publicUrl?: string;
  /** Values for `tokenRef`, `clientSecretRef` and `initialAccessTokenRef`, by reference:
   * a literal, or an OpenClaw SecretRef to an environment variable or a file. */
  secrets?: Record<string, unknown>;
}

type Backend = Record<string, unknown> & { id: string };
export type Status =
  | { state: "authorized" }
  | { state: "client-credentials" }
  | { state: "bearer" }
  | { state: "needs-login"; url?: string; expiresAt?: number; scopes?: readonly string[] }
  | { state: "failing"; reason: string }
  | { state: "not-configured" };

export interface LoginHost {
  store: TokenStore;
  /** Scopes a step-up asked for, by backend id, space-separated and sorted: shared
   * with the CLI, which signs in for them. Changed only by compare-and-apply: the
   * Gateway and the CLI both write it. */
  stepUps: ComparingStore<string>;
  /** Logins completed, by digest of their state, holding the backend id: rows that
   * expire soon after. `openclaw ahp login` reads them, whichever process completed it. */
  completions: KeyedStore<string>;
  secrets: SecretStore;
  settings: PluginSettings;
  environment: Record<string, string | undefined>;
  /** The Gateway's port, as OpenClaw's own CLI resolves it: a sign-in returns there. */
  port: () => number;
  backends: () => Backend[];
  log: (text: string) => void;
  warn: (text: string) => void;
}

/** The Gateway's port as OpenClaw's CLI resolves it: OPENCLAW_GATEWAY_PORT, then `gateway.port`. */
export function configuredPort(config: { gateway?: { port?: unknown } } | undefined, environment: Record<string, string | undefined>): number {
  const env = Number(environment.OPENCLAW_GATEWAY_PORT);
  if (Number.isInteger(env) && env > 0) return env;
  const port = config?.gateway?.port;
  return typeof port === "number" && port > 0 ? port : DEFAULT_PORT;
}

/** `publicUrl`: HTTPS, or HTTP on a loopback IP literal (RFC 8252: not `localhost`); no credentials, query or
 * fragment. A path prefix is kept: `https://host/gw` redirects to
 * `https://host/gw/ahp/oauth/callback`, for a proxy that strips it. */
export function publicBase(value: unknown): { base?: string; problem?: string } {
  if (value === undefined) return {};
  let url: URL;
  try { url = new URL(String(value)); } catch { return { problem: "publicUrl is not a URL; ignored" }; }
  const loopback = ["127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return { problem: "publicUrl is not https (or http on 127.0.0.1 or [::1]); ignored" };
  if (url.username || url.password || url.search || url.hash) return { problem: "publicUrl has credentials, a query or a fragment; ignored" };
  return { base: `${url.origin}${url.pathname.replace(/\/+$/, "")}` };
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function budget(ms: number, signal?: AbortSignal) {
  const timeout = AbortSignal.timeout(ms);
  return { signal: signal ? AbortSignal.any([signal, timeout]) : timeout, deadline: Date.now() + ms };
}

/** Scopes as kept in plugin state: deduplicated, sorted, space-separated. */
const joinScopes = (scopes: readonly string[]) => [...new Set(scopes)].sort().join(" ");
const splitScopes = (kept: string | undefined): readonly string[] => kept?.split(" ").filter(Boolean) ?? [];

/** The SDK's key for one pending login, by its state. */
const pendingKey = (state: string) => frame("ahp.oauth.pending:", [NAMESPACE, state]);

/** A completed login's row: by digest, as the state is not kept anywhere else. */
const completionKey = (state: string) => `done:${createHash("sha256").update(state).digest("hex")}`;
/** A completion row outlives the link it answers by this long. */
const COMPLETION_MS = 60_000;

const describe = (error: unknown) => error instanceof AuthError ? error.code : error instanceof Error ? error.message : String(error);

export class Logins {
  readonly #host: LoginHost;
  /** One managed OAuth per backend, for its own lifetime and network settings. All
   * share one store and namespace. */
  readonly #backends = new Map<string, { settings: BackendSettings; oauth: ReturnType<typeof managedOAuth>; route: DeliveryAuthProvider }>();
  /** Backends a delivery or initialization said need a login, with the scopes it asked for. */
  readonly #needed = new Map<string, readonly string[] | undefined>();
  /** Backends the Gateway log has said need a sign-in: once, until signed in. */
  readonly #hinted = new Set<string>();
  /** Logins this process prepared, by backend, with the scopes each required: reused
   * while valid. Only this process shows their links. */
  readonly #links = new Map<string, PendingLogin & { requiredScopes: readonly string[] }>();
  readonly #checking = new Set<string>();
  /** Failures to resume a backend signed in to elsewhere, already warned of, by backend and code. */
  readonly #warned = new Set<string>();
  readonly #publicBase: string | undefined;
  /** Backends initialization skipped for want of a login: Hooks re-attempts one after a prepare or completion in this process. */
  readonly initializationFailed = new Set<string>();
  /** Hooks' listeners for prepared endpoints, fed by every backend's managed OAuth. */
  readonly #prepared = new Set<(endpoint: { backendId: string; purpose: "event" | "upload"; url: string }) => void>();

  constructor(host: LoginHost) {
    if (typeof host.stepUps.observe !== "function" || typeof host.stepUps.compareAndApply !== "function") throw new Error("this OpenClaw has no compare-and-apply plugin state");
    this.#host = host;
    const { base, problem } = publicBase(host.settings.publicUrl);
    if (problem) host.warn(`Agent Hooks Protocol: ${problem}`);
    this.#publicBase = base;
  }

  /** A backend's settings and managed OAuth; problems with its `oauth` are warned once. */
  #for(id: string) {
    let entry = this.#backends.get(id);
    if (entry) return entry;
    const backend = this.backend(id) ?? { id };
    const { settings, problems } = backendSettings(backend);
    for (const problem of problems) this.#host.warn(`Agent Hooks Protocol: ${problem}`);
    const oauth = managedOAuth({
      namespace: NAMESPACE,
      store: this.#host.store,
      secrets: this.#host.secrets,
      policyFetch: policyFetch(settings.allowPrivateNetwork),
      checkDestination: checkDestination(settings.allowPrivateNetwork),
      selectClient: (issuers, resource, context, operation) => {
        operation.signal.throwIfAborted();
        return this.selectClient(issuers, resource, context);
      },
      loginLifetimeMs: settings.loginLifetimeMs,
      // `openclaw ahp login` prepares; the Gateway's route (or a pasted address) completes.
      persistPendingLogins: true,
    });
    entry = { settings, oauth, route: oauth.provider({ budget: (context) => budget(DELIVERY_MS, context.signal) }) };
    entry.route.onPrepared?.((endpoint) => {
      for (const listener of [...this.#prepared]) listener(endpoint);
    });
    this.#backends.set(id, entry);
    return entry;
  }

  /** Routes each delivery to its own backend's managed OAuth. */
  readonly #route: DeliveryAuthProvider = {
    credential: (context) => this.#for(context.backendId).route.credential(context),
    challenge: (context) => this.#for(context.backendId).route.challenge(context),
    // A prepared sign-in lets Hooks try a backend it skipped at initialization again.
    onPrepared: (listener) => {
      this.#prepared.add(listener);
      return () => { this.#prepared.delete(listener); };
    },
  };

  /** A backend's managed OAuth: its own settings, the shared store. */
  protected managed(backendId: string): ReturnType<typeof managedOAuth> {
    return this.#for(backendId).oauth;
  }

  /** The stored credential for an endpoint, renewed if it can be without a person. */
  protected credential(context: DeliveryAuthContext) {
    return this.#route.credential({ ...context, signal: AbortSignal.timeout(DELIVERY_MS) });
  }

  /** Each login's redirect: the Gateway's route, at `publicUrl` or on its loopback port. */
  get redirectUri(): string {
    return this.#publicBase ? `${this.#publicBase}${CALLBACK_PATH}` : this.loopbackUri;
  }

  /** The Gateway's route on its loopback port, which `openclaw ahp` on its host can
   * reach even where the host cannot reach its own `publicUrl`. */
  get loopbackUri(): string {
    return `http://127.0.0.1:${this.#host.port()}${CALLBACK_PATH}`;
  }

  resolveReference(reference: string): string | undefined {
    return resolveSecret(this.#host.settings.secrets?.[reference], this.#host.environment);
  }

  /** Bearer bindings as before; OAuth presets and OAuth-protected endpoints through managed OAuth. */
  provider(): DeliveryAuthProvider {
    const resolveCredentialReference = (reference: string) => this.resolveReference(reference);
    return auth.compose({ bearer: auth.bearer({ resolveCredentialReference }), oauth: this.#route, discover: this.#route });
  }

  /** Local trust policy: only a backend the operator set up for OAuth, at the issuer
   * they named. The `oauth` object's settings take precedence over the preset's. */
  selectClient(issuers: readonly string[], resource: string, context: DeliveryAuthContext): ClientConfig {
    const settings = this.#for(context.backendId).settings;
    const preset = context.authentication?.type === "oauth" ? context.authentication : undefined;
    if (!settings.configured && !preset) throw new AuthError("access_denied");
    const flow = (settings.flow ?? preset?.flow ?? "authorization_code_pkce") as ClientConfig["flow"];
    const clientId = settings.clientId ?? preset?.clientId;
    const secretRef = settings.clientSecretRef ?? preset?.clientSecretRef;
    const issuer = trustedIssuer({
      configured: settings.issuer ?? preset?.issuer,
      trustAdvertised: settings.trustAdvertisedIssuer,
      flow,
      confidential: secretRef !== undefined || flow === "client_credentials",
      advertised: issuers,
    });
    if (!issuer) throw new AuthError("access_denied");
    const secret = secretRef === undefined ? undefined : this.resolveReference(secretRef);
    // A named secret that does not resolve is not a public client.
    if (secretRef !== undefined && secret === undefined) throw new AuthError("credential_unavailable");
    const registration = settings.registration;
    return {
      issuer,
      resource: preset?.resource ?? resource,
      flow,
      scopes: settings.scopes ?? preset?.scopes ?? [],
      // One consent per backend, for its event and upload endpoints alike.
      grantPartition: context.backendId,
      ...(clientId ? { clientId } : {}),
      ...(secret ? { clientSecret: secret } : {}),
      ...(settings.clientMetadataDocument ? { clientMetadataDocument: settings.clientMetadataDocument } : {}),
      ...(registration ? {
        registration: {
          clientName: registration.clientName ?? "OpenClaw (Agent Hooks Protocol)",
          softwareId: "@agenthooksprotocol/adapter-openclaw",
          ...(registration.scopes ? { scopes: registration.scopes } : {}),
          ...(registration.initialAccessTokenRef ? { initialAccessTokenRef: registration.initialAccessTokenRef } : {}),
        },
      } : {}),
    };
  }

  /** The secret hook: the operator's references from plugin config, and issued
   * secrets in their own files. */
  static secrets(files: SecretStore, settings: PluginSettings, environment: Record<string, string | undefined>): SecretStore {
    return {
      put: (reference, secret, signal) => files.put(reference, secret, signal),
      delete: (reference, signal) => files.delete(reference, signal),
      async get(reference, signal) {
        const configured = settings.secrets?.[reference];
        return configured !== undefined ? resolveSecret(configured, environment) : files.get(reference, signal);
      },
    };
  }

  backend(id: string): Backend | undefined {
    return this.#host.backends().find((backend) => backend.id === id);
  }

  /** The event endpoint's auth context, for HTTP backends. */
  context(backend: Backend): DeliveryAuthContext | undefined {
    const transport = backend.transport as { type?: string; url?: string } | undefined;
    if (transport?.type !== "http" || typeof transport.url !== "string") return undefined;
    return {
      backendId: backend.id,
      purpose: "event",
      url: transport.url,
      ...(object(backend.authentication) ? { authentication: backend.authentication as never } : {}),
    };
  }

  /** How a backend authenticates, before anything is asked of the network. */
  kind(backend: Backend): "bearer" | "client-credentials" | "login" | "none" | "stdio" {
    if (!this.context(backend)) return "stdio";
    const headers = (backend.transport as { headers?: Record<string, unknown> }).headers ?? {};
    const binding = backend.authentication as { type?: string; flow?: string } | undefined;
    if (binding?.type === "bearer" || Object.keys(headers).some((name) => name.toLowerCase() === "authorization")) return "bearer";
    const settings = this.#for(backend.id).settings;
    if (binding?.type === "oauth" || settings.configured) {
      return (settings.flow ?? binding?.flow) === "client_credentials" ? "client-credentials" : "login";
    }
    return "none";
  }

  /** A delivery or initialization diagnostic with `recovery: "login"`. Scopes it asks
   * for are kept for `openclaw ahp login`, added to any not yet signed in for. */
  needsLogin(backendId: string, requiredScopes?: readonly string[]): Promise<void> {
    const needed = this.#needed.get(backendId);
    this.#needed.set(backendId, requiredScopes?.length ? splitScopes(joinScopes([...needed ?? [], ...requiredScopes])) : needed);
    if (!requiredScopes?.length) return Promise.resolve();
    return this.#changeStepUp(backendId, (kept) => [...kept, ...requiredScopes])
      .catch((error) => this.#host.warn(`Agent Hooks Protocol: ${backendId}: could not keep the scopes it asks for (${describe(error)})`));
  }

  /** The scopes a step-up asked for that no stored grant covers yet. */
  async stepUp(backendId: string): Promise<readonly string[]> {
    return splitScopes(await this.#host.stepUps.lookup(backendId));
  }

  /** Change a backend's step-up scopes in one compare-and-apply, so a step-up the
   * other process records in between is never lost; no scopes left deletes the row. */
  async #changeStepUp(backendId: string, change: (kept: readonly string[]) => readonly string[]): Promise<void> {
    const stepUps = this.#host.stepUps;
    for (let attempt = 0; attempt < CONFLICT_RETRIES; attempt += 1) {
      const seen = await stepUps.observe(backendId);
      const next = joinScopes(change(splitScopes(seen.value)));
      if (next === (seen.value ?? "")) return;
      const result = await stepUps.compareAndApply(backendId, seen.comparison, next
        ? { operation: "update", action: "set", value: next }
        : { operation: "delete", action: "delete" });
      if (result.status !== "conflict") return;
    }
    throw new Error("step-up scopes kept changing");
  }

  /** A grant covering `granted` is stored: forget those scopes of a step-up. Any
   * asked for since are kept. */
  async #steppedUp(backendId: string, granted: readonly string[]): Promise<void> {
    if (!granted.length) return;
    try {
      await this.#changeStepUp(backendId, (kept) => kept.filter((scope) => !granted.includes(scope)));
    } catch (error) {
      this.#host.warn(`Agent Hooks Protocol: ${backendId}: signed in, but could not clear the scopes it asked for (${describe(error)})`);
    }
  }

  /** The login this process prepared for a backend, while it is valid. */
  #link(backendId: string) {
    const link = this.#links.get(backendId);
    if (link && link.expiresAt > Date.now()) return link;
    this.#links.delete(backendId);
    return undefined;
  }

  /** The stored credential, renewed if it can be without a person. Never starts a login. */
  async status(backend: Backend): Promise<Status> {
    const context = this.context(backend);
    const kind = this.kind(backend);
    if (!context || kind === "stdio" || kind === "bearer") return kind === "bearer" ? { state: "bearer" } : { state: "not-configured" };
    try {
      const credential = await this.credential(context);
      if (credential && kind === "client-credentials") return { state: "client-credentials" };
      if (credential) {
        // Signed in, but not for what a delivery has since asked for.
        const scopes = await this.stepUp(backend.id);
        if (!scopes.length) return { state: "authorized" };
        const link = this.#link(backend.id);
        return { state: "needs-login", scopes, ...(link ? { url: link.authorizationUrl, expiresAt: link.expiresAt } : {}) };
      }
      // Nothing stored: a backend set up for sign-in has not been signed in to.
      if (kind === "none" && !this.#needed.has(backend.id)) return { state: "not-configured" };
      if (kind === "client-credentials") return { state: "client-credentials" };
    } catch (error) {
      if (!(error instanceof AuthError) || error.recovery !== "login") return { state: "failing", reason: describe(error) };
    }
    if (kind === "none") return { state: "failing", reason: "it asks for OAuth: give it an `oauth` object in hooks.json" };
    const link = this.#link(backend.id);
    return { state: "needs-login", ...(link ? { url: link.authorizationUrl, expiresAt: link.expiresAt } : {}) };
  }

  /** Start a backend's login, or reuse the one this process started. Ready when its grant is usable. */
  async login(backendId: string): Promise<{ type: "ready" } | { type: "pending"; url: string; expiresAt: number; state: string; requiredScopes: readonly string[] }> {
    const backend = this.backend(backendId);
    const context = backend && this.context(backend);
    if (!context) throw new Error(`${backendId} is not an HTTP backend in hooks.json`);
    let link = this.#link(backendId);
    if (!link) {
      // A step-up the Gateway saw, in whichever process this is.
      const requiredScopes = [...new Set([...(this.#needed.get(backendId) ?? []), ...await this.stepUp(backendId)])];
      let result;
      try {
        result = await this.managed(backendId).prepare(context, budget(PREPARE_MS), { redirectUri: this.redirectUri, ...(requiredScopes.length ? { requiredScopes } : {}) });
      } catch (error) {
        // Scopes this backend's settings do not allow, which the SDK names: kept from a
        // step-up, asking again would be refused every time. Any other refusal (no
        // OAuth settings, an untrusted issuer) is not about scopes.
        if (error instanceof AuthError && error.code === "access_denied" && error.requiredScopes?.length) {
          throw new Error(`${backendId} asked for scopes its OAuth settings do not allow (${error.requiredScopes.join(" ")}): run \`openclaw ahp logout ${backendId}\` to forget them, or add them to its \`oauth.scopes\` in hooks.json`, { cause: error });
        }
        throw error;
      }
      if (result.type === "ready") {
        // The stored grant covers every scope asked for.
        await this.#steppedUp(backendId, requiredScopes);
        this.#ready(backendId);
        return { type: "ready" };
      }
      this.#links.set(backendId, (link = { ...result, requiredScopes }));
    }
    return { type: "pending", url: link.authorizationUrl, expiresAt: link.expiresAt, state: link.state, requiredScopes: link.requiredScopes };
  }

  /** Whether the login `login` returned has completed, in whichever process: the
   * backend is authorized, or that login's completion was recorded. A step-up the
   * Gateway recorded since does not make it look unfinished, and a login that was
   * refused, evicted or expired never looks finished. */
  async finished(backend: Backend, login: { state: string }): Promise<boolean> {
    if ((await this.status(backend)).state === "authorized") return true;
    return (await this.#host.completions.lookup(completionKey(login.state))) === backend.id;
  }

  /** The backends to sign in to: every HTTP backend that needs it, never one with a usable grant. */
  async waiting(): Promise<Backend[]> {
    const backends: Backend[] = [];
    for (const backend of this.#host.backends()) {
      const kind = this.kind(backend);
      if (kind !== "login" && !(kind === "none" && this.#needed.has(backend.id))) continue;
      if ((await this.status(backend)).state === "needs-login") backends.push(backend);
    }
    return backends;
  }

  /** At the start of a turn, in the background: say once in the Gateway log which
   * backends need a sign-in. Never awaited by the turn, and never prepares a login:
   * its link could be shown nowhere private. */
  hint(): Promise<void> {
    const work: Promise<void>[] = [];
    for (const backend of this.#host.backends()) {
      const kind = this.kind(backend);
      if (kind !== "login" && !(kind === "none" && this.#needed.has(backend.id))) continue;
      if (this.#checking.has(backend.id)) continue;
      this.#checking.add(backend.id);
      work.push((async () => {
        const status = await this.status(backend);
        if (status.state === "needs-login") return this.show(backend.id);
        // Signed in from a pasted address in another process, which told only its own
        // Hooks. One prepare here finds the grant without a request, and lets this
        // Gateway's Hooks try the skipped backend again.
        if (status.state === "authorized" && this.initializationFailed.has(backend.id)) {
          await this.login(backend.id);
          this.initializationFailed.delete(backend.id);
        }
        this.#ready(backend.id);
      })().catch((error) => {
        const key = `${backend.id}\0${describe(error)}`;
        if (this.#warned.has(key)) return;
        this.#warned.add(key);
        this.#host.warn(`Agent Hooks Protocol: ${backend.id}: signed in, but could not be resumed (${describe(error)})`);
      }).finally(() => this.#checking.delete(backend.id)));
    }
    return Promise.all(work).then(() => {});
  }

  /** In the Gateway log: that a backend needs a sign-in, once until it is signed in. */
  show(backendId: string): void {
    if (this.#hinted.has(backendId)) return;
    this.#hinted.add(backendId);
    this.#host.warn(`Agent Hooks Protocol: sign-in needed for ${backendId}: run \`openclaw ahp login ${backendId}\` on the Gateway's host`);
  }

  #ready(backendId: string): void {
    this.#needed.delete(backendId);
    this.#hinted.delete(backendId);
    this.#links.delete(backendId);
  }

  /** The browser came back, to the Gateway or pasted: complete the stored login its
   * state names, whichever process prepared it, with its own backend's settings. */
  async complete(callback: string): Promise<string> {
    const state = new URL(callback).searchParams.get("state");
    const record = state ? await this.#host.store.load(pendingKey(state), AbortSignal.timeout(DELIVERY_MS)) : undefined;
    const backendId = record?.kind === "pending_login" ? record.context.backendId : undefined;
    if (!backendId || !this.backend(backendId)) throw new AuthError("interaction_required");
    await this.managed(backendId).complete(callback, budget(DELIVERY_MS));
    // For `openclaw ahp login`, which waits on this login, whichever process it runs in.
    const ttlMs = Math.max(0, (record?.kind === "pending_login" ? record.expiresAt : Date.now()) - Date.now()) + COMPLETION_MS;
    await this.#host.completions.register(completionKey(state!), backendId, { ttlMs })
      .catch((error) => this.#host.warn(`Agent Hooks Protocol: ${backendId}: signed in, but could not record it (${describe(error)})`));
    // Completed: the grant covers the scopes this login required.
    await this.#steppedUp(backendId, record?.kind === "pending_login" ? record.client.requiredScopes ?? [] : []);
    this.#ready(backendId);
    this.initializationFailed.delete(backendId);
    return backendId;
  }

  /** Cancel a backend's pending logins, whichever process prepared them, and delete
   * its grant and the scopes a step-up asked for. Its binding stays, so its next
   * delivery knows it needs a login again. Says which of them were there: a login
   * still pending or a grant, and step-up scopes. */
  async logout(backendId: string): Promise<{ signedOut: boolean; forgotScopes: boolean }> {
    const backend = this.backend(backendId);
    const context = backend && this.context(backend);
    if (!context) throw new Error(`${backendId} is not an HTTP backend in hooks.json`);
    const operation = budget(DELIVERY_MS);
    const store = this.#host.store;
    const binding = await store.load(bindingKey(NAMESPACE, context), operation.signal);
    let removed = false;
    const grantKey = binding?.kind === "binding" ? binding.grantKey : undefined;
    if (grantKey) {
      const index = await store.load(frame("ahp.oauth.pending-index:", [grantKey]), operation.signal);
      for (const state of index?.kind === "pending_index" ? index.states : []) {
        // An expired login is still in the index, but there is nothing of it to cancel.
        if ((await store.load(pendingKey(state), operation.signal))?.kind === "pending_login") removed = true;
        await this.managed(backendId).cancel({ type: "pending_login", state, authorizationUrl: "", expiresAt: 0 }, operation);
      }
      removed = await store.coordinate(grantKey, operation.signal, async () => {
        const grant: StoredRecord | undefined = await store.load(grantKey, operation.signal);
        return grant ? store.compareAndSet(grantKey, grant.generation, undefined, operation.signal) : false;
      }) || removed;
    }
    // Scopes a step-up asked for go too: settings that no longer allow them would
    // otherwise refuse every sign-in.
    const forgotScopes = (await this.stepUp(backendId)).length > 0;
    if (forgotScopes) await this.#changeStepUp(backendId, () => []);
    // Still known to need a login, but for no scopes in particular.
    if (this.#needed.has(backendId)) this.#needed.set(backendId, undefined);
    this.#hinted.delete(backendId);
    this.#links.delete(backendId);
    return { signedOut: removed, forgotScopes };
  }
}
