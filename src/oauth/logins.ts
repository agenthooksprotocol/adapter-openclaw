// Browser sign-in for the backends in hooks.json. Every backend has its own OAuth
// state: one consent covers that backend's endpoints (its grant partition is its
// id), and is never shared with another backend.
//
// Deliveries never start a login. One starts only from host code: the hint at the
// start of a turn, `/ahp login`, or `openclaw ahp login`. A link is shown only
// where the operator alone reads it: the Gateway log and the `openclaw ahp`
// terminal. Never a chat reply: OpenClaw keeps those in the transcript the model
// reads, and on a shared channel others would see it too. Whoever opens a link
// binds their account to this Gateway.
import { auth, AuthError, type DeliveryAuthContext, type DeliveryAuthProvider } from "agenthooksprotocol/client";
import { bindingKey, frame, managedOAuth, type ClientConfig, type PendingLogin, type SecretStore, type StoredRecord, type TokenStore } from "agenthooksprotocol/oauth";
import { checkDestination, policyFetch } from "./network.js";
import { resolveSecret } from "./secrets.js";
import { backendSettings, trustedIssuer, type BackendSettings } from "./settings.js";

export const CALLBACK_PATH = "/ahp/oauth/callback";
export const NAMESPACE = "openclaw";
const DEFAULT_PORT = 18789;
const PREPARE_MS = 120_000;
const DELIVERY_MS = 30_000;

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
  | { state: "needs-login"; url?: string; expiresAt?: number }
  | { state: "failing"; reason: string }
  | { state: "not-configured" };

export interface LoginHost {
  store: TokenStore;
  secrets: SecretStore;
  settings: PluginSettings;
  environment: Record<string, string | undefined>;
  /** The port the Gateway listens on: known inside it once it has started. */
  livePort: () => number | undefined;
  /** The port config names, for a process that is not the Gateway. */
  configuredPort: () => number;
  /** Where the Gateway records its live redirect, for `openclaw ahp` to use the same. */
  redirects?: { lookup(key: string): Promise<string | undefined>; register(key: string, value: string): Promise<void> };
  backends: () => Backend[];
  log: (text: string) => void;
  warn: (text: string) => void;
}

/** The Gateway's port as OpenClaw resolves it, for a process that is not the Gateway. */
export function configuredPort(config: { gateway?: { port?: unknown } } | undefined, environment: Record<string, string | undefined>): number {
  const env = Number(environment.OPENCLAW_GATEWAY_PORT);
  if (Number.isInteger(env) && env > 0) return env;
  const port = config?.gateway?.port;
  return typeof port === "number" && port > 0 ? port : DEFAULT_PORT;
}

/** `publicUrl`: HTTPS, or HTTP on a loopback literal; no credentials, query or
 * fragment. A path prefix is kept: `https://host/gw` redirects to
 * `https://host/gw/ahp/oauth/callback`, for a proxy that strips it. */
export function publicBase(value: unknown): { base?: string; problem?: string } {
  if (value === undefined) return {};
  let url: URL;
  try { url = new URL(String(value)); } catch { return { problem: "publicUrl is not a URL; ignored" }; }
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return { problem: "publicUrl is not https (or http on a loopback address); ignored" };
  if (url.username || url.password || url.search || url.hash) return { problem: "publicUrl has credentials, a query or a fragment; ignored" };
  return { base: `${url.origin}${url.pathname.replace(/\/+$/, "")}` };
}

const REDIRECT_KEY = "gateway-redirect";

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function budget(ms: number, signal?: AbortSignal) {
  const timeout = AbortSignal.timeout(ms);
  return { signal: signal ? AbortSignal.any([signal, timeout]) : timeout, deadline: Date.now() + ms };
}

const describe = (error: unknown) => error instanceof AuthError ? error.code : error instanceof Error ? error.message : String(error);

export class Logins {
  readonly #host: LoginHost;
  /** One managed OAuth per backend, for its own lifetime and network settings. All
   * share one store and namespace. */
  readonly #backends = new Map<string, { settings: BackendSettings; oauth: ReturnType<typeof managedOAuth>; route: DeliveryAuthProvider }>();
  /** Backends a delivery or initialization said need a login, with the scopes it asked for. */
  readonly #needed = new Map<string, readonly string[] | undefined>();
  /** The last link logged for a backend: repeated turns show the same one once. */
  readonly #shown = new Map<string, string>();
  readonly #checking = new Set<string>();
  /** Failures to prepare a sign-in already warned of, by backend and code. */
  readonly #warned = new Set<string>();
  readonly #publicBase: string | undefined;
  /** The Gateway's recorded redirect, read by a process that is not the Gateway. */
  #savedRedirect: string | undefined;
  /** Backends initialization skipped for authentication: Hooks re-attempts their configuration after a login is prepared. */
  readonly initializationFailed = new Set<string>();
  /** Hooks' listeners for prepared endpoints, fed by every backend's managed OAuth. */
  readonly #prepared = new Set<(endpoint: { backendId: string; purpose: "event" | "upload"; url: string }) => void>();

  constructor(host: LoginHost) {
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

  /** Stable per grant: a pending login is reused only for the same redirect. The
   * Gateway's live port wins; `openclaw ahp` uses what the Gateway recorded, then config. */
  get redirectUri(): string {
    if (this.#publicBase) return `${this.#publicBase}${CALLBACK_PATH}`;
    const live = this.#host.livePort();
    if (live) return `http://127.0.0.1:${live}${CALLBACK_PATH}`;
    return this.#savedRedirect ?? `http://127.0.0.1:${this.#host.configuredPort()}${CALLBACK_PATH}`;
  }

  /** In the Gateway, once it listens: record the redirect it answers. */
  async recordRedirect(): Promise<void> {
    if (this.#host.livePort()) await this.#host.redirects?.register(REDIRECT_KEY, this.redirectUri);
  }

  /** Outside the Gateway: use the redirect it recorded. */
  async loadRedirect(): Promise<void> {
    const saved = await this.#host.redirects?.lookup(REDIRECT_KEY);
    if (typeof saved === "string" && saved.endsWith(CALLBACK_PATH)) this.#savedRedirect = saved;
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
      ...(flow === "authorization_code_pkce" ? { redirectUri: this.redirectUri } : {}),
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

  /** A delivery or initialization diagnostic with `recovery: "login"`. */
  needsLogin(backendId: string, requiredScopes?: readonly string[]): void {
    this.#needed.set(backendId, requiredScopes);
  }

  /** The stored pending login for a backend, while it is valid. */
  async pending(context: DeliveryAuthContext): Promise<(PendingLogin & { state: string }) | undefined> {
    const key = frame("ahp.oauth.pending:", [bindingKey(NAMESPACE, context)]);
    const record = await this.#host.store.load(key, AbortSignal.timeout(DELIVERY_MS));
    if (record?.kind !== "pending_login" || record.expiresAt <= Date.now()) return undefined;
    return { type: "pending_login", authorizationUrl: record.authorizationUrl, expiresAt: record.expiresAt, key, id: record.id, state: record.state };
  }

  /** The stored credential, renewed if it can be without a person. Never starts a login. */
  async status(backend: Backend): Promise<Status> {
    const context = this.context(backend);
    const kind = this.kind(backend);
    if (!context || kind === "stdio" || kind === "bearer") return kind === "bearer" ? { state: "bearer" } : { state: "not-configured" };
    try {
      const credential = await this.#route.credential({ ...context, signal: AbortSignal.timeout(DELIVERY_MS) });
      if (credential) return kind === "client-credentials" ? { state: "client-credentials" } : { state: "authorized" };
      // Nothing stored: a backend set up for sign-in has not been signed in to.
      if (kind === "none" && !this.#needed.has(backend.id)) return { state: "not-configured" };
      if (kind === "client-credentials") return { state: "client-credentials" };
    } catch (error) {
      if (!(error instanceof AuthError) || error.recovery !== "login") return { state: "failing", reason: describe(error) };
    }
    if (kind === "none") return { state: "failing", reason: "it asks for OAuth: give it an `oauth` object in hooks.json" };
    const pending = await this.pending(context).catch(() => undefined);
    return { state: "needs-login", ...(pending ? { url: pending.authorizationUrl, expiresAt: pending.expiresAt } : {}) };
  }

  /** Start, or reuse, a backend's login. Ready when its grant is usable. */
  async login(backendId: string): Promise<{ type: "ready" } | { type: "pending"; url: string; expiresAt: number }> {
    const backend = this.backend(backendId);
    const context = backend && this.context(backend);
    if (!context) throw new Error(`${backendId} is not an HTTP backend in hooks.json`);
    const requiredScopes = this.#needed.get(backendId);
    const result = await this.#for(backendId).oauth.prepare(context, budget(PREPARE_MS), requiredScopes ? { requiredScopes } : {});
    if (result.type === "ready") {
      this.#ready(backendId);
      return { type: "ready" };
    }
    return { type: "pending", url: result.authorizationUrl, expiresAt: result.expiresAt };
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

  /** At the start of a turn: prepare, in the background, the logins backends need, and
   * log each link once. Never awaited by the turn. */
  hint(): Promise<void> {
    const work: Promise<void>[] = [];
    for (const backend of this.#host.backends()) {
      const kind = this.kind(backend);
      if (kind !== "login" && !(kind === "none" && this.#needed.has(backend.id))) continue;
      if (this.#checking.has(backend.id)) continue;
      this.#checking.add(backend.id);
      work.push((async () => {
        const status = await this.status(backend);
        if (status.state !== "needs-login") {
          // Signed in in another process (`openclaw ahp`): its prepare notified only that
          // process's Hooks. One prepare here, which finds the grant and makes no request,
          // lets this Gateway's Hooks try the skipped backend again.
          if (status.state === "authorized" && this.initializationFailed.delete(backend.id)) await this.login(backend.id);
          return this.#ready(backend.id);
        }
        this.#host.log(`${backend.id}: preparing a sign-in`);
        const result = await this.login(backend.id);
        if (result.type === "pending") this.show(backend.id, result.url);
      })().catch((error) => {
        const key = `${backend.id}\0${describe(error)}`;
        if (this.#warned.has(key)) return;
        this.#warned.add(key);
        this.#host.warn(`Agent Hooks Protocol: ${backend.id}: a sign-in could not be prepared (${describe(error)})`);
      }).finally(() => this.#checking.delete(backend.id)));
    }
    return Promise.all(work).then(() => {});
  }

  /** Inside the Gateway: that a sign-in is needed, once per link. The link itself is
   * shown only on the Gateway host's terminal, by `openclaw ahp`: the Gateway's log is
   * readable to any operator with read access. */
  show(backendId: string, url: string): void {
    if (this.#shown.get(backendId) === url) return;
    this.#shown.set(backendId, url);
    this.#host.warn(`Agent Hooks Protocol: sign-in needed for ${backendId}: run \`openclaw ahp login ${backendId}\` on the Gateway's host`);
  }

  #ready(backendId: string): void {
    this.#needed.delete(backendId);
    this.#shown.delete(backendId);
  }

  /** The browser came back: whichever backend's stored login it answers. Any process
   * sharing the store may complete a login another process started. */
  async complete(callback: string): Promise<string> {
    const state = new URL(callback).searchParams.get("state");
    if (state) {
      for (const backend of this.#host.backends()) {
        const context = this.context(backend);
        const pending = context && await this.pending(context);
        if (!pending || pending.state !== state) continue;
        const { state: _state, ...handle } = pending;
        await this.finish(backend.id, handle, callback);
        this.#ready(backend.id);
        this.initializationFailed.delete(backend.id);
        return backend.id;
      }
    }
    throw new AuthError("interaction_required");
  }

  /** Exchange the callback for the login it answers. */
  protected async finish(backendId: string, handle: PendingLogin, callback: string): Promise<void> {
    await this.#for(backendId).oauth.complete(handle, callback, budget(DELIVERY_MS));
  }

  /** Cancel a backend's pending login and delete its grant. Its binding stays, so its
   * next delivery knows it needs a login again. */
  async logout(backendId: string): Promise<boolean> {
    const backend = this.backend(backendId);
    const context = backend && this.context(backend);
    if (!context) throw new Error(`${backendId} is not an HTTP backend in hooks.json`);
    const operation = budget(DELIVERY_MS);
    const pending = await this.pending(context);
    if (pending) {
      const { state: _state, ...handle } = pending;
      await this.#for(backendId).oauth.cancel(handle, operation);
    }
    const store = this.#host.store;
    const binding = await store.load(bindingKey(NAMESPACE, context), operation.signal);
    let removed = Boolean(pending);
    const grantKey = binding?.kind === "binding" ? binding.grantKey : undefined;
    if (grantKey) {
      removed = await store.coordinate(grantKey, operation.signal, async () => {
        const grant: StoredRecord | undefined = await store.load(grantKey, operation.signal);
        return grant ? store.compareAndSet(grantKey, grant.generation, undefined, operation.signal) : false;
      }) || removed;
    }
    this.#shown.delete(backendId);
    return removed;
  }
}
