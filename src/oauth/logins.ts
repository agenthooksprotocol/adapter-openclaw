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
import { allowHosts, checkDestination, policyFetch } from "./network.js";
import { resolveSecret } from "./secrets.js";

export const CALLBACK_PATH = "/ahp/oauth/callback";
export const NAMESPACE = "openclaw";
const DEFAULT_PORT = 18789;
const PREPARE_MS = 120_000;
const DELIVERY_MS = 30_000;

/** `plugins.entries.agent-hooks-protocol.config.oauth.backends.<id>` */
export interface BackendClient {
  /** The authorization server this backend may use. Required: metadata never chooses one. */
  issuer?: string;
  flow?: "authorization_code_pkce" | "client_credentials";
  /** A pre-registered client. It always wins over a metadata document or registration. */
  clientId?: string;
  clientSecret?: unknown;
  scopes?: string[];
  /** A Client ID Metadata Document this operator publishes: its URL is the client id. */
  clientMetadataDocument?: { url: string; redirectUris: string[] };
  /** Permission to register a client dynamically at `issuer`. */
  registration?: boolean | { clientName?: string; scopes?: string[]; initialAccessToken?: unknown };
}

export interface OAuthSettings {
  /** The Gateway as a browser reaches it, when not at 127.0.0.1 (a proxy, Tailscale). */
  publicUrl?: string;
  /** How long a sign-in link stays valid, at most 10 minutes. */
  loginLifetimeMs?: number;
  /** Hosts OAuth may reach at a private or loopback address. */
  allowPrivateHosts?: string[];
  backends?: Record<string, BackendClient>;
}

export interface PluginSettings {
  oauth?: OAuthSettings;
  /** Values for `tokenRef` and `clientSecretRef` in hooks.json, by reference. */
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
  /** Where the Gateway listens: known exactly inside it, from config outside. */
  port: () => number;
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
  readonly oauth: ReturnType<typeof managedOAuth>;
  readonly #route: DeliveryAuthProvider;
  /** Backends a delivery or initialization said need a login, with the scopes it asked for. */
  readonly #needed = new Map<string, readonly string[] | undefined>();
  /** The last link logged for a backend: repeated turns show the same one once. */
  readonly #shown = new Map<string, string>();
  readonly #checking = new Set<string>();
  /** Backends initialization skipped for authentication: their client starts again after a login. */
  readonly initializationFailed = new Set<string>();
  onLogin?: (backendId: string) => void;

  constructor(host: LoginHost) {
    this.#host = host;
    const oauth = host.settings.oauth ?? {};
    const allowed = allowHosts(oauth.allowPrivateHosts);
    this.oauth = managedOAuth({
      namespace: NAMESPACE,
      store: host.store,
      secrets: host.secrets,
      policyFetch: policyFetch(allowed),
      checkDestination: checkDestination(allowed),
      selectClient: (issuers, resource, context, operation) => {
        operation.signal.throwIfAborted();
        return this.selectClient(issuers, resource, context);
      },
      ...(oauth.loginLifetimeMs ? { loginLifetimeMs: oauth.loginLifetimeMs } : {}),
    });
    this.#route = this.oauth.provider({ budget: (context) => budget(DELIVERY_MS, context.signal) });
  }

  get redirectUri(): string {
    const base = this.#host.settings.oauth?.publicUrl;
    return base ? new URL(CALLBACK_PATH, base).href : `http://127.0.0.1:${this.#host.port()}${CALLBACK_PATH}`;
  }

  resolveReference(reference: string): string | undefined {
    return resolveSecret(this.#host.settings.secrets?.[reference], this.#host.environment);
  }

  /** Bearer bindings as before; OAuth presets and OAuth-protected endpoints through managed OAuth. */
  provider(): DeliveryAuthProvider {
    const resolveCredentialReference = (reference: string) => this.resolveReference(reference);
    return auth.compose({ bearer: auth.bearer({ resolveCredentialReference }), oauth: this.#route, discover: this.#route });
  }

  /** Local trust policy: only a backend this operator configured, at the issuer they named. */
  selectClient(issuers: readonly string[], resource: string, context: DeliveryAuthContext): ClientConfig {
    const entry = this.#host.settings.oauth?.backends?.[context.backendId];
    const preset = context.authentication?.type === "oauth" ? context.authentication : undefined;
    if (!entry && !preset) throw new AuthError("access_denied");
    const issuer = preset?.issuer ?? entry?.issuer;
    if (!issuer || !issuers.includes(issuer)) throw new AuthError("access_denied");
    const flow = (preset?.flow ?? entry?.flow ?? "authorization_code_pkce") as ClientConfig["flow"];
    const clientId = preset?.clientId ?? entry?.clientId;
    const secret = preset?.clientSecretRef !== undefined ? this.resolveReference(preset.clientSecretRef) : resolveSecret(entry?.clientSecret, this.#host.environment);
    const registration = entry?.registration === true ? {} : object(entry?.registration) ? entry.registration : undefined;
    return {
      issuer,
      resource: preset?.resource ?? resource,
      flow,
      scopes: entry?.scopes ?? preset?.scopes ?? [],
      // One consent per backend, for its event and upload endpoints alike.
      grantPartition: context.backendId,
      ...(clientId ? { clientId } : {}),
      ...(secret ? { clientSecret: secret } : {}),
      ...(flow === "authorization_code_pkce" ? { redirectUri: this.redirectUri } : {}),
      ...(entry?.clientMetadataDocument ? { clientMetadataDocument: entry.clientMetadataDocument } : {}),
      ...(registration ? {
        registration: {
          clientName: registration.clientName ?? "OpenClaw (Agent Hooks Protocol)",
          softwareId: "@agenthooksprotocol/adapter-openclaw",
          ...(registration.scopes ? { scopes: registration.scopes } : {}),
          ...(registration.initialAccessToken !== undefined ? { initialAccessTokenRef: `config:${context.backendId}` } : {}),
        },
      } : {}),
    };
  }

  /** The secret hook: issued secrets in their files, an initial access token from config. */
  static secrets(files: SecretStore, settings: PluginSettings, environment: Record<string, string | undefined>): SecretStore {
    return {
      put: (reference, secret, signal) => files.put(reference, secret, signal),
      delete: (reference, signal) => reference.startsWith("config:") ? Promise.resolve() : files.delete(reference, signal),
      async get(reference, signal) {
        if (!reference.startsWith("config:")) return files.get(reference, signal);
        const registration = settings.oauth?.backends?.[reference.slice("config:".length)]?.registration;
        return object(registration) ? resolveSecret(registration.initialAccessToken, environment) : undefined;
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
    const entry = this.#host.settings.oauth?.backends?.[backend.id];
    if (binding?.type === "oauth" || entry) {
      return (binding?.flow ?? entry?.flow) === "client_credentials" ? "client-credentials" : "login";
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
    if (kind === "none") return { state: "failing", reason: "it asks for OAuth, and no client is configured for it" };
    const pending = await this.pending(context).catch(() => undefined);
    return { state: "needs-login", ...(pending ? { url: pending.authorizationUrl, expiresAt: pending.expiresAt } : {}) };
  }

  /** Start, or reuse, a backend's login. Ready when its grant is usable. */
  async login(backendId: string): Promise<{ type: "ready" } | { type: "pending"; url: string; expiresAt: number }> {
    const backend = this.backend(backendId);
    const context = backend && this.context(backend);
    if (!context) throw new Error(`${backendId} is not an HTTP backend in hooks.json`);
    const requiredScopes = this.#needed.get(backendId);
    const result = await this.oauth.prepare(context, budget(PREPARE_MS), requiredScopes ? { requiredScopes } : {});
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
  hint(): void {
    for (const backend of this.#host.backends()) {
      const kind = this.kind(backend);
      if (kind !== "login" && !(kind === "none" && this.#needed.has(backend.id))) continue;
      if (this.#checking.has(backend.id)) continue;
      this.#checking.add(backend.id);
      void (async () => {
        if ((await this.status(backend)).state !== "needs-login") return this.#ready(backend.id);
        const result = await this.login(backend.id);
        if (result.type === "pending") this.show(backend.id, result.url, result.expiresAt);
      })().catch((error) => this.#host.log(`${backend.id}: sign-in not prepared (${describe(error)})`)).finally(() => this.#checking.delete(backend.id));
    }
  }

  /** The operator's private surface inside the Gateway: its log. */
  show(backendId: string, url: string, expiresAt: number): void {
    if (this.#shown.get(backendId) === url) return;
    this.#shown.set(backendId, url);
    this.#host.warn(`Agent Hooks Protocol: sign in to ${backendId}: ${url} (valid until ${new Date(expiresAt).toISOString()}; or run \`openclaw ahp login ${backendId}\`)`);
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
        await this.oauth.complete(handle, callback, budget(DELIVERY_MS));
        this.#ready(backend.id);
        this.onLogin?.(backend.id);
        return backend.id;
      }
    }
    throw new AuthError("interaction_required");
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
      await this.oauth.cancel(handle, operation);
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
