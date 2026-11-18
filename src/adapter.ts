// The adapter's state and the plumbing every mapping shares. One Gateway process
// serves many sessions, so one `Hooks` client delivers for all of them, and what is
// known about a session, a run or a tool call is kept here between its hooks.
import { Hooks } from "agenthooksprotocol/client";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { capabilitiesFor, gaps, MAX_CONTINUATIONS, narrow, type Grants } from "./capabilities.js";
import { join } from "node:path";
import type { StoredRecord } from "agenthooksprotocol/oauth";
import { loadRegistration, stateDir, type LoadedRegistration } from "./config.js";
import { configuredPort, Logins, type PluginSettings } from "./oauth/logins.js";
import { fileSecretStore } from "./oauth/secrets.js";
import { keyedTokenStore, type KeyedStore } from "./oauth/store.js";
import type { Message, NativeMessage } from "./content.js";
import { describe, type AnyResult } from "./effects.js";

export const PLUGIN_ID = "agent-hooks-protocol";
export const SOURCE = "urn:openclaw:gateway";

const MAX_OPEN_CALLS = 1000;

const contentCategories = ["text", "reasoning", "instructions", "attachment", "system", "tool_call", "tool_result"];

type Registration = { protocolVersion: "draft"; hooks: Record<string, unknown>[] };
export type Api = OpenClawPluginApi;

export interface Turn {
  /** OpenClaw's run id. */
  id: string;
  session: SessionState;
  continuationCount: number;
  requests: number;
  /** Consecutive failed requests: the next is another attempt at the same one. */
  failures: number;
  /** turn.start has been delivered. Every hook before the model waits on this. */
  started: Promise<void>;
  /** Why a backend refused the turn. */
  refused?: string;
  /** Context for the prompt. */
  context: string[];
  /** The system prompt, the history and the prompt as the model last read them. */
  request: NativeMessage[];
  system?: string;
  answer?: { id: string; text: string };
  error?: { class: string; message: string };
  /** The calls of the latest model response that have yet to resolve. */
  batch?: { id: string; calls: BatchCall[]; open: Set<string> };
  ended?: boolean;
  /** A tool has been called: OpenClaw makes no further pass of this run. */
  calledTool?: boolean;
}

export interface BatchCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
  outcome?: "ok" | "error" | "denied" | "cancelled";
  execution?: { status: "executed" } | { status: "skipped"; reason: "policy" | "cancelled" | "other"; detail?: string };
}

export interface SessionState {
  key: string;
  /** OpenClaw's session id. */
  id: string;
  agentId?: string;
  workspace?: string;
  model?: { provider: string; id: string };
  /** The session that spawned this one, when it is a subagent. */
  parent?: SessionState;
  agentType?: string;
  /** tool.before of the call that spawned it. */
  parentEventId?: string;
  turn?: Turn;
  /** session.start has been delivered. */
  started?: Promise<void>;
  /** Context for the next prompt. */
  pending: string[];
  /** Deliveries in order, and streaming ones, which nothing waits on. */
  queue: Promise<unknown>;
  stream: Promise<unknown>;
  /** A reply's text after a backend saw it at reply_payload_sending. */
  reviewed?: string;
  /** Not a session: a tool ran with no session context at all. */
  anonymous?: boolean;
}

export interface CallState {
  id: string;
  name: string;
  input: Record<string, unknown>;
  session: SessionState;
  beforeEventId?: string;
  /** tool.before's context, added to the result. */
  context: string[];
  /** tool.after has been delivered. */
  afterSent?: boolean;
  /** A backend or a person refused it. */
  refused?: boolean;
  signal?: AbortSignal;
  /** Its spawned subagent has been matched to it. */
  spawned?: boolean;
  /** Whether the file a write will touch already exists. */
  existed?: boolean;
  paths?: readonly string[];
}

/** Hook context, as far as every hook's has it in common. */
export type Scope = { sessionKey?: string; sessionId?: string; agentId?: string; workspaceDir?: string; runId?: string; modelProviderId?: string; modelId?: string };

export class Adapter {
  api!: Api;
  /** gateway_start has fired: this process is a Gateway. */
  gateway = false;
  readonly sessions = new Map<string, SessionState>();
  readonly #calls = new Map<string, CallState>();
  #client: Promise<Hooks | undefined> | undefined;
  #registration: LoadedRegistration | undefined;
  #logins: Logins | undefined;
  /** Sign-in could not start here: said once. */
  #loginsUnavailable = false;
  /** The Gateway's port, once it has started. */
  port: number | undefined;
  /** Deliveries under way, in every session. */
  readonly #inFlight = new Set<Promise<unknown>>();
  /** Where a tool that reports no session goes. */
  readonly anonymous: SessionState = { key: "", id: "", pending: [], queue: Promise.resolve(), stream: Promise.resolve(), anonymous: true };

  /** The client for every backend that is valid; undefined with no registration. It
   * starts at the first event, when `gateway` is known. */
  hooks(): Promise<Hooks | undefined> {
    return (this.#client ??= this.#start());
  }

  async #start(): Promise<Hooks | undefined> {
    try {
      const { registration, sources, diagnostics, notes } = this.registration();
      for (const line of diagnostics) this.warn(`Agent Hooks Protocol: ${line}`);
      for (const line of notes) this.log(line);
      if (!registration) return undefined;
      const hooks = await this.#create(registration);
      for (const issue of hooks.initializationDiagnostics ?? []) {
        this.warn(`Agent Hooks Protocol: ${issue.backendId}: ${issue.code}${issue.authError ? ` (${issue.authError})` : ""}`);
        // The SDK tries a backend skipped for want of a login again once a sign-in for it
        // is prepared in this process.
        if (issue.recovery === "login") {
          this.#logins?.needsLogin(issue.backendId, issue.requiredScopes);
          this.#logins?.initializationFailed.add(issue.backendId);
        }
      }
      this.log(`delivering to ${registration.hooks.length} backend(s) from ${sources.join(", ")}`);
      return hooks;
    } catch (error) {
      this.warn(`Agent Hooks Protocol not started: ${describe(error)}`);
      return undefined;
    }
  }

  /** The registration, read once per process. */
  registration(): LoadedRegistration {
    return (this.#registration ??= loadRegistration(process.env));
  }

  /** Sign-in state for every backend, in OpenClaw's plugin state. Undefined where
   * this OpenClaw cannot keep it. */
  logins(): Logins | undefined {
    if (this.#logins || this.#loginsUnavailable) return this.#logins;
    try {
      const settings = (this.api.pluginConfig ?? {}) as PluginSettings;
      const environment = process.env;
      const { state } = this.api.runtime;
      const redirects = state.openKeyedStore<string>({ namespace: "ahp-oauth-gateway", retention: "retained" }) as unknown as KeyedStore<string>;
      const records = state.openKeyedStore<StoredRecord>({ namespace: "ahp-oauth", retention: "retained" }) as unknown as KeyedStore<StoredRecord>;
      const leases = state.openKeyedStore<string>({ namespace: "ahp-oauth-leases", maxEntries: 10_000 }) as unknown as KeyedStore<string>;
      const directory = join(stateDir(environment) ?? state.resolveStateDir(), "plugins", PLUGIN_ID, "oauth-secrets");
      const logins = new Logins({
        store: keyedTokenStore(records, leases, { warn: (text) => this.warn(text) }),
        secrets: Logins.secrets(fileSecretStore(directory), settings, environment),
        settings,
        environment,
        livePort: () => this.port,
        configuredPort: () => configuredPort(this.api.config as never, environment),
        redirects,
        backends: () => (this.registration().registration?.hooks ?? []) as never,
        log: (text) => this.log(text),
        warn: (text) => this.warn(text),
      });
      return (this.#logins = logins);
    } catch (error) {
      this.#loginsUnavailable = true;
      this.warn(`Agent Hooks Protocol: OAuth sign-in is unavailable: ${describe(error)}`);
      return undefined;
    }
  }

  /** At the start of a turn: links for backends that need a sign-in, in the background. */
  hintLogins(): void {
    if (!this.registration().registration) return;
    void this.logins()?.hint();
  }

  grants(): Grants {
    const hooks = (this.api.config.plugins?.entries?.[PLUGIN_ID] as { hooks?: { allowConversationAccess?: boolean; allowPromptInjection?: boolean } } | undefined)?.hooks;
    return {
      conversation: hooks?.allowConversationAccess === true,
      promptInjection: hooks?.allowPromptInjection !== false,
      gateway: this.gateway,
    };
  }

  /** One client for every backend that is valid: one that is not must not take a
   * valid backend's fail-closed policy down with it. */
  async #create(registration: Registration): Promise<Hooks> {
    const grants = this.grants();
    const offered = capabilitiesFor(grants);
    const { hooks: backends, removed } = narrow(registration.hooks, offered);
    if (removed.length) this.warn(`Agent Hooks Protocol: not running ${removed.join(", ")}. Set plugins.entries.${PLUGIN_ID}.hooks.allowConversationAccess to true in openclaw.json to turn these events on.`);
    const create = async (hooks: Record<string, unknown>[]) => {
      const logins = this.logins();
      const client = new Hooks({ ...registration, hooks } as never, {
        source: SOURCE,
        ...(logins ? { auth: logins.provider() } : {}),
        harness: { name: "openclaw", version: this.api.runtime.version },
        capabilities: offered,
        manifestMetadata: {
          authentication: ["bearer", "oauth"],
          contentCategories,
          correlationIdentityFields: ["session.id", "turn.id", "call.id", "parentEventId"],
          gaps: [...gaps, ...(grants.gateway ? [] : [{ path: "tool.before.ask", reason: "a run outside the Gateway has no approval surface: nobody can answer" }])],
          limits: { maxContinuations: MAX_CONTINUATIONS },
          managedPolicy: { disableable: true, scopes: ["user"] },
          toolPaths: ["native", "mcp"],
          transports: ["http", "stdio"],
        },
      });
      await client.initialized;
      return client;
    };
    try {
      return await create(backends);
    } catch (error) {
      if (backends.length < 2) throw error;
    }
    const usable: Record<string, unknown>[] = [];
    for (const backend of backends) {
      try {
        await (await create([backend])).close();
        usable.push(backend);
      } catch (error) {
        this.warn(`Agent Hooks Protocol: backend ${String(backend.id)} is invalid and was skipped: ${describe(error)}`);
      }
    }
    return create(usable);
  }

  /** The client; undefined when nothing subscribes to `type`. */
  async client(type: string): Promise<Hooks | undefined> {
    const hooks = await this.hooks();
    return hooks?.subscribes(type as never) ? hooks : undefined;
  }

  /** What is known about the session a hook fired in, updated from its context. */
  session(scope: Scope): SessionState | undefined {
    const key = scope.sessionKey ?? scope.sessionId;
    if (!key) return undefined;
    let state = this.sessions.get(key);
    if (!state) {
      state = { key, id: scope.sessionId ?? key, pending: [], queue: Promise.resolve(), stream: Promise.resolve() };
      this.sessions.set(key, state);
    }
    if (scope.sessionId) state.id = scope.sessionId;
    if (scope.agentId) state.agentId = scope.agentId;
    if (scope.workspaceDir) state.workspace = scope.workspaceDir;
    if (scope.modelProviderId && scope.modelId && !state.model) state.model = { provider: scope.modelProviderId, id: scope.modelId };
    return state;
  }

  /** The AHP session object: a subagent's events are its root session's, with `agent`. */
  sessionObject(state: SessionState) {
    let root = state;
    while (root.parent) root = root.parent;
    const cwd = state.workspace ?? root.workspace;
    return {
      id: root.id,
      // Known by its key alone: OpenClaw has given no id for it yet.
      ...(root.id === root.key ? { synthesized: true } : {}),
      ...(cwd ? { cwd } : {}),
      ...(state.model ? { model: `${state.model.provider}/${state.model.id}` } : {}),
      ...(state.parent ? { agent: { id: state.key, ...(state.agentType ? { type: state.agentType } : {}) } } : {}),
    };
  }

  /** Session and turn for an event raised in a session. */
  scope(state: SessionState) {
    if (state.anonymous) return {};
    return {
      session: this.sessionObject(state),
      ...(state.turn ? { turn: { id: state.turn.id } } : {}),
    };
  }

  /** A tool call, by session: a provider's call ids are its own, and can repeat. */
  call(session: SessionState, id: string): CallState | undefined {
    return this.#calls.get(`${session.key}\0${id}`);
  }

  calls(session: SessionState): CallState[] {
    return [...this.#calls.values()].filter((call) => call.session === session);
  }

  track(call: CallState): CallState {
    this.#calls.set(`${call.session.key}\0${call.id}`, call);
    // Paths with no after_tool_call leave theirs behind: the oldest goes.
    if (this.#calls.size > MAX_OPEN_CALLS) this.#calls.delete(this.#calls.keys().next().value!);
    return call;
  }

  forget(call: CallState): void {
    this.#calls.delete(`${call.session.key}\0${call.id}`);
  }

  #run(previous: Promise<unknown>, work: () => Promise<unknown>): Promise<unknown> {
    const next = previous.then(work).catch((error) => this.log(`event failed: ${describe(error)}`));
    this.#inFlight.add(next);
    void next.finally(() => this.#inFlight.delete(next));
    return next;
  }

  /** Observation hooks are not awaited by anything worth holding up: they go in
   * order here, and the session's other deliveries wait for them first. One session's
   * slow backend does not hold up another's. */
  enqueue(session: SessionState, work: () => Promise<unknown>): Promise<unknown> {
    return (session.queue = this.#run(session.queue, work));
  }

  /** Deltas, in order, which no decision waits on. */
  enqueueStream(session: SessionState, work: () => Promise<unknown>): Promise<unknown> {
    return (session.stream = this.#run(session.stream, work));
  }

  flush(session: SessionState): Promise<unknown> {
    return session.queue;
  }

  /** Delivery diagnostics. */
  report(result: AnyResult): void {
    // The adapter reads no attachment back: release what the SDK kept.
    void result.content?.close().catch(() => {});
    for (const diagnostic of result.diagnostics) {
      const line = `${diagnostic.backendId} ${diagnostic.phase}: ${diagnostic.code}${diagnostic.auth ? ` (${diagnostic.auth.code})` : ""}`;
      // Shown at the next turn's start: a delivery never starts a login itself.
      if (diagnostic.auth?.recovery === "login") this.#logins?.needsLogin(diagnostic.backendId, diagnostic.auth.requiredScopes);
      if (diagnostic.syntheticDenial) this.warn(`${line} (denied by failure policy)`);
      else this.log(line);
    }
  }

  warn(text: string): void {
    this.api.logger.warn(text);
  }

  /** Detail nobody needs while things work. */
  log(text: string): void {
    if (process.env.AHP_DEBUG) this.api.logger.info(`[agent-hooks-protocol] ${text}`);
  }

  async close(): Promise<void> {
    await Promise.allSettled([...this.#inFlight]);
    const client = this.#client;
    this.#client = undefined;
    await (await client)?.close();
  }
}

export type { Message };
