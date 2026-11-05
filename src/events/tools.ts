// Tools: tool.before at before_tool_call; tool.after in the tool result middleware,
// before the model reads a result, and at after_tool_call for the calls that never
// got one (refused, unknown). `ask` goes to OpenClaw's plugin approvals.
import { existsSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { Permission, state } from "agenthooksprotocol/client";
import type { Adapter, BatchCall, CallState, SessionState } from "../adapter.js";
import { applyParts, asText, json, partsOf, texts, textPart, type Block, type Message, type Part } from "../content.js";
import { denial, eventId, injections } from "../effects.js";
import { connection } from "../mcp.js";
import { AWAIT } from "./turns.js";

const FILE_TOOLS = new Set(["write", "edit", "apply_patch"]);
/** A result reported after the fact: nothing a backend says can change it. */
const REPORT_ONLY = { effects: [] } as never;
const APPROVAL_TIMEOUT_MS = 120_000;
/** Runs after any other plugin's before_tool_call. */
const LAST = -1000;

type Execution = NonNullable<BatchCall["execution"]>;

/** How OpenClaw starts the name of an MCP server's tools: a server's name is
 * sanitized and, like the rest, read without case. */
export function mcpPrefix(server: string): string {
  const safe = server.trim().replace(/[^A-Za-z0-9_-]/g, "-") || "mcp";
  return `${(/^[A-Za-z]/.test(safe) ? safe : `mcp-${safe}`).slice(0, 30).toLowerCase()}__`;
}

/** How OpenClaw names an MCP server's tools: `<server>__<tool>`. */
export function descriptor(adapter: Adapter, name: string) {
  const servers = (adapter.api.config as { mcp?: { servers?: Record<string, Record<string, unknown>> } }).mcp?.servers ?? {};
  for (const [server, config] of Object.entries(servers)) {
    const prefix = mcpPrefix(server);
    if (!name.toLowerCase().startsWith(prefix)) continue;
    return {
      name,
      origin: "mcp" as const,
      path: "mcp" as const,
      toolMcp: {
        provenance: "inferred" as const,
        server: { id: server, name: server },
        toolName: name.slice(prefix.length),
        connection: json<never>(connection(config)),
      },
    };
  }
  return { name, origin: "native" as const, path: "native" as const, toolMcp: undefined };
}

function base(adapter: Adapter, call: CallState) {
  return {
    callId: call.id,
    ...descriptor(adapter, call.name),
    ...adapter.scope(call.session),
    ...(call.beforeEventId ? { parentEventId: call.beforeEventId } : {}),
  };
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** What to return as `params`. OpenClaw merges them over the originals, so a key a
 * backend removed has to be removed by name. */
function paramsFor(original: Record<string, unknown>, input: Record<string, unknown>): Record<string, unknown> {
  const removed = Object.keys(original).filter((key) => !(key in input));
  return { ...Object.fromEntries(removed.map((key) => [key, undefined])), ...input };
}

/** A dispatching tool's id for a call it made: `tool_call:<parent id>:...`. */
function dispatchedBy(adapter: Adapter, session: SessionState, id: string): CallState | undefined {
  const parent = /^tool_call:([^:]+):/.exec(id)?.[1];
  return parent ? adapter.call(session, parent) : undefined;
}

function target(call: CallState, path: string): string {
  return isAbsolute(path) ? path : resolve(call.session.workspace ?? ".", path);
}

/** What a tool will write, and whether it is already there. */
function noteTargets(call: CallState, derived: readonly string[] | undefined): void {
  if (!FILE_TOOLS.has(call.name)) return;
  const path = call.input.path;
  call.paths = derived ?? (typeof path === "string" ? [path] : []);
  if (call.paths[0]) call.existed = existsSync(target(call, call.paths[0]));
}

type AfterFields = {
  outcome: NonNullable<BatchCall["outcome"]>;
  execution: Execution;
  items: Message[];
  error?: { class: string; message: string };
  durationMs?: number;
};

async function after(adapter: Adapter, call: CallState, fields: AfterFields, reportOnly: boolean) {
  call.afterSent = true;
  const hooks = await adapter.client("tool.after");
  const result = hooks
    ? await hooks.toolAfter(
        { ...base(adapter, call), input: json(call.input), ...fields } as never,
        { initialState: state.initial(Permission.None), ...(reportOnly ? { capabilities: REPORT_ONLY } : {}) },
      )
    : undefined;
  if (result) adapter.report(result);
  await settleBatch(adapter, call, fields);
  return result;
}

/** A model response's last call has resolved. */
async function settleBatch(adapter: Adapter, call: CallState, fields: AfterFields): Promise<void> {
  const turn = call.session.turn;
  const batch = turn?.batch;
  if (!turn || !batch?.open.has(call.id)) return;
  const entry = batch.calls.find((item) => item.id === call.id);
  if (entry) {
    entry.outcome = fields.outcome;
    entry.execution = fields.execution;
  }
  batch.open.delete(call.id);
  if (batch.open.size) return;
  turn.batch = undefined;
  const hooks = await adapter.client("tool.batch.after");
  if (!hooks) return;
  adapter.report(await hooks.toolBatchAfter({
    ...adapter.scope(call.session),
    batch: { id: batch.id, synthesized: true },
    calls: batch.calls.map((item) => {
      const { origin, path, toolMcp } = descriptor(adapter, item.name);
      return {
        call: { id: item.id },
        tool: { name: item.name, origin, ...(toolMcp ? { mcp: toolMcp } : {}), input: json<{ [key: string]: never }>(item.input) },
        path,
        outcome: item.outcome ?? ("ok" as const),
        execution: item.execution ?? { status: "executed" as const },
      };
    }) as never,
  }, { initialState: state.initial(Permission.None) }));
}

async function fileChanged(adapter: Adapter, call: CallState): Promise<void> {
  if (!FILE_TOOLS.has(call.name) || !call.paths?.length) return;
  const hooks = await adapter.client("file.changed");
  if (!hooks) return;
  adapter.report(await hooks.fileChanged({
    ...adapter.scope(call.session),
    changes: call.paths.map((path, index) => ({
      path: target(call, path),
      operation: index === 0 && call.existed === false ? "create" as const : "update" as const,
      agentCaused: true,
    })),
  }));
}

function resolutionOf(decision: string): { decision: "allow" | "deny"; decidedBy: "user" | "policy" } {
  if (decision === "allow-once" || decision === "allow-always") return { decision: "allow", decidedBy: "user" };
  return { decision: "deny", decidedBy: decision === "deny" ? "user" : "policy" };
}

/** A backend asked for a decision: another may give one at tool.permission.request;
 * failing that, OpenClaw asks a person. */
async function ask(adapter: Adapter, call: CallState) {
  const resolved = (decision: "allow" | "deny", decidedBy: "user" | "policy" | "hook") =>
    adapter.enqueue(call.session, async () => {
      const hooks = await adapter.client("tool.permission.resolved");
      if (hooks) adapter.report(await hooks.toolPermissionResolved({ ...base(adapter, call), input: json(call.input), decision, decidedBy }));
    });
  const hooks = await adapter.client("tool.permission.request");
  if (hooks) {
    const result = await hooks.toolPermissionRequest({
      ...base(adapter, call),
      input: json(call.input),
      suggestions: [],
      sandboxBypass: false,
    }, { initialState: state.initial(Permission.None) });
    adapter.report(result);
    const refused = denial(result);
    if (refused !== undefined) {
      await resolved("deny", "hook");
      return { refused };
    }
    const rewritten = (result.event as { tool?: { input?: unknown } }).tool?.input;
    if (rewritten && typeof rewritten === "object" && !sameJson(rewritten, call.input)) call.input = rewritten as Record<string, unknown>;
    if ((result.state as { permission?: string }).permission === Permission.Allow) {
      await resolved("allow", "hook");
      return {};
    }
  }
  const attention = await adapter.client("user.attention");
  const id = `${call.id}:attention`;
  if (attention) {
    adapter.report(await attention.userAttention({
      ...adapter.scope(call.session),
      attention: {
        kind: "permission",
        title: [textPart(`${id}:title`, `Allow ${call.name}?`)],
        message: [textPart(`${id}:message`, asText(call.input))],
      },
      synthesized: true,
    }));
  }
  return {
    approval: {
      title: `Allow ${call.name}?`.slice(0, 80),
      description: asText(call.input).slice(0, 512),
      severity: "warning" as const,
      timeoutMs: APPROVAL_TIMEOUT_MS,
      allowedDecisions: ["allow-once" as const, "deny" as const],
      onResolution: async (decision: string) => {
        const outcome = resolutionOf(decision);
        if (outcome.decision === "deny") call.refused = true;
        await resolved(outcome.decision, outcome.decidedBy);
      },
    },
  };
}

function track(adapter: Adapter, session: SessionState, id: string, name: string, input: Record<string, unknown>, signal?: AbortSignal): CallState {
  return adapter.track({ id, name, input, session, context: [], ...(signal ? { signal } : {}) });
}

export function tools(adapter: Adapter): void {
  const { api } = adapter;

  api.on("before_tool_call", async (event, ctx) => {
    // Policy holds with no session to report: some paths run tools without one.
    const session = adapter.session(ctx) ?? adapter.anonymous;
    await session.turn?.started;
    await adapter.flush(session);
    // Where nothing stops a refused run, its tools are stopped here.
    if (session.turn?.refused !== undefined) return { block: true, blockReason: session.turn.refused };
    if (session.turn) session.turn.calledTool = true;
    const id = event.toolCallId ?? crypto.randomUUID();
    const original = event.params;
    const call = track(adapter, session, id, event.toolName, original, ctx.abortSignal);
    noteTargets(call, event.derivedPaths);
    const hooks = await adapter.client("tool.before");
    if (!hooks) return;
    const result = await hooks.toolBefore({
      callId: id,
      ...(event.toolCallId ? {} : { callSynthesized: true }),
      ...descriptor(adapter, call.name),
      ...adapter.scope(session),
      input: json(original),
    }, {
      initialState: state.initial(Permission.None),
      ...(ctx.abortSignal && !ctx.abortSignal.aborted ? { signal: ctx.abortSignal } : {}),
    });
    adapter.report(result);
    const before = eventId(result);
    if (before) call.beforeEventId = before;

    // OpenClaw's own abort, in flight: the call is over, and nobody refused it.
    if (result.interrupted) return { block: true, blockReason: "Operation aborted" };
    const refused = denial(result);
    if (refused !== undefined) {
      call.refused = true;
      return { block: true, blockReason: [refused, ...injections(result)].join("\n\n") };
    }
    // A dispatched call's result is its dispatcher's to carry.
    (dispatchedBy(adapter, session, id) ?? call).context.push(...injections(result));
    const rewritten = (result.event as { tool?: { input?: unknown } }).tool?.input;
    if (rewritten && typeof rewritten === "object" && !sameJson(rewritten, original)) call.input = rewritten as Record<string, unknown>;

    if ((result.state as { permission?: string }).permission === Permission.Ask) {
      const answer = await ask(adapter, call);
      if (answer.refused !== undefined) {
        call.refused = true;
        return { block: true, blockReason: [answer.refused, ...call.context].join("\n\n") };
      }
      noteTargets(call, undefined);
      const params = call.input === original ? {} : { params: paramsFor(original, call.input) };
      return answer.approval ? { ...params, requireApproval: answer.approval } : params;
    }
    noteTargets(call, call.input === original ? event.derivedPaths : undefined);
    return call.input === original ? undefined : { params: paramsFor(original, call.input) };
    // Last: each handler's params replace the one before's, and a backend's must stand.
  }, { ...AWAIT, priority: LAST });

  // Before the model reads the result. Trust is explicit: OpenClaw holds this
  // interface back from a plugin that is not enabled by name.
  api.registerAgentToolResultMiddleware(async (event, ctx) => {
    const session = adapter.session(ctx) ?? adapter.anonymous;
    await adapter.flush(session);
    const call = adapter.call(session, event.toolCallId) ?? track(adapter, session, event.toolCallId, event.toolName, event.args);
    const content = (event.result.content ?? []) as unknown as readonly Block[];
    const id = `${call.id}:result`;
    const original = partsOf(id, content);
    const cancelled = Boolean(call.signal?.aborted);
    const result = await after(adapter, call, cancelled
      ? { outcome: "cancelled", execution: { status: "executed" }, items: [] }
      : event.isError
        ? { outcome: "error", execution: { status: "executed" }, items: [], error: { class: "ToolError", message: texts([{ parts: original }]).join("\n") || "The tool reported an error" } }
        : { outcome: "ok", execution: { status: "executed" }, items: [{ id, role: "tool", parts: original }] }, false);
    if (!event.isError && !cancelled) await fileChanged(adapter, call);
    // A fail-closed backend that could not be shown this result: the model is not either.
    const withheld = result ? denial(result) : undefined;
    if (withheld !== undefined) return { result: { ...event.result, content: [{ type: "text", text: withheld }] as never } };
    const effective = result ? (result.event as { items?: { id?: string; parts?: Part[] }[] }).items : undefined;
    // A failure's event has no items: what the model reads stays, unless a backend gave some.
    const next = effective && (!event.isError || effective.length) ? applyOutput(id, content, effective) : content;
    const context = [...call.context, ...(result ? injections(result) : [])];
    const final: readonly Block[] = context.length ? [...next, ...context.map((text) => ({ type: "text", text }))] : next;
    if (final === content) return;
    return { result: { ...event.result, content: final as never } };
  });

  // Every call ends here, whether or not it reached the middleware.
  api.on("after_tool_call", async (event, ctx) => {
    const session = adapter.session(ctx) ?? adapter.anonymous;
    const id = event.toolCallId ?? "";
    const known = adapter.call(session, id);
    await adapter.enqueue(session, async () => {
      if (known) adapter.forget(known);
      if (known?.afterSent) return;
      const call = known ?? { id: id || crypto.randomUUID(), name: event.toolName, input: event.params, session, context: [] };
      const reason = event.error ?? "The tool did not run";
      const resultId = `${call.id}:result`;
      const content = (event.result as { content?: readonly Block[] } | undefined)?.content;
      // A dispatched call ran, with no middleware of its own: its dispatcher has that.
      const ran = !known?.refused && Boolean(known && dispatchedBy(adapter, session, known.id));
      await after(adapter, call, known?.refused
        ? { outcome: "denied", execution: { status: "skipped", reason: "policy" }, items: [] }
        : known?.signal?.aborted
          ? { outcome: "cancelled", execution: { status: "skipped", reason: "cancelled" }, items: [] }
          : ran && !event.error
            ? { outcome: "ok", execution: { status: "executed" }, items: [{ id: resultId, role: "tool", parts: partsOf(resultId, content) }] }
            : ran
              ? { outcome: "error", execution: { status: "executed" }, items: [], error: { class: "ToolError", message: reason } }
              : { outcome: "error", execution: { status: "skipped", reason: "other", detail: reason }, items: [], error: { class: "ToolError", message: reason } }, true);
      if (ran && !event.error) await fileChanged(adapter, call);
    });
  });

  const subscribe = api.agent?.events?.registerAgentEventSubscription ?? api.registerAgentEventSubscription;
  subscribe?.call(api.agent?.events ?? api, {
    id: "agent-hooks-protocol-tools",
    streams: ["tool"],
    payload: "full",
    handle: (event) => {
      const data = event.data as { phase?: string; toolCallId?: string; partialResult?: { content?: readonly Block[] } };
      if (data.phase !== "update" || !data.toolCallId) return;
      const session = event.sessionKey ? adapter.sessions.get(event.sessionKey) : undefined;
      const call = session && adapter.call(session, data.toolCallId);
      const output = texts([{ parts: partsOf("p", data.partialResult?.content) }]).join("\n");
      if (!session || !call || !output) return;
      const piece = `${call.id}:progress:${crypto.randomUUID()}`;
      void adapter.enqueueStream(session, async () => {
        const hooks = await adapter.client("tool.progress");
        if (!hooks) return;
        adapter.report(await hooks.toolProgress({
          ...base(adapter, call),
          input: json(call.input),
          partialOutput: { id: piece, role: "tool", synthesized: true, parts: [textPart(`${piece}#0`, output)] } as never,
          backgrounded: false,
        }));
      });
    },
  });
}

/** The result's effective content: `replace` gives one message for the result;
 * `merge` appends more, each read as more of the same result. */
function applyOutput(id: string, content: readonly Block[], effective: readonly { id?: string; parts?: Part[] }[]): readonly Block[] {
  const own = effective.find((item) => item.id === id);
  const merged = effective.filter((item) => item !== own).flatMap((item) => item.parts ?? []);
  return applyParts(id, content, [...(own?.parts ?? []), ...merged]);
}
