// Turns. An AHP turn is an OpenClaw run, whatever passes a revision makes of it, and
// its id is the run's. turn.start is delivered at the first hook of a run, and what
// it decided is carried out by the hooks that come after it.
import { Permission, state } from "agenthooksprotocol/client";
import { type Adapter, type Scope, type SessionState, type Turn } from "../adapter.js";
import { MAX_CONTINUATIONS } from "../capabilities.js";
import { partsOf, type Message } from "../content.js";
import { denial, flow, injections } from "../effects.js";
import { ensureStarted } from "./lifecycle.js";

/** The longest OpenClaw lets a handler run. AHP subscriptions have timeouts of their
 * own, and OpenClaw's defaults are shorter and would decide for them. */
export const AWAIT = { timeoutMs: 600_000 };

type RunScope = Scope & { trigger?: string; inputProvenance?: { kind?: string } };

function triggerOf(ctx: RunScope): "user" | "external" {
  const provenance = ctx.inputProvenance?.kind;
  if (provenance === "inter_session" || provenance === "internal_system") return "external";
  return !ctx.trigger || ctx.trigger === "user" ? "user" : "external";
}

/** The run a hook fired in, delivering turn.start the first time one is seen. */
export function begin(adapter: Adapter, ctx: RunScope, prompt: string | undefined): Turn | undefined {
  const session = adapter.session(ctx);
  if (!session || !ctx.runId) return undefined;
  if (session.turn?.id === ctx.runId) return session.turn;
  const previous = session.turn;
  const turn: Turn = {
    id: ctx.runId,
    session,
    continuationCount: 0,
    requests: 0,
    failures: 0,
    context: [],
    request: [],
    started: Promise.resolve(),
  };
  session.turn = turn;
  turn.started = (async () => {
    // Another plugin claimed the last run before it began: no agent_end is coming.
    if (previous && !previous.ended) await endTurn(adapter, previous, "completed");
    await ensureStarted(adapter, session);
    await adapter.flush(session);
    const hooks = await adapter.client("turn.start");
    if (!hooks) return;
    const id = `${turn.id}:prompt`;
    const result = await hooks.turnStart({
      turn: { id: turn.id },
      session: adapter.sessionObject(session),
      trigger: triggerOf(ctx),
      items: prompt === undefined ? [] : [{ id, role: "user", synthesized: true, parts: partsOf(id, prompt) } as never],
      ...(session.parentEventId ? { parentEventId: session.parentEventId } : {}),
    }, { initialState: state.initial(Permission.None) });
    adapter.report(result);
    turn.refused = denial(result);
    if (turn.refused === undefined) turn.context.push(...injections(result));
  })();
  return turn;
}

function answerItems(turn: Turn): Message[] {
  if (!turn.answer) return [];
  const { id, text } = turn.answer;
  return [{ id, role: "assistant", synthesized: true, parts: partsOf(id, text) }];
}

export async function endTurn(adapter: Adapter, turn: Turn, outcome: "completed" | "failed" | "cancelled"): Promise<void> {
  turn.ended = true;
  const { session } = turn;
  if (session.turn === turn) session.turn = undefined;
  // Whatever became of its calls, nothing more will be said of them.
  for (const call of adapter.calls(session)) adapter.forget(call);
  const hooks = await adapter.client("turn.end");
  if (!hooks) return;
  adapter.report(await hooks.turnEnd({
    session: adapter.sessionObject(session),
    turn: { id: turn.id },
    items: answerItems(turn) as never,
    continuationCount: turn.continuationCount,
    outcome,
    ...(outcome === "failed" && turn.error ? { error: turn.error } : {}),
  }));
}

export function turns(adapter: Adapter): void {
  const { api } = adapter;

  api.on("before_model_resolve", async (event, ctx) => {
    await begin(adapter, ctx, event.prompt)?.started;
  }, AWAIT);

  api.on("before_prompt_build", async (event, ctx) => {
    const turn = begin(adapter, ctx, event.currentUserMessage ?? event.prompt);
    if (!turn) return;
    await turn.started;
    if (turn.refused !== undefined) return;
    // Lasts for the run: a revision builds its prompt again.
    const context = [...turn.session.pending.splice(0), ...turn.context];
    turn.context = context;
    return context.length ? { appendContext: context.join("\n\n") } : undefined;
  }, AWAIT);

  api.on("before_agent_run", async (event, ctx) => {
    const turn = begin(adapter, ctx, event.prompt);
    if (!turn) return;
    await turn.started;
    if (turn.refused === undefined) return;
    return { outcome: "block", reason: turn.refused, message: turn.refused };
  }, AWAIT);

  api.on("before_agent_finalize", async (event, ctx) => {
    const session = adapter.session({ ...ctx, sessionId: event.sessionId, ...(event.sessionKey ? { sessionKey: event.sessionKey } : {}) });
    const turn = session?.turn;
    if (!session || !turn) return;
    await adapter.flush(session);
    const hooks = await adapter.client("turn.finish.before");
    if (!hooks) return;
    const continuable = turn.continuationCount < MAX_CONTINUATIONS && !turn.calledTool;
    const result = await hooks.turnFinishBefore({
      session: adapter.sessionObject(session),
      turn: { id: turn.id },
      items: answerItems(turn) as never,
      continuationCount: turn.continuationCount,
      outcome: "completed",
    }, {
      initialState: state.initial(Permission.None),
      // After the limit, or a tool, a backend may only stop.
      ...(continuable ? {} : { capabilities: { effects: ["flow"], flow: { operations: ["stop"] } } as never }),
    });
    adapter.report(result);
    // A fail-closed backend that could not be asked wants no more passes made.
    const refused = denial(result);
    if (refused !== undefined) return { action: "finalize", reason: refused };
    const decision = flow(result);
    if (decision?.operation === "stop") return { action: "finalize", reason: decision.reason };
    if (decision?.operation !== "continue" || !continuable) return;
    turn.continuationCount += 1;
    return { action: "revise", reason: decision.instruction ?? "Continue: an AHP hook asked for another pass." };
  }, AWAIT);

  api.on("agent_end", async (event, ctx) => {
    const session = adapter.session(ctx);
    const turn = (session?.turn && (!event.runId || session.turn.id === event.runId)) ? session.turn : undefined;
    if (!turn) return;
    await adapter.enqueue(session!, async () => {
      if (turn.ended) return;
      await session!.stream;
      if (turn.refused !== undefined) {
        turn.error = { class: "Denied", message: turn.refused };
        return endTurn(adapter, turn, "failed");
      }
      if (event.error) turn.error = { class: "AgentError", message: event.error };
      // A provider's failure leaves success true: the request reported it.
      if (turn.error) return endTurn(adapter, turn, "failed");
      return endTurn(adapter, turn, event.success ? "completed" : "cancelled");
    });
  });

  // Streaming text. This API version may have the namespaced form or the older alias.
  const subscribe = api.agent?.events?.registerAgentEventSubscription ?? api.registerAgentEventSubscription;
  subscribe?.call(api.agent?.events ?? api, {
    id: "agent-hooks-protocol-assistant",
    streams: ["assistant"],
    payload: "full",
    handle: (event) => {
      const data = event.data as { delta?: unknown };
      const session = event.sessionKey ? adapter.sessions.get(event.sessionKey) : undefined;
      const turn = session?.turn;
      if (!session || !turn || typeof data.delta !== "string" || !data.delta) return;
      void streamed(adapter, session, turn, data.delta);
    },
  });
}

function streamed(adapter: Adapter, session: SessionState, turn: Turn, delta: string): Promise<unknown> {
  const item = `${turn.id}:${turn.requests}:response`;
  const piece = `${item}:${crypto.randomUUID()}`;
  return adapter.enqueueStream(session, async () => {
    const hooks = await adapter.client("turn.progress");
    if (!hooks) return;
    adapter.report(await hooks.turnProgress({
      session: adapter.sessionObject(session),
      turn: { id: turn.id },
      item: { id: item, synthesized: true },
      delta: { id: piece, role: "assistant", synthesized: true, parts: partsOf(piece, delta) } as never,
      final: false,
    }));
  });
}
