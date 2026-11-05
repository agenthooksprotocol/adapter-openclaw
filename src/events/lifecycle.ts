// Sessions, compaction, subagents and per-session settings.
import { Permission, state } from "agenthooksprotocol/client";
import type { Adapter, SessionState } from "../adapter.js";
import { canonical, type NativeMessage } from "../content.js";
import { injections } from "../effects.js";

/** A subagent is reported under its root session: it has no session events of its own. */
function isSubagent(key: string | undefined): boolean {
  return Boolean(key?.includes(":subagent:"));
}

/** Deliver session.start once. `--local` and a restarted Gateway raise no
 * session_start for a session they meet at its first run. */
export function ensureStarted(adapter: Adapter, session: SessionState, native?: { resumedFrom?: string }): Promise<void> {
  return (session.started ??= (async () => {
    if (session.parent || isSubagent(session.key)) return;
    // A reset's session.end goes first.
    await adapter.flush(session);
    const hooks = await adapter.client("session.start");
    if (!hooks) return;
    const result = await hooks.sessionStart({
      session: adapter.sessionObject(session),
      trigger: native?.resumedFrom ? "clear" : "startup",
      permissionMode: "default",
      items: [],
      ...(native?.resumedFrom ? { resumedFrom: { id: native.resumedFrom } } : {}),
      ...(native ? {} : { synthesized: true }),
    }, { initialState: state.initial(Permission.None) });
    adapter.report(result);
    session.pending.push(...injections(result));
  })());
}

export function lifecycle(adapter: Adapter): void {
  const { api } = adapter;

  api.on("gateway_start", () => {
    adapter.gateway = true;
    void adapter.hooks();
  });

  api.on("gateway_stop", () => adapter.close());

  api.on("session_start", async (event, ctx) => {
    const session = adapter.session({ ...ctx, sessionId: event.sessionId, sessionKey: event.sessionKey ?? ctx.sessionKey });
    if (!session) return;
    // A reset: the same key starts again.
    session.started = undefined;
    await ensureStarted(adapter, session, event.resumedFrom ? { resumedFrom: event.resumedFrom } : {});
  });

  api.on("session_end", async (event, ctx) => {
    const key = event.sessionKey ?? ctx.sessionKey;
    if (isSubagent(key)) return;
    const session = adapter.session({ ...ctx, sessionId: event.sessionId, sessionKey: key });
    if (!session) return;
    // The next session under this key must not lend this one its id.
    const ended = adapter.sessionObject(session);
    // Nothing follows it under this key: a reset's session.start would wait on its queue.
    if (!event.nextSessionId && !event.nextSessionKey) adapter.sessions.delete(session.key);
    await adapter.enqueue(session, async () => {
      const hooks = await adapter.client("session.end");
      if (!hooks) return;
      adapter.report(await hooks.sessionEnd({
        session: ended,
        outcome: "completed",
        reason: event.reason ?? "unknown",
      }));
    });
  });

  api.on("subagent_spawned", (event, ctx) => {
    const child = adapter.session({ sessionKey: event.childSessionKey, agentId: event.agentId });
    const parent = ctx.requesterSessionKey ? adapter.sessions.get(ctx.requesterSessionKey) : undefined;
    if (!child || !parent || child === parent) return;
    child.parent = parent;
    child.agentType = event.label ?? event.agentId;
    // With several spawns alike, which one made this child is not known: no parent then.
    const candidates = adapter.calls(parent).filter((call) => call.name === "sessions_spawn" && !call.spawned && call.input.label === event.label);
    if (candidates.length !== 1) return;
    candidates[0]!.spawned = true;
    if (candidates[0]!.beforeEventId) child.parentEventId = candidates[0]!.beforeEventId;
  });

  api.on("subagent_ended", (event) => {
    adapter.sessions.delete(event.targetSessionKey);
  });

  api.on("before_compaction", async (event, ctx) => {
    const session = adapter.session(ctx);
    if (!session) return;
    await adapter.enqueue(session, async () => {
      const hooks = await adapter.client("context.compact.before");
      if (!hooks) return;
      const seen = new Map<string, number>();
      adapter.report(await hooks.contextCompactBefore({
        ...adapter.scope(session),
        trigger: "auto",
        items: ((event.messages ?? []) as NativeMessage[]).map((native) => canonical(session.id, native, seen)) as never,
        instructions: [],
        ...(event.tokenCount !== undefined ? { tokenCounts: { before: event.tokenCount } } : {}),
        gaps: [
          { path: "trigger", reason: "OpenClaw does not say whether a person asked for this compaction" },
          ...(event.messages ? [] : [{ path: "items", reason: "OpenClaw reports how many messages a compaction will replace, not which" }]),
        ],
      }, { initialState: state.initial(Permission.None) }));
    });
  });

  api.on("after_compaction", async (event, ctx) => {
    const session = adapter.session(ctx);
    if (!session) return;
    await adapter.enqueue(session, async () => {
      const hooks = await adapter.client("context.compact.after");
      if (!hooks) return;
      adapter.report(await hooks.contextCompactAfter({
        ...adapter.scope(session),
        summary: [],
        removed: [],
        execution: { status: "executed" },
        ...(event.tokenCount !== undefined ? { tokenCounts: { after: event.tokenCount } } : {}),
        gaps: [
          { path: "summary", reason: "after_compaction reports counts, not the summary" },
          { path: "removed", reason: "after_compaction reports how many messages it replaced, not which" },
        ],
      }));
    });
  });

  // A person or a client changed a session's settings.
  api.registerHook("session:patch", async (event) => {
    const context = event.context as { patch?: Record<string, unknown>; sessionEntry?: { sessionId?: string; providerOverride?: string; modelOverride?: string } };
    const patch = context.patch ?? {};
    const session = adapter.session({ sessionKey: event.sessionKey, ...(context.sessionEntry?.sessionId ? { sessionId: context.sessionEntry.sessionId } : {}) });
    // `key` names the session being patched and `expected*` guard the write: not settings.
    const settings = Object.keys(patch).filter((name) => name !== "key" && !/^expected[A-Z]/.test(name));
    if (!session || !settings.length) return;
    await adapter.enqueue(session, async () => {
      const entry = context.sessionEntry;
      if ("model" in patch && entry?.modelOverride) {
        const previous = session.model;
        const current = { id: entry.modelOverride, provider: entry.providerOverride ?? previous?.provider ?? "unknown" };
        session.model = current;
        const hooks = await adapter.client("model.switch.after");
        if (hooks && previous && (previous.id !== current.id || previous.provider !== current.provider)) {
          adapter.report(await hooks.modelSwitchAfter({ ...adapter.scope(session), previous, current, reason: "user" }));
        }
      }
      const others = settings.filter((name) => name !== "model");
      const hooks = others.length ? await adapter.client("config.change.after") : undefined;
      if (hooks) {
        adapter.report(await hooks.configChangeAfter({
          ...adapter.scope(session),
          change: { scope: "session", source: "openclaw", settings: others, summary: `session settings changed: ${others.join(", ")}` },
        }));
      }
    });
  }, { name: "agent-hooks-protocol-session-patch", description: "Reports per-session settings to Agent Hooks Protocol backends" });
}

export { isSubagent };
