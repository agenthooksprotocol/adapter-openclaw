// Model requests are observations in OpenClaw. llm_input has what a run's first
// request holds, and each message written after it says how the next one differs;
// model_call_started marks each request as it goes out.
import { Permission, state } from "agenthooksprotocol/client";
import type { Adapter, Turn } from "../adapter.js";
import { blocks, canonical, messageId, textPart, type Block, type Message, type NativeMessage } from "../content.js";
import { begin } from "./turns.js";

type Assistant = NativeMessage & {
  role: "assistant";
  provider?: string;
  model?: string;
  stopReason?: string;
  errorMessage?: string;
  usage?: { input?: number; output?: number; cacheRead?: number; cacheWrite?: number };
};

function attempt(turn: Turn) {
  return { id: `${turn.id}:${turn.requests}`, number: turn.failures + 1, synthesized: true };
}

export function model(adapter: Adapter): void {
  const { api } = adapter;

  api.on("llm_input", (event, ctx) => {
    const turn = begin(adapter, ctx, event.prompt);
    if (!turn) return;
    turn.system = event.systemPrompt;
    turn.request = [...(event.historyMessages as NativeMessage[]), { role: "user", content: event.prompt, timestamp: Date.now() }];
  });

  api.on("model_call_started", (event, ctx) => {
    const session = adapter.session({ ...ctx, ...(event.sessionKey ? { sessionKey: event.sessionKey } : {}), ...(event.sessionId ? { sessionId: event.sessionId } : {}) });
    const turn = session?.turn;
    if (!session || !turn) return;
    turn.requests += 1;
    const current = { id: event.model, provider: event.provider };
    const previous = session.model;
    session.model = current;
    const current_attempt = attempt(turn);
    const snapshot = [...turn.request];
    const system = turn.system;
    void adapter.enqueue(session, async () => {
      if (previous && (previous.id !== current.id || previous.provider !== current.provider)) {
        const switched = await adapter.client("model.switch.after");
        if (switched) adapter.report(await switched.modelSwitchAfter({ ...adapter.scope(session), previous, current, reason: "fallback" }));
      }
      const hooks = await adapter.client("model.request.before");
      if (!hooks) return;
      const seen = new Map<string, number>();
      const systemId = `${current_attempt.id}:system`;
      const items: Message[] = [
        ...(system ? [{ id: systemId, role: "system" as const, synthesized: true, parts: [textPart(`${systemId}#0`, system, "system")] }] : []),
        ...snapshot.map((native) => canonical(session.id, native, seen)),
      ];
      adapter.report(await hooks.modelRequestBefore({
        ...adapter.scope(session),
        model: current,
        attempt: current_attempt,
        params: { model: event.model, provider: event.provider, ...(event.api ? { api: event.api } : {}) },
        items: items as never,
      }, { initialState: state.initial(Permission.None) }));
    });
  });

  // Synchronous, and only read: every message of a run passes through here on its
  // way into the transcript.
  api.on("before_message_write", (event, ctx) => {
    const session = ctx.sessionKey ? adapter.sessions.get(ctx.sessionKey) : undefined;
    const turn = session?.turn;
    const native = event.message as unknown as NativeMessage;
    if (!session || !turn) return;
    if (native.role === "toolResult") turn.request.push(native);
    if (native.role !== "assistant") return;
    turn.request.push(native);
    response(adapter, turn, native as Assistant);
  });

  api.on("model_call_ended", (event, ctx) => {
    const session = adapter.session({ ...ctx, ...(event.sessionKey ? { sessionKey: event.sessionKey } : {}) });
    const turn = session?.turn;
    if (!turn || event.outcome !== "error" || turn.error) return;
    // The failed response's own message, if there is one, says more.
    turn.error = { class: event.errorCategory ?? "ProviderError", message: event.failureKind ?? event.errorCategory ?? "The model request failed" };
  });
}

function response(adapter: Adapter, turn: Turn, message: Assistant): void {
  const { session } = turn;
  const selected = message.model ? { id: message.model, provider: message.provider ?? session.model?.provider ?? "unknown" } : session.model;
  if (!selected) return;
  const current = attempt(turn);
  const toolCalls = blocks(message.content).filter((block: Block) => block.type === "toolCall");
  if (message.stopReason === "aborted") return;
  if (message.stopReason === "error") {
    turn.failures += 1;
    turn.error = { class: "ProviderError", message: message.errorMessage ?? "The model request failed" };
    const error = turn.error;
    void adapter.enqueue(session, async () => {
      const hooks = await adapter.client("model.error");
      if (!hooks) return;
      adapter.report(await hooks.modelError({ ...adapter.scope(session), model: selected, attempt: current, execution: { status: "executed" }, error }));
    });
    return;
  }
  // A retry that worked: the failure before it does not decide the turn.
  turn.error = undefined;
  turn.failures = 0;
  const id = messageId(session.id, message);
  const answer = blocks(message.content).filter((block: Block) => block.type === "text").map((block: Block) => block.text ?? "").join("\n");
  if (answer) turn.answer = { id, text: answer };
  if (toolCalls.length) {
    turn.batch = {
      id: `${current.id}:batch`,
      calls: toolCalls.map((block: Block) => ({ id: block.id ?? "", name: block.name ?? "", input: (block.arguments ?? {}) as Record<string, unknown> })),
      open: new Set(toolCalls.map((block: Block) => block.id ?? "")),
    };
  }
  const { usage } = message;
  void adapter.enqueue(session, async () => {
    const hooks = await adapter.client("model.response.after");
    if (!hooks) return;
    adapter.report(await hooks.modelResponseAfter({
      ...adapter.scope(session),
      model: selected,
      attempt: current,
      execution: { status: "executed" },
      finishReason: message.stopReason ?? "stop",
      items: [canonical(session.id, message)] as never,
      ...(usage ? {
        usage: {
          kind: "amount" as const,
          scope: "attempt" as const,
          provenance: "provider" as const,
          completeness: "complete" as const,
          inputTokens: usage.input ?? 0,
          outputTokens: usage.output ?? 0,
          ...(usage.cacheRead ? { cacheReadTokens: usage.cacheRead } : {}),
          ...(usage.cacheWrite ? { cacheWriteTokens: usage.cacheWrite } : {}),
        },
      } : {}),
    }, { initialState: state.initial(Permission.None) }));
  });
}
