// Channel traffic, which `openclaw agent` does not raise: before_dispatch for what
// arrives, message_sending for what leaves.
import { Permission, state } from "agenthooksprotocol/client";
import type { Adapter } from "../adapter.js";
import { message, texts } from "../content.js";
import { denial } from "../effects.js";
import { AWAIT } from "./turns.js";

/** Shows the transcript's text, whatever delivery is told: a reply here is a report. */
const TRANSCRIPT_CHANNEL = "webchat";

export function messages(adapter: Adapter): void {
  const { api } = adapter;

  api.on("before_dispatch", async (event, ctx) => {
    const key = event.sessionKey ?? ctx.sessionKey;
    // The first message of a session comes before the session does.
    const known = key ? adapter.sessions.get(key) : undefined;
    if (known) await adapter.flush(known);
    const hooks = await adapter.client("user.message.inbound");
    if (!hooks) return;
    const id = `${event.messageId ?? crypto.randomUUID()}:inbound`;
    const result = await hooks.userMessageInbound({
      ...(known ? adapter.scope(known) : {}),
      message: {
        channel: event.channel ?? ctx.channelId ?? "unknown",
        sender: event.senderId ?? "unknown",
        messages: [message(id, "user", event.content, { synthesized: true }) as never],
      },
    }, { initialState: state.initial(Permission.None) });
    adapter.report(result);
    const refused = denial(result);
    return refused === undefined ? undefined : { handled: true, text: refused };
  }, AWAIT);

  /** A reply's text as a backend leaves it. `refused` when one cancels it. */
  async function outbound(key: string | undefined, channel: string | undefined, content: string) {
    const known = key ? adapter.sessions.get(key) : undefined;
    if (known) await adapter.flush(known);
    const hooks = await adapter.client("user.message.outbound");
    if (!hooks) return {};
    const id = `${crypto.randomUUID()}:outbound`;
    const result = await hooks.userMessageOutbound({
      ...(known ? adapter.scope(known) : {}),
      message: {
        channel: channel ?? "unknown",
        messages: [message(id, "assistant", content, { synthesized: true }) as never],
      },
    }, { initialState: state.initial(Permission.None), ...(channel === TRANSCRIPT_CHANNEL ? { capabilities: { effects: [] } as never } : {}) });
    adapter.report(result);
    if (channel === TRANSCRIPT_CHANNEL) return {};
    const refused = denial(result);
    if (refused !== undefined) return { refused };
    const effective = texts((result.event as { message?: { messages?: unknown[] } }).message?.messages).join("\n");
    return effective && effective !== content ? { text: effective } : {};
  }

  // An agent's replies, on every route. Webchat raises only this.
  api.on("reply_payload_sending", async (event, ctx) => {
    const content = event.payload.text;
    if (!content) return;
    const key = event.sessionKey ?? ctx.sessionKey;
    const answer = await outbound(key, event.channel ?? ctx.channelId, content);
    if (answer.refused !== undefined) return { cancel: true, reason: answer.refused };
    // It comes to message_sending next, and is the same message.
    const known = key ? adapter.sessions.get(key) : undefined;
    if (known) known.reviewed = answer.text ?? content;
    return answer.text ? { payload: { ...event.payload, text: answer.text } } : undefined;
  }, AWAIT);

  // Whatever else leaves: what a tool sends, and channel deliveries of a reply.
  api.on("message_sending", async (event, ctx) => {
    const known = ctx.sessionKey ? adapter.sessions.get(ctx.sessionKey) : undefined;
    if (known?.reviewed !== undefined) {
      const same = known.reviewed === event.content;
      known.reviewed = undefined;
      if (same) return;
    }
    const answer = await outbound(ctx.sessionKey, ctx.channelId, event.content);
    if (answer.refused !== undefined) return { cancel: true, cancelReason: answer.refused };
    return answer.text ? { content: answer.text } : undefined;
  }, AWAIT);
}
