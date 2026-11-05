// OpenClaw's messages as canonical AHP content, and effective content back onto
// them. Structured values (tool calls) travel as their JSON in a text part; images
// are attachments, uploaded only when a subscription selects the body.
import { Attachment } from "agenthooksprotocol/client";

export type Role = "system" | "developer" | "user" | "assistant" | "tool";

export type TextPart = {
  id: string;
  kind: "text";
  mediaType: "text/plain";
  selection: "body";
  text: string;
  category?: string;
};

export type AttachmentPart = { id: string; kind: "attachment"; mediaType: string; body: Attachment; category?: string };

export type Part = TextPart | AttachmentPart;

export type Message = {
  id: string;
  role: Role;
  parts: Part[];
  synthesized?: boolean;
};

/** A value as the JSON the SDK's payload types declare. */
export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
export function json<T = { [key: string]: Json }>(value: unknown): T {
  return value as T;
}

export function textPart(id: string, text: string, category?: string): TextPart {
  return { id, kind: "text", mediaType: "text/plain", selection: "body", text, ...(category ? { category } : {}) };
}

export function message(id: string, role: Role, text: string, options: { category?: string; synthesized?: boolean } = {}): Message {
  return {
    id,
    role,
    parts: [textPart(`${id}#0`, text, options.category)],
    ...(options.synthesized ? { synthesized: true } : {}),
  };
}

export function asText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** The text of every part of the messages, in order. */
export function texts(messages: readonly unknown[] | undefined): string[] {
  const out: string[] = [];
  for (const entry of messages ?? []) {
    const parts = (entry as { parts?: unknown[] })?.parts;
    for (const part of parts ?? []) {
      const text = (part as { text?: unknown })?.text;
      if (typeof text === "string" && text !== "") out.push(text);
    }
  }
  return out;
}

/** A block of an OpenClaw message's content. */
export type Block = {
  type: string;
  text?: string;
  thinking?: string;
  data?: string;
  mimeType?: string;
  id?: string;
  name?: string;
  arguments?: unknown;
};

export type NativeMessage = {
  role: string;
  content?: string | readonly Block[];
  timestamp?: number;
  toolCallId?: string;
  customType?: string;
};

export function blocks(content: string | readonly Block[] | undefined): readonly Block[] {
  if (typeof content === "string") return [{ type: "text", text: content }];
  return content ?? [];
}

/** Content blocks as canonical parts, by position: effective parts find their
 * blocks again by these ids. */
export function partsOf(id: string, content: string | readonly Block[] | undefined): Part[] {
  return blocks(content).flatMap((block, index): Part[] => {
    const partId = `${id}#${index}`;
    switch (block.type) {
      case "text":
        return [textPart(partId, block.text ?? "")];
      case "thinking":
        return [textPart(partId, block.thinking ?? "", "reasoning")];
      case "toolCall":
        return [textPart(partId, asText({ id: block.id, name: block.name, arguments: block.arguments }), "tool_call")];
      case "image": {
        const data = block.data ?? "";
        return [{ id: partId, kind: "attachment", mediaType: block.mimeType ?? "application/octet-stream", body: Attachment.lazy(() => new Uint8Array(Buffer.from(data, "base64"))) }];
      }
      default:
        return [];
    }
  });
}

const ROLES: Record<string, Role> = { user: "user", assistant: "assistant", toolResult: "tool", system: "system" };

/** A message's identity: its timestamp stays put across a run's requests. `seen`
 * tells apart two in one millisecond. */
export function messageId(session: string, native: NativeMessage, seen?: Map<string, number>): string {
  if (native.role === "toolResult" && native.toolCallId) return `${native.toolCallId}:result`;
  const base = `${session}:${native.role}:${native.timestamp ?? 0}`;
  const count = seen?.get(base) ?? 0;
  seen?.set(base, count + 1);
  return count ? `${base}:${count}` : base;
}

export function canonical(session: string, native: NativeMessage, seen?: Map<string, number>): Message {
  const id = messageId(session, native, seen);
  return { id, role: ROLES[native.role] ?? "user", synthesized: true, parts: partsOf(id, native.content) };
}

const REPORTED = new Set(["text", "thinking", "toolCall", "image"]);

/** Effective parts back onto a tool result's blocks. Returns the same array when
 * nothing differs. */
export function applyParts(id: string, content: readonly Block[], effective: readonly Part[] | undefined): readonly Block[] {
  if (!effective) return content;
  const byId = new Map(effective.map((part) => [part.id, part]));
  const known = new Set(content.map((_, index) => `${id}#${index}`));
  let changed = false;
  const next: Block[] = [];
  content.forEach((block, index) => {
    // partsOf does not report it, so no backend can have meant to leave it out.
    if (!REPORTED.has(block.type)) {
      next.push(block);
      return;
    }
    const part = byId.get(`${id}#${index}`);
    if (!part) {
      changed = true;
      return;
    }
    const text = (part as TextPart).text;
    if (typeof text === "string" && (block.type !== "text" || text !== block.text)) {
      changed = true;
      next.push(block.type === "text" ? { ...block, text } : { type: "text", text });
    } else {
      next.push(block);
    }
  });
  for (const part of effective) {
    if (known.has(part.id) || typeof (part as TextPart).text !== "string") continue;
    changed = true;
    next.push({ type: "text", text: (part as TextPart).text });
  }
  return changed ? next : content;
}
