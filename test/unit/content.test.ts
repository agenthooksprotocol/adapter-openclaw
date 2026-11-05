import { describe, expect, test } from "bun:test";
import { mcpPrefix } from "../../src/events/tools";
import { applyParts, canonical, messageId, partsOf, texts, textPart } from "../../src/content";
import { capabilities, capabilitiesFor, narrow } from "../../src/capabilities";

describe("content", () => {
  test("blocks become parts by position", () => {
    const parts = partsOf("m", [{ type: "text", text: "hi" }, { type: "thinking", thinking: "hm" }, { type: "toolCall", id: "c", name: "t", arguments: { a: 1 } }]);
    expect(parts.map((part) => part.id)).toEqual(["m#0", "m#1", "m#2"]);
    expect(parts[1]!.category).toBe("reasoning");
    expect(parts[2]!.category).toBe("tool_call");
  });

  test("a tool result takes its call's identity", () => {
    expect(messageId("s", { role: "toolResult", toolCallId: "c" })).toBe("c:result");
  });

  test("two messages in one millisecond stay apart", () => {
    const seen = new Map<string, number>();
    expect(messageId("s", { role: "user", timestamp: 1 }, seen)).not.toBe(messageId("s", { role: "user", timestamp: 1 }, seen));
  });

  test("a custom message reads as the user's", () => {
    expect(canonical("s", { role: "custom", content: "x", timestamp: 1 }).role).toBe("user");
  });

  test("effective parts replace, drop and add", () => {
    const content = [{ type: "text", text: "a" }, { type: "text", text: "b" }];
    expect(applyParts("r", content, [textPart("r#0", "A"), textPart("r#9", "new")])).toEqual([{ type: "text", text: "A" }, { type: "text", text: "new" }]);
  });

  test("text in an image's place replaces the image", () => {
    const content = [{ type: "image", data: "x", mimeType: "image/png" }];
    expect(applyParts("r", content, [textPart("r#0", "redacted")])).toEqual([{ type: "text", text: "redacted" }]);
  });

  test("a block no backend was shown stays", () => {
    const content = [{ type: "text", text: "a" }, { type: "other" }];
    expect(applyParts("r", content, [textPart("r#0", "a")])).toBe(content);
  });

  test("nothing different gives the same array", () => {
    const content = [{ type: "text", text: "a" }];
    expect(applyParts("r", content, [textPart("r#0", "a")])).toBe(content);
  });

  test("texts reads every part", () => {
    expect(texts([{ parts: [{ text: "a" }, { text: "" }] }, { parts: [{ text: "b" }] }])).toEqual(["a", "b"]);
  });
});

describe("capabilitiesFor", () => {
  const all = { conversation: true, promptInjection: true, gateway: true };

  test("with every grant, in a Gateway, everything", () => {
    expect(capabilitiesFor(all)).toEqual(capabilities);
  });

  test("outside a Gateway nobody can answer ask", () => {
    const toolBefore = capabilitiesFor({ ...all, gateway: false }).toolBefore as { intercept: Record<string, unknown> };
    expect(toolBefore.intercept.ask).toBeUndefined();
    expect(toolBefore.intercept.deny).toBe(true);
  });

  test("without conversation access, its events are not offered", () => {
    const result = capabilitiesFor({ ...all, conversation: false });
    expect(result.turnStart).toBeUndefined();
    expect(result.modelRequestBefore).toBeUndefined();
    expect(result.toolBefore).toBeDefined();
  });

  test("without prompt injection, nothing reaches a prompt", () => {
    const result = capabilitiesFor({ ...all, promptInjection: false });
    expect((result.turnStart as { intercept: Record<string, unknown> }).intercept.inject).toBeUndefined();
    expect((result.sessionStart as { intercept?: unknown }).intercept).toBeUndefined();
  });
});

describe("narrow", () => {
  const backend = (subscriptions: unknown[]) => ({ id: "b", subscriptions });

  test("what is offered stays as it is", () => {
    const hooks = [backend([{ mode: "intercept", events: ["tool.before"] }, { mode: "observe", events: ["turn.end"] }])];
    expect(narrow(hooks, capabilities)).toEqual({ hooks, removed: [] });
  });

  test("an event left out goes, and the rest of the backend stays", () => {
    const offered = capabilitiesFor({ conversation: false, promptInjection: true, gateway: true });
    const { hooks, removed } = narrow([backend([{ mode: "intercept", events: ["turn.start", "tool.before"] }, { mode: "observe", events: ["turn.end"] }])], offered);
    expect(hooks[0]!.subscriptions).toEqual([{ mode: "intercept", events: ["tool.before"] }]);
    expect(removed).toEqual(["b: turn.start", "b: turn.end"]);
  });

  test("an event that is only observed cannot be intercepted", () => {
    const { removed } = narrow([backend([{ mode: "intercept", events: ["model.request.before"] }])], capabilities);
    expect(removed).toEqual(["b: model.request.before"]);
  });

  test("a wildcard is the SDK's to resolve", () => {
    const hooks = [backend([{ mode: "intercept", events: ["tool.*"] }, { mode: "observe", events: ["*"] }])];
    expect(narrow(hooks, capabilities)).toEqual({ hooks, removed: [] });
  });

  test("a backend with nothing left goes, rather than being invalid", () => {
    const offered = capabilitiesFor({ conversation: false, promptInjection: true, gateway: true });
    expect(narrow([backend([{ mode: "observe", events: ["turn.end"] }])], offered).hooks).toEqual([]);
  });

  test("a subscription without an event list is the SDK's to judge", () => {
    const hooks = [backend([{ mode: "observe" }])];
    expect(narrow(hooks, capabilities).hooks).toEqual(hooks);
  });
});

describe("mcpPrefix", () => {
  test("follows how OpenClaw names a server's tools", () => {
    expect(mcpPrefix("my-docs")).toBe("my-docs__");
    expect(mcpPrefix("MyDocs")).toBe("mydocs__");
    expect(mcpPrefix("docs.v2")).toBe("docs-v2__");
  });
});
