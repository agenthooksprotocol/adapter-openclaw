// What this adapter can enforce through OpenClaw's plugin API, and what it cannot.
// Everything here is optional for an AHP runtime: an event or effect left out is
// simply not advertised, and the gaps say why.
import { capabilityCount, type HostCapabilities } from "agenthooksprotocol/client";

/** Revisions the embedded runner allows in one run. A fourth is not asked about. */
export const MAX_CONTINUATIONS = 3;

const injectNow = { context: { append: true, deliverAt: ["now"] } } as const;

export const capabilities = {
  // session_start: its context rides on the session's next prompt.
  sessionStart: { observe: true, intercept: { inject: injectNow } },
  sessionEnd: { observe: true },

  // before_agent_run refuses; before_prompt_build adds to the prompt.
  turnStart: { observe: true, intercept: { deny: true, inject: injectNow } },
  turnProgress: { observe: true },
  // before_agent_finalize: revise is another pass, finalize ends it.
  turnFinishBefore: {
    observe: true,
    intercept: {
      flow: {
        operations: ["continue", "stop"],
        remainingContinuations: capabilityCount(MAX_CONTINUATIONS),
        continuationCount: capabilityCount(0),
        maxContinuations: capabilityCount(MAX_CONTINUATIONS),
      },
    },
  },
  turnEnd: { observe: true },

  modelRequestBefore: { observe: true },
  modelResponseAfter: { observe: true },
  modelError: { observe: true },
  modelSwitchAfter: { observe: true },

  // before_tool_call blocks, rewrites and asks; the tool result middleware rewrites
  // what the model reads. `ask` needs the Gateway's approval surfaces.
  toolBefore: {
    observe: true,
    intercept: { deny: true, ask: true, modifyInput: "replace-and-merge", inject: injectNow },
  },
  toolAfter: { observe: true, intercept: { modifyOutput: "replace-and-merge", inject: injectNow } },
  toolProgress: { observe: true },
  toolBatchAfter: { observe: true },
  // Raised when a backend asks at tool.before: another may answer before a person is asked.
  toolPermissionRequest: { observe: true, intercept: { allow: true, deny: true, modifyInput: "replace-and-merge" } },
  toolPermissionResolved: { observe: true },

  contextCompactBefore: { observe: true },
  contextCompactAfter: { observe: true },

  configChangeAfter: { observe: true },
  fileChanged: { observe: true },
  userAttention: { observe: true },
  // before_dispatch claims a message; reply_payload_sending and message_sending
  // rewrite or cancel what leaves.
  userMessageInbound: { observe: true, intercept: { deny: true } },
  userMessageOutbound: { observe: true, intercept: { deny: true, modifyContent: "replace" } },
  hookFailure: { observe: true },
} satisfies HostCapabilities;

/** The events whose native hooks OpenClaw holds back without `allowConversationAccess`. */
const NEEDS_CONVERSATION = ["turnStart", "turnFinishBefore", "turnEnd", "turnProgress", "modelRequestBefore", "modelResponseAfter", "modelError", "toolBatchAfter"] as const;

export interface Grants {
  /** `plugins.entries.<id>.hooks.allowConversationAccess` */
  conversation: boolean;
  /** `plugins.entries.<id>.hooks.allowPromptInjection` */
  promptInjection: boolean;
  /** Running in a Gateway: `--local` has no approval surface to ask on. */
  gateway: boolean;
}

function without<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const { [key]: _removed, ...rest } = value;
  return rest;
}

/** What holds under the operator's grants. A registration naming an event left out
 * here is refused with a warning, rather than left silently unenforced. */
export function capabilitiesFor(grants: Grants): HostCapabilities {
  const result: Record<string, unknown> = { ...capabilities };
  if (!grants.gateway) result.toolBefore = { observe: true, intercept: without(capabilities.toolBefore.intercept, "ask") };
  // Context reaches a prompt through hooks that need both grants.
  if (!grants.conversation || !grants.promptInjection) {
    result.sessionStart = { observe: true };
    result.turnStart = { observe: true, intercept: without(capabilities.turnStart.intercept, "inject") };
  }
  if (!grants.conversation) for (const name of NEEDS_CONVERSATION) delete result[name];
  return result as HostCapabilities;
}

type Subscription = { mode?: unknown; events?: unknown };

/** A registration without what these capabilities leave out, and what that was. A
 * registration naming an unadvertised event is invalid as a whole, and a missing
 * grant must not take a backend's tool policy down with its turn events. */
export function narrow(hooks: Record<string, unknown>[], offered: HostCapabilities): { hooks: Record<string, unknown>[]; removed: string[] } {
  const removed: string[] = [];
  const kept = hooks.flatMap((backend) => {
    if (!Array.isArray(backend.subscriptions) || !backend.subscriptions.length) return [backend];
    const subscriptions = (backend.subscriptions as Subscription[]).flatMap((subscription) => {
      if (!Array.isArray(subscription.events)) return [subscription];
      const events = (subscription.events as string[]).filter((event) => {
        // The SDK resolves a wildcard against what is offered.
        if (event.includes("*")) return true;
        const capability = (offered as Record<string, { observe?: boolean; intercept?: unknown } | undefined>)[event.replace(/\.(.)/g, (_, letter: string) => letter.toUpperCase())];
        const available = subscription.mode === "intercept" ? capability?.intercept : capability?.observe;
        if (!available) removed.push(`${String(backend.id)}: ${event}`);
        return Boolean(available);
      });
      return events.length ? [{ ...subscription, events }] : [];
    });
    // Nothing left is not the same as leaving a backend to choose: it has no place here.
    return subscriptions.length ? [{ ...backend, subscriptions }] : [];
  });
  return { hooks: kept, removed };
}

/** Coverage OpenClaw's plugin API does not reach, as manifest gaps. */
export const gaps = [
  { path: "message", reason: "a plugin has no surface to show a person a message on: the message effect is not advertised" },
  { path: "turn.start.modify", reason: "OpenClaw's hooks add to a prompt but do not rewrite it" },
  { path: "turn.start.runtimes", reason: "before_agent_run is implemented by the embedded and CLI runners and node admission: Codex and Copilot harness turns cannot be refused here" },
  { path: "turn.finish.before.continue", reason: "OpenClaw will not make another pass of a run that has called a tool: only stop is offered then" },
  { path: "hooks.timeouts", reason: "OpenClaw lets a prompt, finalize or message through when its hook times out: an operator's plugins.entries.<id>.hooks.timeoutMs below a subscription's own timeout can skip that policy" },
  { path: "hooks.other_plugins", reason: "this plugin's hook runs last and sees the call as the model made it: another plugin's rewrite or requireApproval of the same call is not reported, and an approval freezes the input" },
  { path: "turn.finish.before.modify", reason: "the answer is recorded before finalization: rewrite a reply at user.message.outbound" },
  { path: "model.request.before.intercept", reason: "OpenClaw raises only observations per model request: refuse at turn.start or tool.before" },
  { path: "model.response.after.intercept", reason: "the only hook that sees a response before it is recorded is synchronous, and a backend is not" },
  { path: "model.switch.before", reason: "before_model_resolve overrides a model but does not report a switch being asked for" },
  { path: "tool.before.allow", reason: "a plugin cannot answer OpenClaw's own exec approvals, so allow could not be kept" },
  { path: "tool.before.return", reason: "a blocked call's result is always an error to the model, and the result middleware does not run for it" },
  { path: "tool.before.ask.route", reason: "with no connected approval surface OpenClaw blocks the call and says so: it runs only if a person approves" },
  { path: "tool.after.unexecuted", reason: "a call that never ran has no result middleware: tool.after reports it and cannot change it" },
  { path: "tool.after.direct", reason: "POST /tools/invoke and the MCP loopback used by CLI backends run tools outside the agent loop: tool.before holds there, and tool.after may not be raised" },
  { path: "tool.runtimes", reason: "Codex and agentsapi runs go through their own relays and are not covered by this adapter's tests" },
  { path: "tool.permission.request.native", reason: "OpenClaw's exec approvals are not visible to plugins: the stage exists only when a backend asks at tool.before" },
  { path: "tool.batch.after.intercept", reason: "OpenClaw has no batch boundary: the event is reported once a model request's calls have resolved" },
  { path: "tool.dispatch", reason: "with tool search on, the dispatching tool and the tool it calls are each reported: the inner call's tool.after is a report, and its output is rewritten at the dispatching call's" },
  { path: "tool.mcp.names", reason: "an MCP tool is recognised by its configured server's name: a server renamed to keep names unique reports as native" },
  { path: "context.compact.before.intercept", reason: "before_compaction is an observation with no veto or rewrite" },
  { path: "context.compact.before.items", reason: "before_compaction usually reports counts, not the messages" },
  { path: "context.compact.after.failed", reason: "OpenClaw reports only compactions that completed" },
  { path: "context.compact.after.summary", reason: "after_compaction reports counts, not the summary or the messages it replaced" },
  { path: "user.message.outbound.bypass", reason: "OpenClaw delivers a message when these hooks time out or fail" },
  { path: "user.message.inbound.modify", reason: "before_dispatch claims a message but does not rewrite it" },
  { path: "user.message.inbound.session", reason: "a channel's message can arrive before its session exists: such an event has no session" },
  { path: "user.message.outbound.webchat", reason: "webchat shows the transcript's text: a reply there is reported and cannot be changed" },
  { path: "user.message.outbound.media", reason: "a reply's text is reported and rewritten: its media is delivered as it is" },
  { path: "user.message.outbound.transcript", reason: "a reply is rewritten for delivery: the transcript keeps what the model said" },
  { path: "config.change.before", reason: "OpenClaw raises no event before a setting changes" },
  { path: "config.change.after.settings", reason: "only per-session changes are reported: edits to openclaw.json are not" },
  { path: "workspace.change", reason: "a workspace belongs to an agent's configuration: nothing moves one during a session" },
  { path: "task.change", reason: "OpenClaw's task hooks are not exposed to plugins" },
  { path: "user.elicitation", reason: "OpenClaw does not surface MCP elicitation or ask_user to plugins" },
  { path: "file.changed.exec", reason: "only the write, edit and apply_patch tools' changes are reported" },
  { path: "session.subagent", reason: "a subagent is reported under its root session with session.agent: its own session events are not" },
];
