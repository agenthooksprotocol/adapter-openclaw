# Agent Hooks Protocol adapter for OpenClaw

An [OpenClaw](https://openclaw.ai) plugin that delivers the Gateway's events to
[Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol)
backends and applies their effects natively. It is built on the
[AHP TypeScript SDK](https://github.com/agenthooksprotocol/typescript-sdk).

It needs OpenClaw 2026.9.36 or later (and so Node 24), and is tested against 2026.9.36
and 2026.10.10.

## Install

```sh
openclaw plugins install npm:@agenthooksprotocol/adapter-openclaw --accept-capabilities
openclaw config set plugins.entries.agent-hooks-protocol.hooks.allowConversationAccess true
```

`--accept-capabilities` consents to the plugin rewriting tool results before the model
reads them. `allowConversationAccess` lets it see prompts and responses. Without it,
turn and model events are left out with a warning: tool policy still holds.

## Register backends

The adapter reads AHP registrations (the spec's `hooks.json`) from two places and
merges them into one document:

| File | Scope |
| --- | --- |
| `~/.agents/hooks.json` | user |
| `~/.openclaw/hooks.json` (`$OPENCLAW_STATE_DIR`) | user |

Later rows win: a backend in a later file replaces the backend with the same `id` from
an earlier one. A file or backend that is not valid is skipped with a warning, and the
others still run.

A workspace's files are not read. One Gateway serves many workspaces, and an agent can
write to its own: a file there could choose where session content goes, or turn off the
policy that governs the agent writing it.

```json
{
  "protocolVersion": "draft",
  "hooks": [
    {
      "id": "com.example.policy",
      "transport": { "type": "http", "url": "https://hooks.example/ahp" },
      "subscriptions": [
        {
          "mode": "intercept",
          "events": ["tool.before", "turn.start"],
          "timeoutMs": 2000,
          "failurePolicy": "fail-closed",
          "content": { "default": "body" }
        }
      ]
    }
  ]
}
```

Omit `subscriptions` to let the backend choose them (server-driven configuration).

Set `AHP_HOOKS_FILE` to one registration's absolute path to use that file alone, with
no discovery (tests, CI, a pinned deployment). Set `AHP_DEBUG=1` to log what the
adapter loaded and each delivery diagnostic.

The registration is read once, when the Gateway's first event needs it: restart the
Gateway after changing one.

## What it covers

24 of AHP's 32 events. The manifest's `gaps` say what each leaves out.

| AHP event | OpenClaw | A backend can |
| --- | --- | --- |
| `session.start` | `session_start`, or a session's first run | add context to the next prompt |
| `session.end` | `session_end` | observe |
| `turn.start` | first hook of a run | refuse (`before_agent_run`), add context (`before_prompt_build`) |
| `turn.progress` | the agent event stream | observe |
| `turn.finish.before` | `before_agent_finalize` | ask for another pass, up to 3, or stop |
| `turn.end` | `agent_end` | observe |
| `model.request.before` | `model_call_started` | observe |
| `model.response.after` | `before_message_write` | observe |
| `model.error` | a failed response | observe |
| `model.switch.after` | a session patch, or a fallback | observe |
| `tool.before` | `before_tool_call` | refuse, rewrite the input, ask, add context |
| `tool.after` | tool result middleware, `after_tool_call` | rewrite the result, add context |
| `tool.progress` | the agent event stream | observe |
| `tool.batch.after` | a model response's last call | observe |
| `tool.permission.request` | a backend's `ask` | allow, refuse, rewrite the input |
| `tool.permission.resolved` | the approval's outcome | observe |
| `context.compact.before`, `.after` | `before_compaction`, `after_compaction` | observe |
| `config.change.after` | `session:patch` | observe |
| `file.changed` | the `write`, `edit` and `apply_patch` tools | observe |
| `user.attention` | a backend's `ask` | observe |
| `user.message.inbound` | `before_dispatch` | refuse |
| `user.message.outbound` | `reply_payload_sending`, `message_sending` | refuse, rewrite, on a channel |
| `hook.failure` | the SDK | observe |

### Where it falls short

- **No per-request control.** OpenClaw only reports a model request. Refuse at
  `turn.start` or `tool.before`; neither a request nor a response can be rewritten.
- **`turn.start` cannot rewrite a prompt**, only refuse it or add to it. The refusal
  holds on the embedded and CLI runners and node admission, not on Codex or Copilot
  harness turns.
- **`turn.finish.before` cannot continue a run that has called a tool:** OpenClaw makes
  no further pass of one, so only stop is offered then.
- **With tool search on (OpenClaw's default),** the dispatching tool and the tool it
  calls are each reported. Policy on the inner call holds, but its output is rewritten
  at the dispatching call's `tool.after`.
- **`tool.before` has no `allow` or `return`.** A plugin cannot answer OpenClaw's own
  exec approvals, and a blocked call's result is always an error to the model.
- **`ask` needs someone to answer.** It goes to OpenClaw's plugin approvals. With no
  connected approval surface the call is blocked, and the model is told why. It is not
  offered at all under `openclaw agent --local`.
- **Webchat replies are only reported.** Webchat shows the transcript's text. On any
  other channel a reply can be refused or rewritten, and the transcript keeps what the
  model said.
- **The `message` effect is not offered:** a plugin has nowhere to show one to a person.
- **Compaction is observe-only**, and only finished compactions report.
- **Only tools report file changes:** a shell command's do not count.
- **OpenClaw's hook timeouts are raised to 10 minutes** so a subscription's own
  `timeoutMs` decides. An operator's `plugins.entries.<id>.hooks.timeoutMs` still wins,
  and when one expires OpenClaw blocks a tool call or a run, but lets a prompt, a
  finalize or a message through.
- **Other plugins:** this plugin's `before_tool_call` runs last and is shown the call as
  the model made it, so another plugin's rewrite of the same call is not reported.
- **Not covered by tests:** Codex and agentsapi runs, `POST /tools/invoke`, and a real
  provider.

## Develop

```sh
npm install
npm run check   # typecheck, unit tests, end-to-end tests on both OpenClaw versions
```

The end-to-end tests need Node 24 and bun. They install the packed plugin into a real
Gateway under a temporary home, with a local fake model, a recording backend and a
recording channel. Nothing reaches a real provider or backend.
