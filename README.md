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
adapter loaded and each delivery diagnostic, with its authentication failure code.

The registration is read once, when the Gateway's first event needs it: restart the
Gateway after changing one.

## Sign in to a backend (OAuth)

A backend can ask for a bearer token from an OAuth authorization server. Bearer
bindings (`tokenEnv`, `tokenRef`) and `Authorization` headers work as before; OAuth
needs OpenClaw 2026.10.10 or later (2026.9.36 keeps plugin state from plugins it
does not trust, so there sign-in is unavailable and deliveries go on without it).

Every backend has its own sign-in. One consent covers that backend's event and
upload endpoints, and is never shared with another backend. A backend with a usable
grant is never asked to sign in again.

**How a sign-in happens.** A delivery never starts one. When a backend refuses a
delivery for want of a token, or its `oauth` settings have no usable grant yet, the
next turn says so in the Gateway log, once until it is signed in:

```
Agent Hooks Protocol: sign-in needed for com.example.policy: run `openclaw ahp login com.example.policy` on the Gateway's host
```

`openclaw ahp login`, on the Gateway host's terminal, starts the sign-in and is the
only place its link is shown. Not in the Gateway log, which any operator with read
access can tail; not in a chat reply, because OpenClaw keeps those in the transcript
the model reads, and on a shared channel others would see it too. Whoever opens a
link binds their account to this Gateway. A link lasts 10 minutes at most. Each
`openclaw ahp login` has its own, so two can run at once; whichever finishes last
is the grant every process then uses.

The browser returns to the Gateway's own route, `/ahp/oauth/callback`, which
completes the sign-in and says "You can close this tab". It needs no Gateway
token: the OAuth state authenticates the callback. The Gateway can complete a login
that `openclaw ahp login` started because pending sign-ins are kept in plugin state,
which both share; the Gateway then starts delivering to that backend at its next
turn.

**Commands.** On the Gateway's host:

```sh
openclaw ahp status            # each backend: authorized, needs-login, client-credentials, bearer token, or failing: why
openclaw ahp login [backend]   # start a sign-in, print its link and wait; without a backend, every backend that needs it
openclaw ahp complete <url>    # finish with the address the browser ended on, if it could not reach the Gateway
openclaw ahp logout <backend>  # cancel its pending sign-in and delete its tokens
```

`openclaw ahp status` and `login` say so when the Gateway is not running, since a
link returns to it. `openclaw ahp login` on a terminal also accepts that address
pasted in. In chat, the
owner's `/ahp status`, `/ahp login [backend]` and `/ahp logout <backend>` do the same,
without ever putting a link in the reply: `/ahp login` points at `openclaw ahp login`.

Without a person (CI, `openclaw agent --local` in a script), the hint is only
logged: use client credentials. `openclaw agent exec` runs with a temporary state
directory, so it has no sign-in of the Gateway's: use client credentials, or
`--state-dir` to share the Gateway's.

### Settings

A backend's OAuth settings are an `oauth` object on its entry in `hooks.json`. The
same names mean the same in every AHP adapter, so one `~/.agents/hooks.json` serves
them all:

```json
{
  "id": "com.example.policy",
  "transport": { "type": "http", "url": "https://hooks.example/ahp" },
  "oauth": { "issuer": "https://auth.example", "registration": true, "scopes": ["hooks"] }
}
```

| Setting | Meaning |
| --- | --- |
| `issuer` | The authorization server trusted for this backend (or the `authentication` preset's). A backend's advertisement never chooses one by itself. Client credentials and client secrets always need it. |
| `trustAdvertisedIssuer` | Without `issuer`, trust the one issuer the backend advertises, for a public browser sign-in only. Default `false`. |
| `flow` | `authorization_code_pkce` (default) or `client_credentials`. |
| `scopes` | Scopes to request. |
| `clientId` | A client registered in advance. It always wins. |
| `clientSecretRef` | A key in the plugin config's `secrets`. |
| `clientMetadataDocument` | `{ "url", "redirectUris" }`: a Client ID Metadata Document you publish, used where the issuer supports them. `redirectUris` must include the Gateway's callback (a loopback one may leave out the port). The adapter publishes none of its own. |
| `registration` | `true`, or `{ "clientName", "scopes", "initialAccessTokenRef" }`: permission to register a client (RFC 7591) at `issuer`, which it requires. Each sign-in registers its own, for the Gateway's callback. |
| `loginLifetimeMinutes` | How long a sign-in link lasts, up to 10 (the default). |
| `allowPrivateNetwork` | Allow the authorization server on loopback or private addresses. Default `false`. |

The registration's own `oauth` preset (`issuer`, `resource`, `clientId`, `flow`,
`scopes`, `clientSecretRef`) works too; the `oauth` object's settings take
precedence. OAuth requests go only to HTTPS endpoints, follow no redirects, and
connect only to public addresses (unless `allowPrivateNetwork`).

What is OpenClaw's alone goes in the plugin config,
`plugins.entries.agent-hooks-protocol.config`:

| Setting | Meaning |
| --- | --- |
| `publicUrl` | The Gateway as a browser reaches it, behind a proxy or Tailscale: HTTPS, or HTTP on `127.0.0.1` or `[::1]` (not `localhost`), with no credentials, query or fragment (otherwise it is ignored with a warning). A path prefix is kept, for a proxy that strips it: the redirect is `<publicUrl>/ahp/oauth/callback`. By default it is `http://127.0.0.1:<port>/ahp/oauth/callback`, where the port is the one OpenClaw's CLI reaches the Gateway on: `OPENCLAW_GATEWAY_PORT`, else `gateway.port`. |
| `secrets` | `{ "<ref>": <secret> }` for `tokenRef`, `clientSecretRef` and `initialAccessTokenRef`. A secret is a string, or a SecretRef `{ "source": "env", "provider": "default", "id": "NAME" }` or `{ "source": "file", "provider": "…", "id": "/path" }`. |

### Where credentials live

- Tokens, refresh tokens, pending sign-ins, discovery results and registered client
  ids: OpenClaw's plugin state (the `ahp-oauth` namespace of its state database under
  `~/.openclaw`, or `$OPENCLAW_STATE_DIR`), shared by the Gateway and `openclaw ahp`.
  A short-lived lease row (`ahp-oauth-leases`), renewed atomically while held, keeps
  the two from refreshing or completing the same grant at once; a holder that loses
  its lease says so in the log, and its writes still go through only where the record's
  generation is unchanged.
- Client secrets that a registration issued: OpenClaw has no secret store a plugin
  can write, so each is a file of its own, mode `0600`, in
  `<state dir>/plugins/agent-hooks-protocol/oauth-secrets/` (mode `0700`), apart from
  the tokens. Secrets you configure stay in the plugin config's `secrets`.

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
recording channel, and for sign-in a fake OAuth authorization server over HTTPS
with a throwaway CA (they need `openssl`). Nothing reaches a real provider or backend.
