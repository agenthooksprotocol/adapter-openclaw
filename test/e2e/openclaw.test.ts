// The adapter inside a real OpenClaw Gateway, on the oldest and newest versions it
// claims: installed from a packed tarball the way a person would, with an isolated
// home, a local fake model and a recording AHP backend. Nothing here reaches a real
// backend or provider. Needs Node 24 or later on PATH, as OpenClaw does.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";

const REPO = resolve(import.meta.dir, "../..");
const root = realpathSync(mkdtempSync(join(tmpdir(), "ahp-openclaw-e2e-")));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const VERSIONS = [
  { name: "2026.9.36", dir: join(REPO, "node_modules/openclaw-floor") },
  { name: "2026.10.10", dir: join(REPO, "node_modules/openclaw") },
];

const PLUGIN = "agent-hooks-protocol";
let tarball = "";
beforeAll(async () => {
  const child = Bun.spawn(["npm", "pack", "--ignore-scripts", "--pack-destination", root], { cwd: REPO, stdout: "pipe", stderr: "pipe" });
  const output = await new Response(child.stdout).text();
  if ((await child.exited) !== 0) throw new Error(await new Response(child.stderr).text());
  tarball = join(root, output.trim().split("\n").at(-1)!);
}, 60000);

type Event = Record<string, any> & { type: string };
type Request = { model: string; tools?: { function?: { name?: string } }[]; messages: { role: string; content: unknown; tool_calls?: unknown[] }[] };
type Options = { toolSearch?: boolean; grants?: Record<string, boolean>; backends?: (recorder: Record<string, unknown>) => Record<string, unknown>[]; events?: { intercept: string[]; observe: string[] } };

const body = (text: string) => ({ kind: "text", mediaType: "text/plain", selection: "body", text });
const inject = (event: Event, text: string) => ({ type: "inject", target: "context", operation: "append", deliverAt: "now", value: [{ id: `i-${event.id}`, role: "user", parts: [{ id: `i-${event.id}#0`, ...body(text) }] }] });
const text = (content: unknown) => (typeof content === "string" ? content : ((content ?? []) as { text?: string }[]).map((part) => part.text ?? "").join("\n"));
const partsText = (items: unknown) => ((items ?? []) as { parts?: { text?: string }[] }[]).flatMap((item) => (item.parts ?? []).map((part) => part.text ?? "")).join("\n");

const OBSERVE = ["session.end", "turn.end", "turn.progress", "model.request.before", "model.response.after", "model.error", "model.switch.after", "tool.progress", "tool.batch.after", "tool.permission.resolved", "context.compact.before", "context.compact.after", "config.change.after", "file.changed", "user.attention"];
const INTERCEPT = ["session.start", "turn.start", "turn.finish.before", "tool.before", "tool.after", "tool.permission.request", "user.message.inbound", "user.message.outbound"];

async function freePort(): Promise<number> {
  return new Promise((done) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      server.close(() => done(port));
    });
  });
}

/** One real OpenClaw and everything around it. */
class World {
  readonly received: Event[] = [];
  readonly requests: Request[] = [];
  policy: (event: Event) => unknown[] = () => [];
  /** Deliveries of this type wait this long. */
  slow: { type: string; ms: number; session?: string } | undefined;
  /** What each delivery was told it may do, by event id. */
  readonly offered = new Map<string, Record<string, any>>();
  readonly dir: string;
  readonly home: string;
  readonly project: string;
  readonly state: string;
  port = 0;
  #backend: ReturnType<typeof Bun.serve>;
  #model: ReturnType<typeof Bun.serve>;
  #gateway?: ReturnType<typeof Bun.spawn>;
  #session = 0;

  constructor(readonly openclaw: string, readonly options: Options = {}) {
    this.dir = mkdtempSync(join(root, "world-"));
    this.home = join(this.dir, "home");
    this.state = join(this.home, ".openclaw");
    this.project = join(this.dir, "project");
    mkdirSync(this.state, { recursive: true });
    mkdirSync(this.project, { recursive: true });
    this.#backend = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: async (request) => {
        const wire = (await request.json()) as { id?: string; method: string; params: { event: Event; capabilities?: Record<string, any> } };
        this.received.push(wire.params.event);
        if (wire.params.capabilities) this.offered.set(wire.params.event.id, wire.params.capabilities);
        if (this.slow?.type === wire.params.event.type && (!this.slow.session || JSON.stringify(wire.params.event).includes(this.slow.session))) await Bun.sleep(this.slow.ms);
        if (wire.method === "hooks/observe") return new Response(null, { status: 202 });
        return Response.json({ jsonrpc: "2.0", id: wire.id, result: { protocolVersion: "draft", effects: this.policy(wire.params.event) } });
      },
    });
    this.#model = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      idleTimeout: 0,
      fetch: async (request) => {
        if (new URL(request.url).pathname.endsWith("/models")) return Response.json({ data: [{ id: "m", object: "model" }] });
        const incoming = (await request.json()) as Request;
        this.requests.push(incoming);
        const last = incoming.messages.at(-1)!;
        // What OpenClaw adds after a prompt does not hide it.
        const trailing = incoming.messages.slice(incoming.messages.findLastIndex((entry) => entry.role !== "user" && entry.role !== "system") + 1).filter((entry) => entry.role === "user").map((entry) => text(entry.content)).join("\n");
        if (trailing.includes("MODEL-FAILS")) return new Response("nope", { status: 400 });
        // A compaction's summary request quotes the conversation.
        const summarizing = trailing.includes("<conversation>");
        const call = last.role === "user" && !summarizing ? /CALL (\S+) (\{.*\})/.exec(trailing) : null;
        const both = last.role === "user" && trailing.includes("TWO-CALLS");
        const spawns = last.role === "user" && trailing.includes("TWO-SPAWNS");
        const chunk = (delta: unknown, finish: string | null = null) =>
          `data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: incoming.model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
        const frames = spawns
          ? [chunk({ role: "assistant", tool_calls: [0, 1].map((index) => ({ index, id: `call_spawn${index}_${crypto.randomUUID().slice(0, 6)}`, type: "function", function: { name: "sessions_spawn", arguments: JSON.stringify({ task: `work ${index}` }) } })) }), chunk({}, "tool_calls")]
          : both
          ? [chunk({ role: "assistant", tool_calls: ["one", "two"].map((name, index) => ({ index, id: `call_${name}_${crypto.randomUUID().slice(0, 6)}`, type: "function", function: { name: "exec", arguments: JSON.stringify({ command: `echo ${name}` }) } })) }), chunk({}, "tool_calls")]
          : call
            ? [chunk({ role: "assistant", tool_calls: [{ index: 0, id: `call_${crypto.randomUUID().slice(0, 8)}`, type: "function", function: { name: call[1], arguments: call[2] } }] }), chunk({}, "tool_calls")]
            : [chunk({ role: "assistant", content: "final " }), chunk({ content: "answer" }), chunk({}, "stop")];
        frames.push(`data: ${JSON.stringify({ id: "c", object: "chat.completion.chunk", created: 1, model: incoming.model, choices: [], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } })}\n\n`, "data: [DONE]\n\n");
        return new Response(frames.join(""), { headers: { "content-type": "text/event-stream" } });
      },
    });
    const content = { default: "body" };
    const recorder = {
      id: "org.example.recorder",
      transport: { type: "http", url: `http://127.0.0.1:${this.#backend.port}/ahp` },
      subscriptions: [
        { mode: "intercept", events: options.events?.intercept ?? INTERCEPT, timeoutMs: 30000, failurePolicy: "fail-closed", content },
        { mode: "observe", events: options.events?.observe ?? OBSERVE, content },
      ],
    };
    writeFileSync(join(this.dir, "hooks.json"), JSON.stringify({ protocolVersion: "draft", hooks: options.backends ? options.backends(recorder) : [recorder] }));
  }

  /** What the recording channel has been asked to send. */
  delivered(): string[] {
    const path = join(this.dir, "channel.log");
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((line) => (JSON.parse(line) as { text: string }).text);
  }

  get env(): Record<string, string> {
    return {
      CHANNEL_LOG: join(this.dir, "channel.log"),
      PATH: process.env.PATH!,
      HOME: this.home,
      OPENCLAW_STATE_DIR: this.state,
      OPENCLAW_CONFIG_PATH: join(this.home, "openclaw.json"),
      OPENCLAW_NO_RESPAWN: "1",
      AHP_HOOKS_FILE: join(this.dir, "hooks.json"),
      ...(process.env.AHP_DEBUG ? { AHP_DEBUG: "1" } : {}),
    };
  }

  writeConfig(extra: Record<string, unknown> = {}): void {
    const path = join(this.home, "openclaw.json");
    const previous = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {};
    writeFileSync(path, JSON.stringify({
      ...previous,
      gateway: { mode: "local", port: this.port, bind: "loopback", auth: { mode: "none" } },
      models: { providers: { fake: { baseUrl: `http://127.0.0.1:${this.#model.port}/v1`, api: "openai-completions", apiKey: "x", models: [{ id: "m", name: "m", contextWindow: 100000, maxTokens: 4000, input: ["text"], reasoning: false }, { id: "n", name: "n", contextWindow: 100000, maxTokens: 4000, input: ["text"], reasoning: false }] } } },
      agents: { defaults: { model: { primary: "fake/m" }, workspace: this.project } },
      tools: { profile: "full", ...(this.options.toolSearch ? {} : { toolSearch: false }) },
      mcp: { servers: Object.fromEntries(["my-docs", "Other.Docs"].map((name) => [name, { command: "node", args: [join(import.meta.dir, "mcp-server.mjs")], env: { SECRET_TOKEN: "do-not-leak" } }])) },
      ...extra,
    }, null, 2));
  }

  async cli(args: string[], timeoutMs = 90000): Promise<{ stdout: string; stderr: string; code: number }> {
    const child = Bun.spawn(["node", join(this.openclaw, "openclaw.mjs"), ...args], { cwd: this.project, env: this.env, stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: timeoutMs });
    const [stdout, stderr] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
    return { stdout, stderr, code: await child.exited };
  }

  /** The plugin as a person would install it. */
  async install(): Promise<void> {
    this.port = await freePort();
    this.writeConfig();
    const installed = await this.cli(["plugins", "install", tarball, "--force", "--accept-capabilities"], 180000);
    if (installed.code !== 0) throw new Error(`install: ${installed.stdout}\n${installed.stderr}`);
    // The README's second command.
    if (!this.options.grants) {
      const granted = await this.cli(["config", "set", `plugins.entries.${PLUGIN}.hooks.allowConversationAccess`, "true"]);
      if (granted.code !== 0) throw new Error(`config set: ${granted.stdout}\n${granted.stderr}`);
    }
    const config = JSON.parse(readFileSync(join(this.home, "openclaw.json"), "utf8"));
    if (this.options.grants) config.plugins.entries[PLUGIN] = { ...config.plugins.entries[PLUGIN], hooks: this.options.grants };
    config.plugins.load = { paths: [join(import.meta.dir, "channel-plugin")] };
    config.plugins.entries.recch = { enabled: true };
    config.channels = { recch: { enabled: true } };
    writeFileSync(join(this.home, "openclaw.json"), JSON.stringify(config, null, 2));
  }

  async start(): Promise<void> {
    await this.install();
    this.#gateway = Bun.spawn(["node", join(this.openclaw, "openclaw.mjs"), "gateway", "run", "--port", String(this.port)], {
      cwd: this.project,
      env: this.env,
      stdin: "ignore",
      stdout: Bun.file(join(this.dir, "gateway.log")),
      stderr: Bun.file(join(this.dir, "gateway.err")),
    });
    const started = Date.now();
    while (true) {
      const { code, stdout } = await this.cli(["gateway", "call", "health", "--json"], 20000);
      if (code === 0 && stdout.includes('"ok"')) break;
      if (Date.now() - started > 90000) throw new Error(`the Gateway did not start: ${this.log()}`);
      await Bun.sleep(500);
    }
  }

  log(): string {
    const read = (name: string) => (existsSync(join(this.dir, name)) ? readFileSync(join(this.dir, name), "utf8") : "");
    return `${read("gateway.log")}\n${read("gateway.err")}`;
  }

  sessionKey(): string {
    this.#session += 1;
    return `t${this.#session}-${crypto.randomUUID().slice(0, 6)}`;
  }

  of(type: string, key?: string): Event[] {
    return this.received.filter((event) => event.type === type && (!key || JSON.stringify(event.session ?? {}).includes(this.sessionIds.get(key) ?? key)));
  }

  /** Session key to OpenClaw's session id, learned from the run's reply. */
  readonly sessionIds = new Map<string, string>();

  /** A turn from `openclaw agent`, until its reply. */
  async say(key: string, words: string): Promise<{ reply: string; raw: any }> {
    const { stdout } = await this.cli(["agent", "--session-key", key, "-m", words, "--json"]);
    const start = stdout.indexOf("{");
    const raw = start >= 0 ? JSON.parse(stdout.slice(start)) : {};
    const result = raw.result ?? raw;
    const id = result.meta?.agentMeta?.sessionId ?? raw.sessionId;
    if (id) this.sessionIds.set(key, id);
    await this.settled();
    return { reply: (result.payloads ?? []).map((payload: { text?: string }) => payload.text ?? "").join("\n") || raw.error?.message || "", raw };
  }

  call(key: string, tool: string, args: unknown) {
    return this.say(key, `CALL ${tool} ${JSON.stringify(args)}`);
  }

  async rpc(method: string, params: unknown): Promise<any> {
    const { stdout } = await this.cli(["gateway", "call", method, "--params", JSON.stringify(params), "--json"]);
    return JSON.parse(stdout);
  }

  /** Observations arrive after the reply: wait for quiet. */
  async settled(ms = 400): Promise<void> {
    let count = -1;
    while (count !== this.received.length) {
      count = this.received.length;
      await Bun.sleep(ms);
    }
  }

  async until(done: () => boolean, what: string, ms = 30000): Promise<void> {
    const started = Date.now();
    while (!done()) {
      if (Date.now() - started > ms) throw new Error(`timed out waiting for ${what}: ${this.received.map((event) => event.type).slice(-12).join(" ")}`);
      await Bun.sleep(50);
    }
  }

  /** What the model read in the last request, as one string. */
  lastRequest(): string {
    return this.requests.at(-1)!.messages.map((entry) => text(entry.content)).join("\n");
  }

  /** An operator connected for the length of `work`. */
  async withOperator<T>(decision: string, work: (lines: Record<string, any>[]) => Promise<T>): Promise<T> {
    const lines: Record<string, any>[] = [];
    const script = join(import.meta.dir, "operator.mjs");
    const child = Bun.spawn(["node", script, join(this.openclaw, "dist/plugin-sdk/gateway-runtime.js"), `ws://127.0.0.1:${this.port}`, decision], { cwd: this.dir, env: this.env, stdin: "ignore", stdout: "pipe", stderr: "ignore" });
    void (async () => {
      const decoder = new TextDecoder();
      let buffer = "";
      for await (const chunk of child.stdout as unknown as AsyncIterable<Uint8Array>) {
        buffer += decoder.decode(chunk);
        let end: number;
        while ((end = buffer.indexOf("\n")) >= 0) {
          lines.push(JSON.parse(buffer.slice(0, end)));
          buffer = buffer.slice(end + 1);
        }
      }
    })();
    await this.until(() => lines.some((line) => line.ready), "the operator to connect");
    try {
      return await work(lines);
    } finally {
      child.kill();
    }
  }

  async stop(): Promise<void> {
    this.#gateway?.kill();
    await this.#gateway?.exited;
    this.#backend.stop(true);
    this.#model.stop(true);
  }
}

describe.each(VERSIONS)("OpenClaw $name", ({ dir }) => {
  let world: World;
  beforeAll(async () => {
    world = new World(dir);
    await world.start();
  }, 300000);
  afterAll(() => world.stop());
  const clear = () => {
    world.policy = () => [];
    world.received.length = 0;
    world.requests.length = 0;
  };

  test("reports a whole turn, with the prompt and system prompt in it", async () => {
    clear();
    const key = world.sessionKey();
    const { reply } = await world.say(key, "hello there");
    expect(reply).toBe("final answer");
    const types = world.received.map((event) => event.type).filter((type) => type !== "turn.progress");
    expect(types).toEqual(["session.start", "turn.start", "model.request.before", "model.response.after", "turn.finish.before", "turn.end"]);
    const [start] = world.of("turn.start");
    expect(partsText(start!.items)).toContain("hello there");
    expect(start!.trigger).toBe("user");
    const request = world.of("model.request.before")[0]!;
    expect(request.items[0].role).toBe("system");
    expect(partsText(request.items)).toContain("hello there");
    expect(request.model).toEqual({ id: "m", provider: "fake" });
    const response = world.of("model.response.after")[0]!;
    expect(partsText(response.items)).toBe("final answer");
    expect(response.usage.inputTokens).toBe(5);
    const end = world.of("turn.end")[0]!;
    expect(end.outcome).toBe("completed");
    expect(partsText(end.items)).toBe("final answer");
    for (const event of [request, response, end]) expect(event.turn.id).toBe(start!.turn.id);
    expect(world.of("session.start")[0]!.session.id).toBe(start!.session.id);
    expect(world.of("session.start")[0]!.manifest.gaps.length).toBeGreaterThan(0);
  });

  test("streams text as turn.progress", async () => {
    clear();
    await world.say(world.sessionKey(), "hello");
    const progress = world.of("turn.progress");
    expect(progress.length).toBeGreaterThan(0);
    expect(progress.map((event) => partsText([event.delta])).join("")).toContain("answer");
  });

  test("reports each request of a run with what it holds", async () => {
    clear();
    await world.call(world.sessionKey(), "exec", { command: "echo hi" });
    const requests = world.of("model.request.before");
    expect(requests).toHaveLength(2);
    expect(requests[0]!.attempt.id).not.toBe(requests[1]!.attempt.id);
    expect(partsText(requests[1]!.items)).toContain("hi");
    expect(requests[1]!.items.some((item: { role: string }) => item.role === "tool")).toBe(true);
  });

  test("reports a tool call from start to end", async () => {
    clear();
    await world.call(world.sessionKey(), "exec", { command: "echo hi" });
    const before = world.of("tool.before")[0]!;
    expect(before.tool).toMatchObject({ name: "exec", origin: "native", input: { command: "echo hi" } });
    const after = world.of("tool.after")[0]!;
    expect(after.outcome).toBe("ok");
    expect(after.execution).toEqual({ status: "executed" });
    expect(partsText(after.items)).toContain("hi");
    expect(after.call.id).toBe(before.call.id);
    expect(after.parentEventId).toBe(before.id);
    expect(world.of("tool.after")).toHaveLength(1);
    const batch = world.of("tool.batch.after")[0]!;
    expect(batch.calls.map((entry: { call: { id: string } }) => entry.call.id)).toEqual([before.call.id]);
  });

  test("reports a batch once all its calls have resolved", async () => {
    clear();
    await world.say(world.sessionKey(), "TWO-CALLS");
    expect(world.of("tool.after")).toHaveLength(2);
    const batches = world.of("tool.batch.after");
    expect(batches).toHaveLength(1);
    expect(batches[0]!.calls).toHaveLength(2);
  });

  test("reports what a running tool prints", async () => {
    clear();
    await world.call(world.sessionKey(), "exec", { command: "echo partial; sleep 1; echo done" });
    expect(world.of("tool.progress").map((event) => partsText([event.partialOutput])).join("")).toContain("partial");
  });

  test("reports files the write tool changes", async () => {
    clear();
    const path = join(world.project, `note-${crypto.randomUUID().slice(0, 6)}.txt`);
    await world.call(world.sessionKey(), "write", { path, content: "one" });
    await world.call(world.sessionKey(), "write", { path, content: "two" });
    const changes = world.of("file.changed").flatMap((event) => event.changes);
    expect(changes.map((change: { operation: string }) => change.operation)).toEqual(["create", "update"]);
    expect(changes[0].path).toBe(path);
  });

  test("a denied call does not run, and the model reads why", async () => {
    clear();
    const path = join(world.dir, "denied");
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "deny", reason: "NOT ALLOWED" }] : []);
    await world.call(world.sessionKey(), "exec", { command: `touch ${path}` });
    expect(existsSync(path)).toBe(false);
    expect(world.lastRequest()).toContain("NOT ALLOWED");
    const after = world.of("tool.after")[0]!;
    expect(after.outcome).toBe("denied");
    expect(after.execution).toEqual({ status: "skipped", reason: "policy" });
  });

  test("a rewritten input is what runs", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "modify", target: "input", operation: "replace", value: { command: "echo rewritten" } }] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo original" });
    expect(world.lastRequest()).toContain("rewritten");
    expect(world.of("tool.after")[0]!.tool.input).toEqual({ command: "echo rewritten" });
  });

  test("a merged input keeps the rest", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "modify", target: "input", operation: "merge", value: { command: "echo merged" } }] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo original", timeoutSeconds: 30 });
    expect(world.of("tool.after")[0]!.tool.input).toMatchObject({ command: "echo merged", timeoutSeconds: 30 });
  });

  test("a rewritten result is what the model reads", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.after" ? [{ type: "modify", target: "output", operation: "replace", value: [{ id: "r", role: "tool", parts: [{ id: "r#0", ...body("REDACTED") }] }] }] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo SECRET-VALUE" });
    const tool = world.requests.at(-1)!.messages.filter((entry) => entry.role === "tool").map((entry) => text(entry.content)).join("\n");
    expect(tool).toContain("REDACTED");
    expect(tool).not.toContain("SECRET-VALUE");
  });

  test("context from tool hooks reaches the model with the result", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [inject(event, "FROM-BEFORE")] : event.type === "tool.after" ? [inject(event, "FROM-AFTER")] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo hi" });
    const tool = world.requests.at(-1)!.messages.filter((entry) => entry.role === "tool").map((entry) => text(entry.content)).join("\n");
    expect(tool).toContain("FROM-BEFORE");
    expect(tool).toContain("FROM-AFTER");
  });

  test("a replaced input loses the keys it leaves out", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "modify", target: "input", operation: "replace", value: { command: "pwd" } }] : []);
    await world.call(world.sessionKey(), "exec", { command: "pwd", workdir: "/tmp" });
    const tool = world.requests.at(-1)!.messages.filter((entry) => entry.role === "tool").map((entry) => text(entry.content)).join("\n");
    expect(tool).toContain(world.project);
  });

  test("a fail-closed backend that fails at tool.after keeps the result from the model", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.after" ? [{ type: "deny", reason: "not an effect this event has" }] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo SECRET-VALUE" });
    const tool = world.requests.at(-1)!.messages.filter((entry) => entry.role === "tool").map((entry) => text(entry.content)).join("\n");
    expect(tool).not.toContain("SECRET-VALUE");
  });

  test("a call that fails is reported as failed", async () => {
    clear();
    await world.call(world.sessionKey(), "read", { path: "does-not-exist" });
    const after = world.of("tool.after")[0]!;
    expect(after.outcome).toBe("error");
    expect(after.error.message).toContain("does-not-exist");
  });

  test("a call to an unknown tool is reported as not having run", async () => {
    clear();
    await world.call(world.sessionKey(), "nope", {});
    const after = world.of("tool.after")[0]!;
    expect(after.outcome).toBe("error");
    expect(after.execution).toMatchObject({ status: "skipped", reason: "other" });
  });

  test("a refused turn reaches no model", async () => {
    clear();
    world.policy = (event) => (event.type === "turn.start" ? [{ type: "deny", reason: "NOT THIS PROMPT" }] : []);
    const { reply } = await world.say(world.sessionKey(), "forbidden words");
    expect(world.requests).toHaveLength(0);
    expect(reply).toContain("NOT THIS PROMPT");
    expect(world.of("turn.end")[0]!.outcome).toBe("failed");
    expect(world.of("turn.end")[0]!.error.class).toBe("Denied");
  });

  test("context from turn.start and session.start reaches the model", async () => {
    clear();
    world.policy = (event) => (event.type === "session.start" ? [inject(event, "SESSION-CONTEXT")] : event.type === "turn.start" ? [inject(event, "TURN-CONTEXT")] : []);
    const key = world.sessionKey();
    await world.say(key, "hello");
    expect(world.lastRequest()).toContain("SESSION-CONTEXT");
    expect(world.lastRequest()).toContain("TURN-CONTEXT");
  });

  test("a backend can ask for another pass, up to the limit", async () => {
    clear();
    world.policy = (event) => (event.type === "turn.finish.before" && event.continuationCount === 0 ? [{ type: "flow", operation: "continue", instruction: "CHECK AGAIN" }] : []);
    await world.say(world.sessionKey(), "hello");
    expect(world.requests).toHaveLength(2);
    expect(world.lastRequest()).toContain("CHECK AGAIN");
    expect(world.of("turn.start")).toHaveLength(1);
    expect(world.of("turn.end")).toHaveLength(1);
    expect(world.of("turn.end")[0]!.continuationCount).toBe(1);
  });

  test("after a tool, only stop is offered: OpenClaw makes no further pass", async () => {
    clear();
    await world.call(world.sessionKey(), "exec", { command: "echo hi" });
    const finish = world.of("turn.finish.before")[0]!;
    expect(world.offered.get(finish.id)!.flow.operations).toEqual(["stop"]);
  });

  test("a backend that keeps asking stops at the limit", async () => {
    clear();
    world.policy = (event) => (event.type === "turn.finish.before" && event.continuationCount < 3 ? [{ type: "flow", operation: "continue", instruction: "AGAIN" }] : []);
    await world.say(world.sessionKey(), "hello");
    expect(world.requests.length).toBeLessThanOrEqual(4);
    expect(world.of("turn.end")).toHaveLength(1);
  });

  test("flow stop ends the turn over another backend's asking", async () => {
    clear();
    world.policy = (event) => (event.type === "turn.finish.before" ? [{ type: "flow", operation: "stop", reason: "ENOUGH" }] : []);
    await world.say(world.sessionKey(), "hello");
    expect(world.requests).toHaveLength(1);
    expect(world.of("turn.end")[0]!.outcome).toBe("completed");
  });

  test("ask: a person's approval lets the call run", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "ask" }] : []);
    await world.withOperator("allow-once", async (lines) => {
      await world.call(world.sessionKey(), "exec", { command: "echo approved" });
      expect(lines.some((line) => line.approval?.title?.includes("exec"))).toBe(true);
    });
    expect(world.lastRequest()).toContain("approved");
    expect(world.of("tool.permission.request")).toHaveLength(1);
    await world.until(() => world.of("tool.permission.resolved").length === 1, "resolution");
    expect(world.of("tool.permission.resolved")[0]).toMatchObject({ decision: "allow", decidedBy: "user" });
    expect(world.of("user.attention")[0]!.attention.kind).toBe("permission");
    expect(world.of("tool.after")[0]!.outcome).toBe("ok");
  });

  test("ask: a person's refusal stops the call", async () => {
    clear();
    const path = join(world.dir, "refused");
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "ask" }] : []);
    await world.withOperator("deny", () => world.call(world.sessionKey(), "exec", { command: `touch ${path}` }));
    expect(existsSync(path)).toBe(false);
    await world.until(() => world.of("tool.permission.resolved").length === 1, "resolution");
    expect(world.of("tool.permission.resolved")[0]).toMatchObject({ decision: "deny", decidedBy: "user" });
    expect(world.of("tool.after")[0]!.outcome).toBe("denied");
  });

  test("ask: with no approval surface the call does not run", async () => {
    clear();
    const path = join(world.dir, "unrouted");
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "ask" }] : []);
    await world.call(world.sessionKey(), "exec", { command: `touch ${path}` });
    expect(existsSync(path)).toBe(false);
    expect(world.lastRequest()).toContain("no approval route");
    expect(world.of("tool.after")[0]!.outcome).toBe("denied");
  });

  test("ask: another backend can answer before a person is asked", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "ask" }] : event.type === "tool.permission.request" ? [{ type: "allow" }] : []);
    await world.call(world.sessionKey(), "exec", { command: "echo answered" });
    expect(world.lastRequest()).toContain("answered");
    expect(world.of("tool.permission.resolved")[0]).toMatchObject({ decision: "allow", decidedBy: "hook" });
    expect(world.of("user.attention")).toHaveLength(0);
  });

  test("ask: a rewritten input is what a person approves and what runs", async () => {
    clear();
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "ask" }, { type: "modify", target: "input", operation: "replace", value: { command: "echo safe" } }] : []);
    await world.withOperator("allow-once", () => world.call(world.sessionKey(), "exec", { command: "echo unsafe" }));
    expect(world.lastRequest()).toContain("safe");
    expect(world.of("tool.after")[0]!.tool.input).toEqual({ command: "echo safe" });
  });

  test("a subagent is reported under its root session", async () => {
    clear();
    const key = world.sessionKey();
    await world.call(key, "sessions_spawn", { task: "child work please", label: "kid" });
    await world.until(() => world.of("turn.start").some((event) => event.session.agent), "the subagent's turn");
    await world.settled();
    const child = world.of("turn.start").find((event) => event.session.agent)!;
    const parent = world.of("turn.start").find((event) => !event.session.agent)!;
    expect(child.session.id).toBe(parent.session.id);
    expect(child.session.agent).toMatchObject({ type: "kid" });
    expect(child.session.agent.id).toContain(":subagent:");
    const spawn = world.of("tool.before").find((event) => event.tool.name === "sessions_spawn")!;
    expect(child.parentEventId).toBe(spawn.id);
    expect(world.of("session.start")).toHaveLength(1);
    expect(world.of("session.end")).toHaveLength(0);
  });

  test("two spawns never share a parent", async () => {
    clear();
    await world.say(world.sessionKey(), "TWO-SPAWNS");
    await world.until(() => world.of("turn.start").filter((event) => event.session.agent).length === 2, "the subagents' turns");
    await world.settled();
    // Run one at a time, each is its own; run together, neither is claimed.
    const parents = world.of("turn.start").filter((event) => event.session.agent).map((child) => child.parentEventId).filter(Boolean);
    expect(new Set(parents).size).toBe(parents.length);
  });

  test("an MCP tool under a sanitized server name is still described", async () => {
    clear();
    await world.call(world.sessionKey(), "other-docs__lookup", { q: "y" });
    expect(world.of("tool.before")[0]!.tool.mcp).toMatchObject({ server: { id: "Other.Docs" }, toolName: "lookup" });
  });

  test("one session's slow backend does not hold up another's decisions", async () => {
    clear();
    const slowKey = world.sessionKey();
    world.slow = { type: "model.response.after", ms: 8000, session: slowKey };
    try {
      const running = world.say(slowKey, "hello");
      await world.until(() => world.of("model.response.after").length > 0, "the slow delivery");
      const started = Date.now();
      await world.call(world.sessionKey(), "exec", { command: "echo fast" });
      expect(Date.now() - started).toBeLessThan(7000);
      await running;
    } finally {
      world.slow = undefined;
    }
  }, 60000);

  test("a session's settings are reported, by what changed", async () => {
    clear();
    const key = world.sessionKey();
    await world.say(key, "hello");
    await world.rpc("sessions.patch", { key: `agent:main:${key}`, verboseLevel: "on" });
    await world.until(() => world.of("config.change.after").length > 0, "the change");
    expect(world.of("config.change.after")[0]!.change.settings).toEqual(["verboseLevel"]);
  });

  test("an MCP tool is described, without what its server is given", async () => {
    clear();
    await world.call(world.sessionKey(), "my-docs__lookup", { q: "x" });
    const before = world.of("tool.before")[0]!;
    expect(before.path).toBe("mcp");
    expect(before.tool.origin).toBe("mcp");
    expect(before.tool.mcp).toMatchObject({ server: { id: "my-docs" }, toolName: "lookup" });
    expect(JSON.stringify(before)).not.toContain("do-not-leak");
    expect(partsText(world.of("tool.after")[0]!.items)).toContain("doc for x");
  });

  test("a failed model request is reported, and fails the turn", async () => {
    clear();
    await world.say(world.sessionKey(), "MODEL-FAILS");
    await world.until(() => world.of("turn.end").length > 0, "the turn to end");
    expect(world.of("model.error")[0]!.error.message).toContain("400");
    expect(world.of("turn.end")[0]!.outcome).toBe("failed");
    expect(world.of("model.response.after")).toHaveLength(0);
  });

  test("an aborted run is cancelled, not failed", async () => {
    clear();
    const key = world.sessionKey();
    const running = world.call(key, "exec", { command: "sleep 30" });
    await world.until(() => world.of("tool.before").length > 0, "the call");
    await Bun.sleep(500);
    await world.rpc("chat.abort", { sessionKey: `agent:main:${key}` });
    await running;
    await world.until(() => world.of("turn.end").length > 0, "the turn to end");
    expect(world.of("turn.end")[0]!.outcome).toBe("cancelled");
    expect(world.of("tool.after")[0]!.outcome).toBe("cancelled");
  });

  test("a new conversation ends one session and starts another", async () => {
    clear();
    const key = world.sessionKey();
    await world.say(key, "hello");
    await world.say(key, "/new");
    await world.until(() => world.of("session.end").length > 0, "the session to end");
    expect(world.of("session.end")[0]!.reason).toBe("new");
    const order = world.received.map((event) => event.type).filter((type) => type === "session.start" || type === "session.end");
    expect(order).toEqual(["session.start", "session.end", "session.start"]);
    expect(world.of("session.start").length).toBeGreaterThanOrEqual(2);
    expect(world.of("session.start").at(-1)!.trigger).toBe("clear");
    expect(world.of("session.start").at(-1)!.resumedFrom.id).toBeDefined();
  });

  test("a model chosen for a session is reported", async () => {
    clear();
    const key = world.sessionKey();
    await world.say(key, "hello");
    await world.rpc("sessions.patch", { key: `agent:main:${key}`, model: "fake/n" });
    await world.until(() => world.of("model.switch.after").length > 0, "the switch");
    expect(world.of("model.switch.after")[0]).toMatchObject({ previous: { id: "m", provider: "fake" }, current: { id: "n", provider: "fake" } });
    await world.say(key, "again");
    expect(world.requests.at(-1)!.model).toBe("n");
    expect(world.of("model.switch.after")).toHaveLength(1);
  });

  test("a compaction is reported before and after", async () => {
    clear();
    const key = world.sessionKey();
    await world.call(key, "exec", { command: "echo one" });
    await world.call(key, "exec", { command: "echo two" });
    await world.say(key, "hello");
    await world.rpc("sessions.compact", { key: `agent:main:${key}` });
    await world.until(() => world.of("context.compact.after").length > 0, "the compaction");
    const before = world.of("context.compact.before")[0]!;
    expect(before.gaps.map((gap: { path: string }) => gap.path)).toContain("trigger");
    expect(before.tokenCounts?.before ?? 0).toBeGreaterThanOrEqual(0);
    expect(world.of("context.compact.after")[0]!.execution).toEqual({ status: "executed" });
  });

  test("a channel's message is reported, and can be refused", async () => {
    clear();
    const key = `agent:main:${world.sessionKey()}`;
    await world.rpc("chat.send", { sessionKey: key, message: "hello there", idempotencyKey: crypto.randomUUID() });
    await world.until(() => world.of("turn.end").length > 0, "the turn");
    const inbound = world.of("user.message.inbound")[0]!;
    expect(inbound.message.channel).toBe("webchat");
    expect(partsText(inbound.message.messages)).toBe("hello there");
    clear();
    world.policy = (event) => (event.type === "user.message.inbound" ? [{ type: "deny", reason: "NOT THIS MESSAGE" }] : []);
    await world.withOperator("none", async (lines) => {
      await world.rpc("chat.send", { sessionKey: `agent:main:${world.sessionKey()}`, message: "forbidden", idempotencyKey: crypto.randomUUID() });
      await world.until(() => lines.some((line) => line.chat?.state === "final"), "the reply");
      expect(JSON.stringify(lines.filter((line) => line.chat))).toContain("NOT THIS MESSAGE");
    });
    expect(world.requests).toHaveLength(0);
    expect(world.of("turn.start")).toHaveLength(0);
  });

  /** What the recording channel was given, for a reply delivered through it. */
  async function deliver(): Promise<string[]> {
    const before = world.delivered().length;
    await world.cli(["agent", "--session-key", world.sessionKey(), "-m", "hello", "--deliver", "--reply-channel", "recch", "--reply-to", "bob", "--json"]);
    await world.settled();
    return world.delivered().slice(before);
  }

  test("a reply on a channel is reported once", async () => {
    clear();
    expect(await deliver()).toEqual(["final answer"]);
    const [outbound, ...rest] = world.of("user.message.outbound");
    expect(rest).toHaveLength(0);
    expect(outbound!.message.channel).toBe("recch");
    expect(partsText(outbound!.message.messages)).toBe("final answer");
  });

  test("a reply on a channel can be rewritten", async () => {
    clear();
    world.policy = (event) => (event.type === "user.message.outbound" ? [{ type: "modify", target: "content", operation: "replace", value: [{ id: "o", role: "assistant", parts: [{ id: "o#0", ...body("REWRITTEN REPLY") }] }] }] : []);
    expect(await deliver()).toEqual(["REWRITTEN REPLY"]);
    expect(world.of("user.message.outbound")).toHaveLength(1);
  });

  test("a reply on a channel can be cancelled", async () => {
    clear();
    world.policy = (event) => (event.type === "user.message.outbound" ? [{ type: "deny", reason: "NOT THIS REPLY" }] : []);
    expect(await deliver()).toEqual([]);
  });

  test("a webchat reply is reported and stays as it is", async () => {
    clear();
    world.policy = (event) => (event.type === "user.message.outbound" ? [{ type: "deny", reason: "TOO LATE" }] : []);
    await world.withOperator("none", async (lines) => {
      await world.rpc("chat.send", { sessionKey: `agent:main:${world.sessionKey()}`, message: "hello", idempotencyKey: crypto.randomUUID() });
      await world.until(() => lines.some((line) => line.chat?.state === "final"), "the reply");
      await world.settled();
      expect(JSON.stringify(lines.filter((line) => line.chat?.state === "final"))).toContain("final answer");
    });
    expect(world.of("user.message.outbound")[0]!.message.channel).toBe("webchat");
  });

  test("a backend can take longer than OpenClaw's own hook timeouts", async () => {
    clear();
    world.slow = { type: "tool.before", ms: 17000 };
    world.policy = (event) => (event.type === "tool.before" ? [{ type: "deny", reason: "AFTER THINKING" }] : []);
    try {
      await world.call(world.sessionKey(), "exec", { command: "echo hi" });
    } finally {
      world.slow = undefined;
    }
    expect(world.lastRequest()).toContain("AFTER THINKING");
  }, 60000);
});

describe.each(VERSIONS)("OpenClaw $name, set up differently", ({ dir }) => {
  test("with tool search on, a dispatched call is governed and reported as what it was", async () => {
    const world = new World(dir, { toolSearch: true });
    try {
      await world.start();
      const key = world.sessionKey();
      await world.say(key, "hello");
      const names = world.requests[0]!.tools!.map((tool) => tool.function?.name);
      const dispatcher = names.includes("dispatch_action") ? "dispatch_action" : "tool_call";
      world.received.length = 0;
      world.policy = (event) => (event.type === "tool.before" && event.tool.name === "exec" ? [inject(event, "INNER-CONTEXT")] : []);
      await world.call(world.sessionKey(), dispatcher, { id: "exec", args: { command: "echo dispatched" } });
      const inner = world.of("tool.after").find((event) => event.tool.name === "exec")!;
      expect(inner.outcome).toBe("ok");
      expect(inner.execution).toEqual({ status: "executed" });
      expect(partsText(inner.items)).toContain("dispatched");
      expect(world.lastRequest()).toContain("INNER-CONTEXT");
      world.policy = (event) => (event.type === "tool.before" && event.tool.name === "exec" ? [{ type: "deny", reason: "NOT DISPATCHED" }] : []);
      const path = join(world.dir, "dispatched");
      await world.call(world.sessionKey(), dispatcher, { id: "exec", args: { command: `touch ${path}` } });
      expect(existsSync(path)).toBe(false);
      expect(world.lastRequest()).toContain("NOT DISPATCHED");
    } finally {
      await world.stop();
    }
  }, 300000);

  test("a wildcard subscription is delivered and enforced", async () => {
    const path = join(tmpdir(), `ahp-openclaw-wildcard-${crypto.randomUUID()}`);
    const world = new World(dir, {
      backends: (recorder) => [{ ...recorder, subscriptions: [{ mode: "intercept", events: ["tool.*"], timeoutMs: 10000, failurePolicy: "fail-closed", content: { default: "body" } }] }],
    });
    try {
      await world.start();
      world.policy = (event) => (event.type === "tool.before" ? [{ type: "deny", reason: "WILDCARD" }] : []);
      await world.call(world.sessionKey(), "exec", { command: `touch ${path}` });
      expect(existsSync(path)).toBe(false);
      expect(world.lastRequest()).toContain("WILDCARD");
    } finally {
      await world.stop();
    }
  }, 300000);

  test("without conversation access, tool policy still holds and turn events are left out", async () => {
    const world = new World(dir, { grants: { allowConversationAccess: false } });
    try {
      await world.start();
      world.policy = (event) => (event.type === "tool.before" ? [{ type: "deny", reason: "STILL GUARDED" }] : []);
      await world.call(world.sessionKey(), "exec", { command: "echo hi" });
      expect(world.lastRequest()).toContain("STILL GUARDED");
      expect(world.of("turn.start")).toHaveLength(0);
      expect(world.of("tool.after")[0]!.outcome).toBe("denied");
      expect(world.log()).toContain("allowConversationAccess");
    } finally {
      await world.stop();
    }
  }, 300000);

  test("one invalid backend does not take a valid one's policy down", async () => {
    const world = new World(dir, {
      backends: (recorder) => [
        { id: "org.example.broken", transport: { type: "http", url: "http://127.0.0.1:1/ahp" }, subscriptions: [{ mode: "intercept", events: ["model.request.before"], timeoutMs: 1000, failurePolicy: "fail-open", content: { default: "body" } }] },
        recorder,
      ],
    });
    try {
      await world.start();
      world.policy = (event) => (event.type === "tool.before" ? [{ type: "deny", reason: "STILL GUARDED" }] : []);
      await world.call(world.sessionKey(), "exec", { command: "echo hi" });
      expect(world.lastRequest()).toContain("STILL GUARDED");
    } finally {
      await world.stop();
    }
  }, 300000);

  test("a fail-closed backend that is down refuses the call", async () => {
    const path = `/tmp/ahp-openclaw-unreachable-${crypto.randomUUID()}`;
    const world = new World(dir, {
      backends: (recorder) => [{ ...recorder, id: "org.example.down", transport: { type: "http", url: "http://127.0.0.1:9/ahp" }, subscriptions: [{ mode: "intercept", events: ["tool.before"], timeoutMs: 2000, failurePolicy: "fail-closed", content: { default: "body" } }] }],
    });
    try {
      await world.start();
      await world.call(world.sessionKey(), "exec", { command: `touch ${path}` });
      expect(existsSync(path)).toBe(false);
    } finally {
      await world.stop();
    }
  }, 300000);

  test("--local: delivers everything before the process exits, and does not offer ask", async () => {
    const world = new World(dir);
    try {
      await world.install();
      const key = world.sessionKey();
      const { code, stdout, stderr } = await world.cli(["agent", "--local", "--session-key", key, "-m", 'CALL exec {"command":"echo hi"}', "--json"]);
      if (code !== 0) throw new Error(`${stdout}\n${stderr}`);
      const types = world.received.map((event) => event.type);
      for (const type of ["session.start", "turn.start", "tool.before", "tool.after", "turn.end"]) expect(types).toContain(type);
      const start = world.of("session.start")[0]!;
      expect(start.synthesized).toBe(true);
      expect(JSON.stringify(start.manifest.gaps)).toContain("tool.before.ask");
    } finally {
      await world.stop();
    }
  }, 300000);
});
