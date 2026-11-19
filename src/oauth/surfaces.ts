// Where a person meets sign-in: the Gateway's callback route, `/ahp` in chat and
// `openclaw ahp` on the Gateway's host.
import type { IncomingMessage, ServerResponse } from "node:http";
import { createInterface } from "node:readline";
import { AuthError } from "agenthooksprotocol/client";
import { CALLBACK_PATH, type Logins, type Status } from "./logins.js";

const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(response: ServerResponse, status: number, title: string, text: string): void {
  response.statusCode = status;
  response.setHeader("content-type", "text/html; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("content-security-policy", "default-src 'none'");
  response.end(`<!doctype html><meta charset="utf-8"><title>${escape(title)}</title><h1>${escape(title)}</h1><p>${escape(text)}</p>`);
}

/** The redirect target. Reachable without Gateway auth: the OAuth state is what
 * authenticates a callback, and the SDK checks it before it uses anything. */
export function callbackRoute(logins: () => Logins) {
  return async (request: IncomingMessage, response: ServerResponse): Promise<boolean> => {
    if (request.method !== "GET") {
      response.statusCode = 405;
      response.end();
      return true;
    }
    const current = logins();
    const url = new URL(request.url ?? CALLBACK_PATH, current.redirectUri);
    try {
      const backend = await current.complete(url.href);
      page(response, 200, "Signed in", `OpenClaw can now deliver to ${backend}. You can close this tab.`);
    } catch (error) {
      const code = error instanceof AuthError ? error.code : "provider_failed";
      const reason = code === "interaction_required" ? "This sign-in link has expired or was already used." : code === "access_denied" ? "Sign-in was refused." : `Sign-in did not complete (${code}).`;
      page(response, 400, "Not signed in", `${reason} Run \`openclaw ahp login\` for a new link.`);
    }
    return true;
  };
}

function logoutText(result: { signedOut: boolean; forgotScopes: boolean }): string {
  if (result.signedOut) return result.forgotScopes ? "signed out, and forgot the scopes it asked for" : "signed out";
  return result.forgotScopes ? "was not signed in; forgot the scopes it asked for" : "was not signed in";
}

export function describeStatus(status: Status, withLink: boolean): string {
  switch (status.state) {
    case "authorized": return "authorized";
    case "client-credentials": return "client-credentials";
    case "bearer": return "bearer token";
    case "not-configured": return "no OAuth";
    case "failing": return `failing: ${status.reason}`;
    case "needs-login": {
      const label = status.scopes?.length ? `needs-login for ${status.scopes.join(" ")}` : "needs-login";
      if (!status.url) return label;
      return withLink ? `${label}: ${status.url} (valid until ${new Date(status.expiresAt!).toISOString()})` : `${label} (run \`openclaw ahp login\` on the Gateway's host)`;
    }
  }
}

async function statusLines(logins: Logins, backends: { id: string }[], withLink: boolean): Promise<string> {
  if (!backends.length) return "No backends in hooks.json.";
  const lines = await Promise.all(backends.map(async (backend) => `${backend.id}: ${describeStatus(await logins.status(backend as never), withLink)}`));
  return lines.join("\n");
}

type CommandContext = { args?: string; senderIsOwner?: boolean; gatewayClientScopes?: string[] };

/** `/ahp status|login [backend]|logout <backend>`, for the owner. Its reply lands in
 * the transcript, so it never carries a link: links go to the Gateway log. */
export function chatCommand(logins: () => Logins, backends: () => { id: string }[]) {
  return async (ctx: CommandContext): Promise<{ text: string }> => {
    const owner = ctx.senderIsOwner === true || (ctx.gatewayClientScopes ?? []).some((scope) => scope === "operator.admin" || scope === "operator.write");
    if (!owner) return { text: "Only the Gateway's owner can manage Agent Hooks Protocol sign-in." };
    const [verb = "status", id] = (ctx.args ?? "").trim().split(/\s+/).filter(Boolean);
    const current = logins();
    try {
      if (verb === "status") return { text: await statusLines(current, backends(), false) };
      if (verb === "login") {
        const targets = id ? [{ id }] : await current.waiting();
        if (!targets.length) return { text: "No backend needs a sign-in." };
        const lines = await Promise.all(targets.map(async (target) => {
          const backend = current.backend(target.id);
          if (!backend) return `${target.id}: not a backend in hooks.json`;
          const status = await current.status(backend);
          return status.state === "needs-login" ? `${target.id}: run \`openclaw ahp login ${target.id}\` on the Gateway's host for the sign-in link` : `${target.id}: ${describeStatus(status, false)}`;
        }));
        return { text: lines.join("\n") };
      }
      if (verb === "logout" && id) return { text: `${id}: ${logoutText(await current.logout(id))}` };
    } catch (error) {
      return { text: `Agent Hooks Protocol: ${error instanceof AuthError ? error.code : error instanceof Error ? error.message : String(error)}` };
    }
    return { text: "Usage: /ahp status | /ahp login [backend] | /ahp logout <backend>" };
  };
}

interface Command {
  command(name: string): Command;
  description(text: string): Command;
  argument(name: string, description?: string): Command;
  action(handler: (...args: any[]) => unknown): Command;
}

/** `openclaw ahp`: a terminal on the Gateway's host is the operator's own, so links show. */
export function cliCommands(program: Command, logins: () => Logins, backends: () => { id: string }[]): void {
  const ahp = program.command("ahp").description("Agent Hooks Protocol: backend sign-in");
  ahp.command("status").description("How each backend in hooks.json authenticates").action(async () => {
    const current = logins();
    const stopped = await gatewayStopped(current);
    if (stopped) console.log(stopped);
    console.log(await statusLines(current, backends(), true));
  });
  ahp.command("login").argument("[backend]", "a backend id; without one, every backend that needs it")
    .description("Sign in to a backend, in a browser").action(async (id?: string) => {
      const current = logins();
      // A link would return to nothing: no client is registered and none is printed.
      const stopped = await gatewayStopped(current);
      if (stopped) {
        console.log(stopped);
        process.exitCode = 1;
        return;
      }
      const targets = id ? [{ id }] : await current.waiting();
      if (!targets.length) return console.log("No backend needs a sign-in.");
      let failed = false;
      for (const target of targets) {
        const result = await current.login(target.id);
        if (result.type === "ready") {
          console.log(`${target.id}: already signed in`);
          continue;
        }
        console.log(`Sign in to ${target.id}: ${result.url}`);
        if (!(await waitForLogin(current, target.id, result))) {
          failed = true;
          console.log(`${target.id}: the link expired before sign-in finished`);
          continue;
        }
        console.log(`${target.id}: signed in`);
        // A delivery asked for more while this sign-in was open.
        const status = await current.status(current.backend(target.id)!);
        if (status.state === "needs-login" && status.scopes?.length) console.log(`${target.id}: it has since asked for ${status.scopes.join(" ")} too: run \`openclaw ahp login ${target.id}\` again`);
      }
      if (failed) process.exitCode = 1;
    });
  ahp.command("complete").argument("<url>", "the address the browser ended on")
    .description("Finish a sign-in when the browser could not reach the Gateway").action(async (url: string) => {
      console.log(`${await logins().complete(url)}: signed in`);
    });
  ahp.command("logout").argument("<backend>").description("Cancel a backend's sign-in and delete its tokens").action(async (id: string) => {
    console.log(`${id}: ${logoutText(await logins().logout(id))}`);
  });
}

/** Whether something answers at an address: the Gateway, if it is running. */
export async function gatewayRunning(uri: string, timeoutMs = 2000): Promise<boolean> {
  try {
    await fetch(uri, { signal: AbortSignal.timeout(timeoutMs), redirect: "manual" });
    return true;
  } catch {
    return false;
  }
}

/** For `openclaw ahp`: a link returns to the Gateway, where config says it is. Why
 * not, when nothing answers there. Asked on the loopback port, which this host
 * reaches even where it cannot reach its own `publicUrl`; at `publicUrl` only if
 * nothing answers on loopback (a Gateway bound to another interface). */
export async function gatewayStopped(logins: Pick<Logins, "redirectUri" | "loopbackUri">, timeoutMs?: number): Promise<string | undefined> {
  if (await gatewayRunning(logins.loopbackUri, timeoutMs)) return undefined;
  const loopback = new URL(logins.loopbackUri).origin;
  if (logins.redirectUri === logins.loopbackUri) {
    return `No Gateway answers at ${loopback}, where a sign-in returns. Start the Gateway, or if it runs elsewhere, set OPENCLAW_GATEWAY_PORT or gateway.port to its port (or publicUrl to the address a browser reaches it at), then run this again.`;
  }
  if (await gatewayRunning(logins.redirectUri, timeoutMs)) return undefined;
  return `No Gateway answers at ${loopback} or at ${new URL(logins.redirectUri).origin} (publicUrl), where a sign-in returns. Start the Gateway, or set OPENCLAW_GATEWAY_PORT or gateway.port to the port it listens on, then run this again.`;
}

/** Until the Gateway (or a pasted address, on a terminal) completes the login. */
async function waitForLogin(logins: Logins, id: string, login: { expiresAt: number; state: string; requiredScopes: readonly string[] }): Promise<boolean> {
  const backend = logins.backend(id)!;
  let pasted: Promise<void> | undefined;
  const lines = process.stdin.isTTY ? createInterface({ input: process.stdin, output: process.stdout }) : undefined;
  lines?.setPrompt("Or paste the address your browser ended on: ");
  lines?.prompt();
  lines?.on("line", (line) => {
    if (!line.trim()) return;
    pasted = logins.complete(line.trim()).then(() => {}, (error) => {
      console.log(`Not signed in: ${error instanceof AuthError ? error.code : String(error)}`);
      lines.prompt();
    });
  });
  try {
    while (Date.now() < login.expiresAt) {
      await pasted;
      if (await logins.finished(backend, login)) return true;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return false;
  } finally {
    lines?.close();
  }
}
