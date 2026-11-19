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

export function describeStatus(status: Status, withLink: boolean): string {
  switch (status.state) {
    case "authorized": return "authorized";
    case "client-credentials": return "client-credentials";
    case "bearer": return "bearer token";
    case "not-configured": return "no OAuth";
    case "failing": return `failing: ${status.reason}`;
    case "needs-login":
      if (!status.url) return "needs-login";
      return withLink ? `needs-login: ${status.url} (valid until ${new Date(status.expiresAt!).toISOString()})` : "needs-login (run `openclaw ahp login` on the Gateway's host)";
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
      if (verb === "logout" && id) return { text: (await current.logout(id)) ? `${id}: signed out` : `${id}: was not signed in` };
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
    await warnIfStopped(current);
    console.log(await statusLines(current, backends(), true));
  });
  ahp.command("login").argument("[backend]", "a backend id; without one, every backend that needs it")
    .description("Sign in to a backend, in a browser").action(async (id?: string) => {
      const current = logins();
      await warnIfStopped(current);
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
        if (!(await waitForLogin(current, target.id, result.expiresAt))) {
          failed = true;
          console.log(`${target.id}: the link expired before sign-in finished`);
        } else console.log(`${target.id}: signed in`);
      }
      if (failed) process.exitCode = 1;
    });
  ahp.command("complete").argument("<url>", "the address the browser ended on")
    .description("Finish a sign-in when the browser could not reach the Gateway").action(async (url: string) => {
      console.log(`${await logins().complete(url)}: signed in`);
    });
  ahp.command("logout").argument("<backend>").description("Cancel a backend's sign-in and delete its tokens").action(async (id: string) => {
    console.log((await logins().logout(id)) ? `${id}: signed out` : `${id}: was not signed in`);
  });
}

/** Whether something answers at the redirect: the Gateway, if it is running. */
export async function gatewayRunning(redirectUri: string, timeoutMs = 2000): Promise<boolean> {
  try {
    await fetch(redirectUri, { signal: AbortSignal.timeout(timeoutMs), redirect: "manual" });
    return true;
  } catch {
    return false;
  }
}

/** For `openclaw ahp`: a link returns to the Gateway, at the port config names. */
async function warnIfStopped(logins: Logins): Promise<void> {
  if (!(await gatewayRunning(logins.redirectUri))) {
    console.log(`The Gateway is not running at ${new URL(logins.redirectUri).origin}: a sign-in link returns there, so start the Gateway (or finish with \`openclaw ahp complete <url>\`).`);
  }
}

/** Until the Gateway (or a pasted address, on a terminal) completes the login. */
async function waitForLogin(logins: Logins, id: string, expiresAt: number): Promise<boolean> {
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
    while (Date.now() < expiresAt) {
      await pasted;
      if ((await logins.status(backend)).state === "authorized") return true;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return false;
  } finally {
    lines?.close();
  }
}
