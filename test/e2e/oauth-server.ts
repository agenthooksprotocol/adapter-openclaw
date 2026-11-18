// A real, small OAuth world on one HTTPS origin: an AHP backend that wants a bearer
// token (RFC 9728 metadata and a 401 challenge), and the authorization server that
// issues it (RFC 8414 metadata, RFC 7591 registration, authorization code with
// PKCE S256, refresh). The certificate comes from a throwaway CA that the processes
// under test trust through NODE_EXTRA_CA_CERTS.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

export interface Tls { ca: string; cert: string; key: string }

/** A CA and a certificate for 127.0.0.1, under `dir`. */
export function makeTls(dir: string): Tls {
  const run = (args: string[]) => {
    const result = Bun.spawnSync(["openssl", ...args], { cwd: dir, stdout: "ignore", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(`openssl ${args[0]}: ${result.stderr.toString()}`);
  };
  writeFileSync(join(dir, "ext"), "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n");
  run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=ahp-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"]);
  run(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "req.csr", "-subj", "/CN=127.0.0.1"]);
  run(["x509", "-req", "-in", "req.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "cert.pem", "-days", "1", "-extfile", "ext"]);
  return { ca: join(dir, "ca.pem"), cert: join(dir, "cert.pem"), key: join(dir, "key.pem") };
}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export class AuthServer {
  readonly server: ReturnType<typeof Bun.serve>;
  readonly origin: string;
  /** What the backend received, and the Authorization header it came with. */
  readonly deliveries: { type: string; authorization?: string }[] = [];
  /** Requests refused for want of a valid token. */
  unauthorized = 0;
  readonly clients = new Map<string, { redirectUris: string[] }>();
  readonly #codes = new Map<string, { clientId: string; redirectUri: string; challenge: string; resource: string; scope: string }>();
  readonly tokens = new Set<string>();
  readonly #refresh = new Map<string, string>();

  constructor(tls: Tls) {
    this.server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      tls: { cert: Bun.file(tls.cert), key: Bun.file(tls.key) },
      fetch: (request) => this.#handle(request),
    });
    this.origin = `https://127.0.0.1:${this.server.port}`;
  }

  get resource(): string {
    return `${this.origin}/ahp`;
  }

  async #handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const origin = this.origin;
    switch (url.pathname) {
      case "/.well-known/oauth-protected-resource/ahp":
      case "/.well-known/oauth-protected-resource":
        return Response.json({ resource: this.resource, authorization_servers: [origin], bearer_methods_supported: ["header"] });
      case "/.well-known/oauth-authorization-server":
        return Response.json({
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          registration_endpoint: `${origin}/register`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      case "/register": {
        const body = (await request.json()) as { redirect_uris?: string[]; client_name?: string };
        if (!body.redirect_uris?.length) return Response.json({ error: "invalid_redirect_uri" }, { status: 400 });
        const clientId = `client-${crypto.randomUUID()}`;
        this.clients.set(clientId, { redirectUris: body.redirect_uris });
        return Response.json({ ...body, client_id: clientId, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }, { status: 201 });
      }
      case "/authorize": {
        const q = url.searchParams;
        const client = this.clients.get(q.get("client_id") ?? "");
        const redirectUri = q.get("redirect_uri") ?? "";
        if (!client || !client.redirectUris.includes(redirectUri)) return new Response("unknown client or redirect", { status: 400 });
        if (q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") || q.get("resource") !== this.resource) {
          return new Response("bad authorization request", { status: 400 });
        }
        // Consent is automatic: the person under test always agrees.
        const code = crypto.randomUUID();
        this.#codes.set(code, { clientId: q.get("client_id")!, redirectUri, challenge: q.get("code_challenge")!, resource: q.get("resource")!, scope: q.get("scope") ?? "" });
        const back = new URL(redirectUri);
        back.searchParams.set("code", code);
        back.searchParams.set("state", q.get("state") ?? "");
        back.searchParams.set("iss", origin);
        return new Response(null, { status: 302, headers: { location: back.href } });
      }
      case "/token": {
        const form = new URLSearchParams(await request.text());
        const issue = (scope: string) => {
          const token = `tok-${crypto.randomUUID()}`;
          const refresh = `ref-${crypto.randomUUID()}`;
          this.tokens.add(token);
          this.#refresh.set(refresh, scope);
          return Response.json({ access_token: token, token_type: "Bearer", expires_in: 3600, refresh_token: refresh, ...(scope ? { scope } : {}) }, { headers: { "cache-control": "no-store" } });
        };
        if (form.get("grant_type") === "authorization_code") {
          const grant = this.#codes.get(form.get("code") ?? "");
          this.#codes.delete(form.get("code") ?? "");
          const verifier = form.get("code_verifier") ?? "";
          const challenge = b64url(createHash("sha256").update(verifier).digest());
          if (!grant || grant.clientId !== form.get("client_id") || grant.redirectUri !== form.get("redirect_uri") || grant.challenge !== challenge) {
            return Response.json({ error: "invalid_grant" }, { status: 400 });
          }
          return issue(grant.scope);
        }
        if (form.get("grant_type") === "refresh_token") {
          const scope = this.#refresh.get(form.get("refresh_token") ?? "");
          if (scope === undefined) return Response.json({ error: "invalid_grant" }, { status: 400 });
          this.#refresh.delete(form.get("refresh_token")!);
          return issue(scope);
        }
        return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
      }
      case "/ahp": {
        const authorization = request.headers.get("authorization") ?? undefined;
        if (!authorization || !this.tokens.has(authorization.replace(/^Bearer /, ""))) {
          this.unauthorized += 1;
          return new Response(null, { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/ahp"` } });
        }
        const wire = (await request.json()) as { id?: string; method: string; params: { event: { type: string } } };
        this.deliveries.push({ type: wire.params.event.type, authorization });
        if (wire.method === "hooks/observe") return new Response(null, { status: 202 });
        return Response.json({ jsonrpc: "2.0", id: wire.id, result: { protocolVersion: "draft", effects: [] } });
      }
    }
    return new Response("not found", { status: 404 });
  }

  stop(): void {
    this.server.stop(true);
  }
}
