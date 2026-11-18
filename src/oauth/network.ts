// OAuth's own network access: discovery, registration and token requests. HTTPS
// only, no redirects followed, a bounded body, and no private or loopback address
// unless the backend's `oauth.allowPrivateNetwork` permits it. The check runs on the address the
// connection uses, so a name that resolves elsewhere later is checked again.
import { lookup as resolve, type LookupAddress } from "node:dns";
import { isIP } from "node:net";
import { request } from "node:https";
import { AuthError } from "agenthooksprotocol/client";
import type { NetworkPurpose, Operation, PolicyFetch } from "agenthooksprotocol/oauth";

const MAX_BODY = 1024 * 1024;

/** Addresses OAuth metadata must not steer this process to by default. */
export function privateAddress(address: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return privateAddress(mapped);
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168);
  }
  const lower = address.toLowerCase();
  return lower === "::" || lower === "::1" || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower) || /^ff/.test(lower);
}

/** Names that mean this machine or its local network, whatever they resolve to. */
function localName(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, "");
  return name === "localhost" || name.endsWith(".localhost") || name.endsWith(".local") || name.endsWith(".internal");
}

/** Whether a URL's host is refused before anything resolves it. */
function refusedHost(url: URL, allowPrivateNetwork: boolean): boolean {
  if (allowPrivateNetwork) return false;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return isIP(host) ? privateAddress(host) : localName(host);
}

function refuse(): never {
  throw new AuthError("untrusted_destination");
}

/** For each endpoint the SDK is about to use, and the authorization URL before a person opens it. */
export function checkDestination(allowPrivateNetwork: boolean) {
  return (url: URL, _purpose: NetworkPurpose, _operation: Operation): void => {
    if (url.protocol !== "https:" || url.username || url.password || refusedHost(url, allowPrivateNetwork)) refuse();
  };
}

export function policyFetch(allowPrivateNetwork: boolean): PolicyFetch {
  return async (url, init, { operation }) => {
    const target = new URL(url);
    if (target.protocol !== "https:" || target.username || target.password || refusedHost(target, allowPrivateNetwork)) refuse();
    const exempt = allowPrivateNetwork;
    const signal = init.signal ? AbortSignal.any([init.signal, operation.signal]) : operation.signal;
    // Request normalizes the body and its content type.
    const prepared = new Request(url, { method: init.method ?? "GET", headers: init.headers, body: init.body ?? null });
    const body = prepared.body ? Buffer.from(await prepared.arrayBuffer()) : undefined;
    const headers: Record<string, string> = {};
    prepared.headers.forEach((value, key) => { headers[key] = value; });
    return new Promise<Response>((done, fail) => {
      const outgoing = request(target, {
        method: prepared.method,
        headers,
        signal,
        lookup: (hostname, options, callback) => {
          resolve(hostname, { ...options, all: true }, (error, addresses: LookupAddress[]) => {
            if (error) return (callback as (error: Error) => void)(error);
            if (!exempt && addresses.some(({ address }) => privateAddress(address))) {
              return (callback as (error: Error) => void)(Object.assign(new Error("address not permitted"), { code: "EADDRNOTAVAIL" }));
            }
            if ((options as { all?: boolean }).all) return (callback as (error: null, addresses: LookupAddress[]) => void)(null, addresses);
            const [first] = addresses;
            (callback as (error: null, address: string, family: number) => void)(null, first!.address, first!.family);
          });
        },
      }, (incoming) => {
        const status = incoming.statusCode ?? 0;
        if (status >= 300 && status < 400 && init.redirect === "error") {
          incoming.destroy();
          return fail(new TypeError("redirect refused"));
        }
        const chunks: Buffer[] = [];
        let size = 0;
        incoming.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BODY) incoming.destroy(new Error("response too large"));
          else chunks.push(chunk);
        });
        incoming.on("error", fail);
        incoming.on("end", () => {
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(incoming.headers)) {
            for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) responseHeaders.append(key, item);
          }
          const empty = status === 204 || status === 304 || prepared.method === "HEAD";
          done(new Response(empty ? null : Buffer.concat(chunks), { status, headers: responseHeaders }));
        });
      });
      outgoing.on("error", fail);
      outgoing.end(body);
    });
  };
}
