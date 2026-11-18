// OAuth's own network access: discovery, registration and token requests. HTTPS
// only, no redirects followed, a bounded body, and no private or loopback address
// unless the backend's `oauth.allowPrivateNetwork` permits it. The check runs on the address the
// connection uses, so a name that resolves elsewhere later is checked again.
import { lookup as resolve, type LookupAddress } from "node:dns";
import { BlockList, isIP } from "node:net";
import { request } from "node:https";
import { AuthError } from "agenthooksprotocol/client";
import type { NetworkPurpose, Operation, PolicyFetch } from "agenthooksprotocol/oauth";

const MAX_BODY = 1024 * 1024;

/** IPv4 ranges that are not global unicast (RFC 6890 and its successors). */
const PRIVATE_V4 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) PRIVATE_V4.addSubnet(network, prefix, "ipv4");

/** IPv6 global unicast is 2000::/3, less these. Everything outside it is not global. */
const GLOBAL_V6 = new BlockList();
GLOBAL_V6.addSubnet("2000::", 3, "ipv6");
const SPECIAL_V6 = new BlockList();
// IETF protocol assignments (Teredo among them), documentation, 6to4, and documentation again.
for (const [network, prefix] of [["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20]] as const) SPECIAL_V6.addSubnet(network, prefix, "ipv6");

/** An IPv6 literal's 16 bytes, accepting `::` and a trailing dotted quad. */
function ipv6Bytes(address: string): number[] | undefined {
  let text = address.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0]!;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) text = `${text.slice(0, dotted.index)}0:0`;
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : [];
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail] : head;
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return undefined;
  const bytes = groups.flatMap((group) => { const value = parseInt(group, 16); return [value >> 8, value & 255]; });
  if (dotted) bytes.splice(12, 4, ...dotted.slice(1, 5).map(Number));
  return bytes;
}

/** The IPv4 address an IPv6 one stands for: mapped (::ffff:0:0/96), compatible
 * (::/96) or NAT64 (64:ff9b::/96). */
function embeddedV4(bytes: number[]): string | undefined {
  const zero = (from: number, to: number) => bytes.slice(from, to).every((byte) => byte === 0);
  const v4 = bytes.slice(12).join(".");
  if (zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) return v4;
  if (zero(0, 12)) return v4;
  if (bytes[0] === 0 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12)) return v4;
  return undefined;
}

/** Whether an address is anything but global unicast: OAuth metadata must not
 * steer this process there by default. */
export function privateAddress(address: string): boolean {
  const literal = address.replace(/^\[|\]$/g, "");
  if (isIP(literal) === 4) return PRIVATE_V4.check(literal, "ipv4");
  if (isIP(literal) !== 6) return true;
  const bytes = ipv6Bytes(literal);
  if (!bytes) return true;
  const v4 = embeddedV4(bytes);
  if (v4 !== undefined) return PRIVATE_V4.check(v4, "ipv4");
  return !GLOBAL_V6.check(literal, "ipv6") || SPECIAL_V6.check(literal, "ipv6");
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
