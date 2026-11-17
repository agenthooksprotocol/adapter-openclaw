// Where managed OAuth keeps its records: OpenClaw's plugin state, which the Gateway
// and the `openclaw ahp` CLI (a separate, short-lived process) share. Tokens and
// pending logins live in a retained namespace. Client secrets do not: see secrets.ts.
import { createHash } from "node:crypto";
import type { StoredRecord, TokenStore } from "agenthooksprotocol/oauth";

/** What this needs of OpenClaw's `PluginStateKeyedStore`. */
export interface KeyedStore<T> {
  lookup(key: string): Promise<T | undefined>;
  register(key: string, value: T, opts?: { ttlMs?: number }): Promise<void>;
  registerIfAbsent(key: string, value: T, opts?: { ttlMs?: number }): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  deleteIfEqual?: (key: string, expected: string | number | boolean | null) => Promise<boolean>;
  observe?: (key: string) => Promise<{ value: T | undefined; comparison: string }>;
  compareAndApply?: (key: string, comparison: string, intent:
    | { operation: "update"; action: "set"; value: T }
    | { operation: "update" | "delete"; action: "keep" }
    | { operation: "delete"; action: "delete" }) => Promise<{ status: "applied" | "unchanged" } | { status: "conflict"; current: { value: T | undefined; comparison: string } }>;
}

/** A lease outlives a crashed holder by at most this long. */
export const LEASE_MS = 60_000;
const CONFLICT_RETRIES = 5;

/** SDK keys are long framed strings: the stored key is their digest, and never logged. */
const digest = (key: string) => createHash("sha256").update(key).digest("hex");

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, ms);
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    signal.addEventListener("abort", abort, { once: true });
  });
}

/** Wait for an earlier holder, or give up on abort: a cancelled waiter never runs. */
function waitFor(previous: Promise<unknown>, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void previous.catch(() => {}).then(() => { signal.removeEventListener("abort", abort); resolve(); });
  });
}

/**
 * A `TokenStore` over two plugin-state namespaces: `records` (retained) and `leases`
 * (bounded, with expiry). compareAndSet is OpenClaw's observe + compareAndApply on
 * the record's generation. coordinate serializes a key in this process with a
 * promise chain, and across processes with a lease row taken by registerIfAbsent,
 * renewed while the work runs and released when it settles.
 */
export function keyedTokenStore(records: KeyedStore<StoredRecord>, leases: KeyedStore<string>, options: { leaseMs?: number } = {}): TokenStore {
  const leaseMs = options.leaseMs ?? LEASE_MS;
  const chains = new Map<string, Promise<unknown>>();
  if (!records.observe || !records.compareAndApply) throw new Error("this OpenClaw has no compare-and-apply plugin state");
  const observe = records.observe.bind(records), apply = records.compareAndApply.bind(records);

  async function acquire(key: string, token: string, signal: AbortSignal): Promise<void> {
    for (let wait = 20; ; wait = Math.min(wait * 2, 250)) {
      signal.throwIfAborted();
      if (await leases.registerIfAbsent(key, token, { ttlMs: leaseMs })) return;
      await sleep(wait, signal);
    }
  }

  async function release(key: string, token: string): Promise<void> {
    if (leases.deleteIfEqual) await leases.deleteIfEqual(key, token);
    else if ((await leases.lookup(key)) === token) await leases.delete(key);
  }

  return {
    async load(key, signal) {
      signal.throwIfAborted();
      return records.lookup(digest(key));
    },

    async compareAndSet(key, expected, value, signal) {
      const stored = digest(key);
      for (let attempt = 0; attempt < CONFLICT_RETRIES; attempt += 1) {
        signal.throwIfAborted();
        const seen = await observe(stored);
        if (seen.value?.generation !== expected) return false;
        signal.throwIfAborted();
        const result = await apply(stored, seen.comparison, value !== undefined
          ? { operation: "update", action: "set", value }
          : seen.value === undefined ? { operation: "delete", action: "keep" } : { operation: "delete", action: "delete" });
        // A conflict may be storage metadata only: look again at the generation.
        if (result.status !== "conflict") return true;
      }
      return false;
    },

    coordinate(key, signal, work) {
      const stored = digest(key);
      const previous = chains.get(stored) ?? Promise.resolve();
      const run = (async () => {
        await waitFor(previous, signal);
        signal.throwIfAborted();
        const token = crypto.randomUUID();
        await acquire(stored, token, signal);
        const renew = setInterval(() => {
          void leases.lookup(stored).then((holder) => holder === token ? leases.register(stored, token, { ttlMs: leaseMs }) : undefined).catch(() => {});
        }, Math.max(1, Math.floor(leaseMs / 3)));
        try {
          signal.throwIfAborted();
          return await work();
        } finally {
          clearInterval(renew);
          await release(stored, token).catch(() => {});
        }
      })();
      const settled = run.catch(() => {});
      chains.set(stored, settled);
      void settled.then(() => { if (chains.get(stored) === settled) chains.delete(stored); });
      return run;
    },
  };
}
