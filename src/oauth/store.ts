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
    | { operation: "update"; action: "set"; value: T; ttlMs?: number }
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
export function keyedTokenStore(records: KeyedStore<StoredRecord>, leases: KeyedStore<string>, options: { leaseMs?: number; warn?: (text: string) => void } = {}): TokenStore {
  const leaseMs = options.leaseMs ?? LEASE_MS;
  const chains = new Map<string, Promise<unknown>>();
  if (!records.observe || !records.compareAndApply || !leases.observe || !leases.compareAndApply) throw new Error("this OpenClaw has no compare-and-apply plugin state");
  const observe = records.observe.bind(records), apply = records.compareAndApply.bind(records);
  const observeLease = leases.observe.bind(leases), applyLease = leases.compareAndApply.bind(leases);
  /** Leases this process holds, by stored key. A lost one commits nothing more. */
  const held = new Map<string, { token: string; lost: boolean }>();

  /** A lease another holder has taken: said once. The work still commits where the
   * record's generation is unchanged (compareAndSet checks it), so a refresh token the
   * server has already rotated is never thrown away. */
  function lost(lease: { token: string; lost: boolean }): void {
    if (lease.lost) return;
    lease.lost = true;
    options.warn?.("Agent Hooks Protocol: an OAuth lock expired or was taken while held");
  }

  /** Extend the lease only while it is still this holder's, in one compare-and-apply.
   * A storage error is tried again at the next renewal: it does not lose the lease. */
  async function renew(key: string, lease: { token: string; lost: boolean }): Promise<void> {
    let seen: { value: string | undefined; comparison: string };
    try {
      seen = await observeLease(key);
    } catch {
      return;
    }
    if (seen.value !== lease.token) return lost(lease);
    try {
      const result = await applyLease(key, seen.comparison, { operation: "update", action: "set", value: lease.token, ttlMs: leaseMs });
      if (result.status === "conflict" && result.current.value !== lease.token) lost(lease);
    } catch {
      // Tried again at the next renewal.
    }
  }

  /** Before a write under a lease: warn if another holder has it. */
  async function checkHeld(key: string): Promise<void> {
    const lease = held.get(key);
    if (!lease || lease.lost) return;
    try {
      if ((await leases.lookup(key)) !== lease.token) lost(lease);
    } catch {
      // The generation check below still guards the write.
    }
  }

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
        // The generation, not the lease, decides: a newer holder's write changes it.
        await checkHeld(stored);
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
        const lease = { token, lost: false };
        held.set(stored, lease);
        const timer = setInterval(() => void renew(stored, lease), Math.max(1, Math.floor(leaseMs / 3)));
        try {
          signal.throwIfAborted();
          return await work();
        } finally {
          clearInterval(timer);
          if (held.get(stored) === lease) held.delete(stored);
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
