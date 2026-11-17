// Client secrets an authorization server issued at dynamic registration, and the
// secrets the operator configures. OpenClaw gives a plugin no keychain or writable
// secret store, so issued secrets are files of their own, apart from the tokens:
// one 0600 file per reference in a 0700 directory under OpenClaw's state directory.
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SecretStore } from "agenthooksprotocol/oauth";

const name = (reference: string) => createHash("sha256").update(reference).digest("hex");

export function fileSecretStore(directory: string): SecretStore {
  const path = (reference: string) => join(directory, name(reference));
  const ensure = () => {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
  };
  return {
    async put(reference, secret, signal) {
      signal.throwIfAborted();
      ensure();
      // Written aside, then renamed: a reader never sees half a secret.
      const temporary = `${path(reference)}.${process.pid}.${crypto.randomUUID()}`;
      writeFileSync(temporary, secret, { mode: 0o600, flag: "wx" });
      renameSync(temporary, path(reference));
    },
    async get(reference, signal) {
      signal.throwIfAborted();
      const file = path(reference);
      return existsSync(file) ? readFileSync(file, "utf8") : undefined;
    },
    async delete(reference, signal) {
      signal.throwIfAborted();
      try {
        unlinkSync(path(reference));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    },
  };
}

/** A configured secret: a literal, or an OpenClaw-style reference to an environment
 * variable or a file. */
export type SecretInput = string | { source: "env" | "file"; provider?: string; id: string };

export function resolveSecret(input: unknown, environment: Record<string, string | undefined>): string | undefined {
  if (typeof input === "string") return input || undefined;
  if (!input || typeof input !== "object") return undefined;
  const { source, id } = input as { source?: unknown; id?: unknown };
  if (typeof id !== "string" || !id) return undefined;
  if (source === "env") return environment[id] || undefined;
  if (source === "file") return existsSync(id) ? readFileSync(id, "utf8").trim() || undefined : undefined;
  return undefined;
}
