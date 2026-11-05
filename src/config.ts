// Registration discovery: `hooks.json` under `~/.agents/` and OpenClaw's state
// directory, merged into one AHP registration document.
//
// Only a user's files count. One Gateway serves many workspaces, and an agent can
// write to its own: a file there could choose where session content goes, or turn
// off the policy that governs the agent writing it.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Environment = Record<string, string | undefined>;

export interface LoadedRegistration {
  /** The merged registration, or undefined when no file declares a backend. */
  registration?: { protocolVersion: "draft"; hooks: Record<string, unknown>[] };
  /** The files that contributed, lowest precedence first. */
  sources: string[];
  /** Files or backends skipped: a person should know a policy may not be running. */
  diagnostics: string[];
  /** Backends replaced by a more specific file: normal, and detail. */
  notes: string[];
}

/** OpenClaw's directory for this user. */
export function stateDir(environment: Environment): string | undefined {
  return environment.OPENCLAW_STATE_DIR ?? (environment.HOME ? join(environment.HOME, ".openclaw") : undefined);
}

/** Lowest precedence first: a later file's backend replaces an earlier one with the
 * same `id`, and OpenClaw's directory beats `.agents`. */
export function registrationPaths(environment: Environment): string[] {
  const paths: string[] = [];
  if (environment.HOME) paths.push(join(environment.HOME, ".agents/hooks.json"));
  const state = stateDir(environment);
  if (state) paths.push(join(state, "hooks.json"));
  return paths;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Read and merge every registration file that exists. Structural validation of
 * the result is the SDK's: this only keeps files from poisoning each other. */
export function loadRegistration(environment: Environment): LoadedRegistration {
  // One explicit file replaces discovery (tests, CI, a pinned deployment).
  const paths = environment.AHP_HOOKS_FILE ? [environment.AHP_HOOKS_FILE] : registrationPaths(environment);
  const diagnostics: string[] = [];
  const notes: string[] = [];
  const sources: string[] = [];
  const backends = new Map<string, { backend: Record<string, unknown>; path: string }>();
  for (const path of paths) {
    if (!existsSync(path)) continue;
    let document: unknown;
    try {
      document = JSON.parse(readFileSync(path, "utf8"));
    } catch (error) {
      diagnostics.push(`${path}: unreadable or not JSON (${error instanceof SyntaxError ? "syntax error" : String(error)}); skipped`);
      continue;
    }
    if (!object(document) || document.protocolVersion !== "draft" || !Array.isArray(document.hooks)) {
      diagnostics.push(`${path}: not an AHP draft registration (protocolVersion "draft", hooks[]); skipped`);
      continue;
    }
    sources.push(path);
    for (const backend of document.hooks) {
      if (!object(backend) || typeof backend.id !== "string") {
        diagnostics.push(`${path}: a backend without an id; skipped`);
        continue;
      }
      const previous = backends.get(backend.id);
      if (previous) notes.push(`${backend.id}: ${path} replaces ${previous.path}`);
      backends.set(backend.id, { backend, path });
    }
  }
  if (backends.size === 0) return { sources, diagnostics, notes };
  return {
    registration: { protocolVersion: "draft", hooks: [...backends.values()].map(({ backend }) => backend) },
    sources,
    diagnostics,
    notes,
  };
}
