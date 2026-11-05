// Reading a boundary result.
import type { DeliveryDiagnostic } from "agenthooksprotocol/client";
import { texts } from "./content.js";

/** What every boundary result has, whatever its event. */
export interface AnyResult {
  readonly event: unknown;
  readonly effects: unknown;
  readonly acceptedResponses: readonly unknown[];
  readonly state: unknown;
  readonly content?: { close(): Promise<void> };
  readonly diagnostics: readonly DeliveryDiagnostic[];
  readonly interrupted: boolean;
}

function residual(result: AnyResult): readonly Record<string, unknown>[] {
  return (result.effects ?? []) as unknown as readonly Record<string, unknown>[];
}

/** User-visible `message` effects. */
export function messages(result: AnyResult): string[] {
  return residual(result)
    .filter((effect) => effect.type === "message" && typeof effect.text === "string")
    .map((effect) => effect.text as string);
}

/** Model-visible `inject` effects, as strings. */
export function injections(result: AnyResult): string[] {
  const state = result.state as { injections?: readonly { value?: readonly unknown[] }[] };
  const fromState = state.injections ?? [];
  const fromEffects = residual(result).filter((effect) => effect.type === "inject") as { value?: readonly unknown[] }[];
  const all = fromState.length ? fromState : fromEffects;
  return all.flatMap((effect) => texts(effect.value as unknown[] | undefined)).filter((text) => text !== "");
}

/** The accepted `flow` operation, if any: stop outranks continue. */
export function flow(result: AnyResult): { operation: "stop"; reason: string } | { operation: "continue"; instruction?: string } | undefined {
  const flows = residual(result).filter((effect) => effect.type === "flow");
  const stop = flows.find((effect) => effect.operation === "stop");
  if (stop) return { operation: "stop", reason: String(stop.reason ?? "Stopped by an AHP hook") };
  const state = result.state as { flow?: string };
  const go = flows.find((effect) => effect.operation === "continue");
  if (go || state.flow === "continue") {
    const instruction = flows
      .filter((effect) => effect.operation === "continue" && typeof effect.instruction === "string")
      .map((effect) => effect.instruction as string)
      .join("\n");
    return { operation: "continue", ...(instruction ? { instruction } : {}) };
  }
  if (state.flow === "stop") return { operation: "stop", reason: "Stopped by an AHP hook" };
  return undefined;
}

/** Whether the boundary refused the operation, and why. */
export function denial(result: AnyResult): string | undefined {
  const state = result.state as { permission?: string };
  if (!result.interrupted && state.permission !== "deny") return undefined;
  for (const response of result.acceptedResponses as unknown as readonly { response?: { result?: { effects?: { type?: string; reason?: string }[] } }; result?: { effects?: { type?: string; reason?: string }[] } }[]) {
    const effects = response.response?.result?.effects ?? response.result?.effects ?? [];
    const deny = effects.find((effect) => effect.type === "deny");
    if (deny?.reason) return deny.reason;
  }
  if (result.diagnostics.some((diagnostic) => diagnostic.syntheticDenial))
    return "An AHP hook was unavailable and its failure policy is fail-closed";
  return "Denied by an AHP hook";
}

/** A value a backend supplied with `return`, if any. */
export function supplied(result: AnyResult): { value: unknown } | undefined {
  return (result.state as { candidate?: { value: unknown } | null }).candidate ?? undefined;
}

/** The id the SDK gave the delivered event. */
export function eventId(result: AnyResult): string | undefined {
  const id = (result.event as { id?: unknown } | undefined)?.id;
  return typeof id === "string" ? id : undefined;
}

export function describe(value: unknown): string {
  if (value instanceof Error) return value.message;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
