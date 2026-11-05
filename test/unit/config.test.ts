import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadRegistration, registrationPaths, stateDir } from "../../src/config";

const home = mkdtempSync(join(tmpdir(), "ahp-openclaw-config-"));
afterAll(() => rmSync(home, { recursive: true, force: true }));

const backend = (id: string, url: string) => ({ id, transport: { type: "http", url }, subscriptions: [] });
function write(path: string, value: unknown): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
}

describe("registration paths", () => {
  test("the state directory follows OPENCLAW_STATE_DIR", () => {
    expect(stateDir({ HOME: "/h" })).toBe("/h/.openclaw");
    expect(stateDir({ HOME: "/h", OPENCLAW_STATE_DIR: "/s" })).toBe("/s");
    expect(stateDir({})).toBeUndefined();
  });

  test("only a user's files, OpenClaw's last", () => {
    expect(registrationPaths({ HOME: "/h" })).toEqual(["/h/.agents/hooks.json", "/h/.openclaw/hooks.json"]);
  });
});

describe("loadRegistration", () => {
  test("nothing configured is no registration", () => {
    const empty = mkdtempSync(join(home, "empty-"));
    expect(loadRegistration({ HOME: empty }).registration).toBeUndefined();
  });

  test("merges by id, and the later file wins", () => {
    const user = mkdtempSync(join(home, "user-"));
    write(join(user, ".agents/hooks.json"), { protocolVersion: "draft", hooks: [backend("a", "http://a"), backend("b", "http://b")] });
    write(join(user, ".openclaw/hooks.json"), { protocolVersion: "draft", hooks: [backend("b", "http://b2")] });
    const { registration, sources, notes } = loadRegistration({ HOME: user });
    expect(registration!.hooks.map((hook) => hook.id)).toEqual(["a", "b"]);
    expect((registration!.hooks[1]!.transport as { url: string }).url).toBe("http://b2");
    expect(sources).toHaveLength(2);
    expect(notes[0]).toContain("replaces");
  });

  test("AHP_HOOKS_FILE replaces discovery", () => {
    const user = mkdtempSync(join(home, "pinned-"));
    write(join(user, ".agents/hooks.json"), { protocolVersion: "draft", hooks: [backend("a", "http://a")] });
    write(join(user, "pinned.json"), { protocolVersion: "draft", hooks: [backend("p", "http://p")] });
    const { registration } = loadRegistration({ HOME: user, AHP_HOOKS_FILE: join(user, "pinned.json") });
    expect(registration!.hooks.map((hook) => hook.id)).toEqual(["p"]);
  });

  test("a broken file is reported, and does not poison the others", () => {
    const user = mkdtempSync(join(home, "broken-"));
    write(join(user, ".agents/hooks.json"), "{ nope");
    write(join(user, ".openclaw/hooks.json"), { protocolVersion: "draft", hooks: [backend("a", "http://a"), { noId: true }] });
    const { registration, diagnostics } = loadRegistration({ HOME: user });
    expect(registration!.hooks).toHaveLength(1);
    expect(diagnostics).toHaveLength(2);
  });

  test("another protocol version is reported", () => {
    const user = mkdtempSync(join(home, "version-"));
    write(join(user, ".agents/hooks.json"), { protocolVersion: "1", hooks: [] });
    expect(loadRegistration({ HOME: user }).diagnostics[0]).toContain("not an AHP draft registration");
  });

  test("a workspace's file is never read", () => {
    const user = mkdtempSync(join(home, "workspace-"));
    write(join(user, "project/.agents/hooks.json"), { protocolVersion: "draft", hooks: [backend("evil", "http://evil")] });
    expect(loadRegistration({ HOME: user }).registration).toBeUndefined();
  });
});
