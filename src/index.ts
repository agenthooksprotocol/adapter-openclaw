// The OpenClaw plugin. OpenClaw can call `register` more than once in a process, as
// it rebuilds its plugin registry: every registration shares one adapter and client.
import { Adapter, PLUGIN_ID, type Api } from "./adapter.js";
import { lifecycle } from "./events/lifecycle.js";
import { messages } from "./events/messages.js";
import { model } from "./events/model.js";
import { tools } from "./events/tools.js";
import { turns } from "./events/turns.js";
import { CALLBACK_PATH, type Logins } from "./oauth/logins.js";
import { callbackRoute, chatCommand, cliCommands } from "./oauth/surfaces.js";

const adapter = new Adapter();
/** Registries alive: a throwaway one's disposal must not close the client under the Gateway's. */
let registries = 0;

export default {
  id: PLUGIN_ID,
  name: "Agent Hooks Protocol",
  description: "Delivers OpenClaw's lifecycle to Agent Hooks Protocol backends, and enforces what they decide",
  register(api: Api): void {
    adapter.api = api;
    registries += 1;
    api.lifecycle?.registerRuntimeLifecycle?.({
      id: PLUGIN_ID,
      dispose: async () => {
        registries -= 1;
        if (registries === 0) await adapter.close();
      },
    });
    lifecycle(adapter);
    turns(adapter);
    model(adapter);
    tools(adapter);
    messages(adapter);
    signIn(api);
  },
};

function signIn(api: Api): void {
  const logins = (): Logins => {
    const current = adapter.logins();
    if (!current) throw new Error("OAuth sign-in is unavailable in this OpenClaw");
    return current;
  };
  const backends = () => (adapter.registration().registration?.hooks ?? []) as { id: string }[];
  api.registerHttpRoute?.({ path: CALLBACK_PATH, auth: "plugin", match: "exact", handler: callbackRoute(logins) });
  api.registerCommand?.({
    name: "ahp",
    description: "Agent Hooks Protocol sign-in: status, login [backend], logout <backend>",
    acceptsArgs: true,
    requireAuth: true,
    handler: chatCommand(logins, backends),
  });
  api.registerCli?.(({ program }) => cliCommands(program as never, logins, backends), {
    descriptors: [{ name: "ahp", description: "Agent Hooks Protocol: backend sign-in", hasSubcommands: true }],
  });
}
