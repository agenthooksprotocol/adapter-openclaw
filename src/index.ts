// The OpenClaw plugin. OpenClaw can call `register` more than once in a process, as
// it rebuilds its plugin registry: every registration shares one adapter and client.
import { Adapter, PLUGIN_ID, type Api } from "./adapter.js";
import { lifecycle } from "./events/lifecycle.js";
import { messages } from "./events/messages.js";
import { model } from "./events/model.js";
import { tools } from "./events/tools.js";
import { turns } from "./events/turns.js";

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
  },
};
