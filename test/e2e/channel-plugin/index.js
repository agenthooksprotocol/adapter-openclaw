import { appendFileSync } from "node:fs";
const log = (x) => appendFileSync(process.env.CHANNEL_LOG, JSON.stringify(x) + "\n");
const plugin = {
  id: "recch",
  meta: { id: "recch", label: "Rec", selectionLabel: "Rec", docsPath: "/channels/recch", blurb: "rec" },
  capabilities: { chatTypes: ["direct"] },
  config: { listAccountIds: () => ["default"], resolveAccount: () => ({ accountId: "default", enabled: true, configured: true }), isConfigured: () => true, isEnabled: () => true },
  outbound: { deliveryMode: "direct", resolveTarget: ({ to }) => ({ ok: true, to: to ?? "x" }), sendText: async (ctx) => { log({ text: ctx.text, to: ctx.to }); return { channel: "recch", messageId: String(Date.now()) }; } },
};
export default { id: "recch", name: "Rec", register(api) { api.registerChannel({ plugin }); } };
