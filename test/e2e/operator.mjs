// A connected operator: what a Control UI is to the Gateway. Prints approvals and
// chat events as JSON lines, and answers approvals with the decision it was given.
// operator.mjs <path to openclaw's gateway-runtime.js> <url> <allow-once|deny|none>
const [runtime, url, decision] = process.argv.slice(2);
const { GatewayClient } = await import(runtime);
const client = new GatewayClient({
  url,
  clientName: "cli",
  mode: "cli",
  caps: ["approvals", "plugin-approvals"],
  scopes: ["operator.read", "operator.write", "operator.approvals", "operator.admin"],
  onHelloOk: () => console.log(JSON.stringify({ ready: true })),
  onEvent: (frame) => {
    if (frame.event === "plugin.approval.requested") {
      console.log(JSON.stringify({ approval: frame.payload.request }));
      if (decision !== "none") void client.request("plugin.approval.resolve", { id: frame.payload.id, decision });
    }
    if (frame.event === "chat") console.log(JSON.stringify({ chat: frame.payload }));
  },
});
client.start();
