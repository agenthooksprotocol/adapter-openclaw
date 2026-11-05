// An MCP server's connection as AHP describes it, without what may hold a
// credential: environment and headers stay out, and a URL keeps only its address.
export function connection(config: Record<string, unknown> | undefined) {
  if (typeof config?.url === "string") {
    try {
      const url = new URL(config.url);
      return { transport: "http" as const, url: `${url.origin}${url.pathname}` };
    } catch {
      return { transport: "http" as const, gaps: [{ path: "url", reason: "the configured address is not a URL" }] };
    }
  }
  if (typeof config?.command === "string")
    return {
      transport: "stdio" as const,
      gaps: [
        { path: "command", reason: "a local server's command line may hold a credential" },
        { path: "args", reason: "a local server's command line may hold a credential" },
        { path: "cwd", reason: "a local server's working directory is not reported" },
      ],
    };
  return { transport: "unknown", gaps: [{ path: "address", reason: "the server's configuration is not visible to this plugin" }, { path: "addressForm", reason: "the server's configuration is not visible to this plugin" }] };
}
