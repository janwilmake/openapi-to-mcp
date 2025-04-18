import app from "./app";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import OAuthProvider from "@cloudflare/workers-oauth-provider";

/** NB: This is the exported durable object!!! */
export class MyMCP extends McpAgent {
  // I cannot easily define the McpServer dynamically as this is a static value in the McpAgent. Sunil?
  server: McpServer | undefined = undefined;

  async init() {
    // Fetch the name asynchronously
    const response = await fetch("https://your-api.com/openapi.json");
    const {
      info: { name, version },
    } = await response.json();

    this.server = new McpServer(
      { name, version },
      // The idea would be to add this in dynamically based on the OpenAPI spec
      //{ capabilities, enforceStrictCapabilities, instructions },
    );

    // tool executions are initialized here
    this.server.tool(
      "add",
      { a: z.number(), b: z.number() },
      async ({ a, b }) => ({
        content: [{ type: "text", text: String(a + b) }],
      }),
    );
  }
}

export default {
  fetch: (request: Request, env: any, ctx: ExecutionContext) => {
    const provider = new OAuthProvider({
      apiRoute: "/sse",
      // We could change the routes here.
      // TODO: fix these types
      // @ts-ignore
      apiHandler: MyMCP.mount("/sse"),
      // @ts-ignore
      defaultHandler: app,
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/token",
      clientRegistrationEndpoint: "/register",
    });

    return provider.fetch(request, env, ctx);
  },
};
