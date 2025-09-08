import YAML from "yaml";

interface McpConfig {
  protocolVersion?: string;
  serverInfo?: {
    name: string;
    version: string;
  };
  promptOperationIds?: string[];
  toolOperationIds?: string[];
  resourceOperationIds?: string[];
  authOperation?: {
    path: string;
    method: string;
    operation: OpenAPIOperation;
  };
  requiresAuth?: boolean;
  allOperations: Map<
    string,
    { path: string; method: string; operation: OpenAPIOperation }
  >;
  openapi: OpenAPISpec;
}

interface OpenAPIOperation {
  operationId: string;
  summary?: string;
  description?: string;
  parameters?: Array<{
    name: string;
    in: string;
    required?: boolean;
    description?: string;
    schema?: any;
  }>;
  requestBody?: {
    content?: {
      [mediaType: string]: {
        schema?: any;
      };
    };
  };
  responses?: {
    [statusCode: string]: {
      description?: string;
      content?: {
        [mediaType: string]: {
          schema?: any;
        };
      };
    };
  };
  security?: Array<{ [key: string]: string[] }>;
}

interface OpenAPISpec {
  openapi: string;
  info: {
    title: string;
    version: string;
  };
  paths: {
    [path: string]: {
      [method: string]: OpenAPIOperation;
    };
  };
  components?: {
    securitySchemes?: { [name: string]: any };
    schemas?: { [name: string]: any };
  };
  security?: Array<{ [key: string]: string[] }>;
  servers?: Array<{ url: string; description?: string }>;
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers":
            "Content-Type, Authorization, MCP-Protocol-Version",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Handle .well-known/oauth-protected-resource proxy
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource/")) {
      const pathParts = url.pathname
        .replace("/.well-known/oauth-protected-resource/", "")
        .split("/")
        .filter(Boolean);

      if (pathParts.length >= 1) {
        const hostname = pathParts[0];

        // Validate hostname format
        if (!isValidHostname(hostname)) {
          return new Response(
            JSON.stringify({ error: "Invalid hostname format" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json" },
            }
          );
        }

        // Try proxying to https://{hostname}/.well-known/oauth-protected-resource/mcp first
        if (pathParts.length >= 2 && pathParts[1] === "mcp") {
          try {
            const targetUrl = `https://${hostname}/.well-known/oauth-protected-resource/mcp`;
            console.log(`Proxying oauth-protected-resource to: ${targetUrl}`);

            const response = await fetch(targetUrl, {
              method: request.method,
              headers: request.headers,
              ...(request.method !== "GET" &&
                request.method !== "HEAD" && {
                  body: request.body,
                }),
            });

            // If successful, return the response
            if (response.ok) {
              return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: {
                  ...Object.fromEntries(response.headers.entries()),
                  "Access-Control-Allow-Origin": "*",
                },
              });
            }
          } catch (error) {
            console.log(`Failed to proxy to /mcp endpoint:`, error.message);
          }
        }

        // Fallback: try https://{hostname}/.well-known/oauth-protected-resource
        try {
          const targetUrl = `https://${hostname}/.well-known/oauth-protected-resource`;
          console.log(
            `Proxying oauth-protected-resource to fallback: ${targetUrl}`
          );

          const response = await fetch(targetUrl, {
            method: request.method,
            headers: request.headers,
            ...(request.method !== "GET" &&
              request.method !== "HEAD" && {
                body: request.body,
              }),
          });

          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: {
              ...Object.fromEntries(response.headers.entries()),
              "Access-Control-Allow-Origin": "*",
            },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              error: "Failed to proxy to oauth-protected-resource endpoint",
              details: error.message,
            }),
            {
              status: 502,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            }
          );
        }
      }

      return new Response(
        JSON.stringify({
          error:
            "Invalid oauth-protected-resource URL structure. Use: /.well-known/oauth-protected-resource/{hostname}/mcp",
          example:
            "https://mcp.openapisearch.com/.well-known/oauth-protected-resource/api.example.com/mcp",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }

    // Parse URL structure: /{hostname}/mcp
    const pathParts = url.pathname.split("/").filter(Boolean);
    if (pathParts.length !== 2 || pathParts[1] !== "mcp") {
      return new Response(
        JSON.stringify({
          error: "Invalid URL structure. Use: /{hostname}/mcp",
          example: "https://openapimcp.com/api.example.com/mcp",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    const hostname = pathParts[0];

    // Validate hostname format
    if (!isValidHostname(hostname)) {
      return new Response(
        JSON.stringify({ error: "Invalid hostname format" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    try {
      // Fetch and parse OpenAPI spec
      const openapi = await fetchOpenAPISpec(hostname);

      // Build MCP configuration from OpenAPI
      const mcpConfig = await buildMcpConfig(openapi, hostname);

      // Handle MCP requests
      if (request.method === "POST") {
        const response = await handleMcpRequest(request, mcpConfig, hostname);

        // Add CORS headers
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: {
            ...Object.fromEntries(response.headers.entries()),
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers":
              "Content-Type, Authorization, MCP-Protocol-Version",
          },
        });
      }

      return new Response(
        `MCP endpoint ready for ${hostname}.\nUse POST requests with MCP protocol.\nAvailable tools: ${
          mcpConfig.toolOperationIds?.join(", ") || "none"
        }\nRequires auth: ${mcpConfig.requiresAuth}`,
        {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        }
      );
    } catch (error) {
      console.error("Error processing request:", error);
      return new Response(
        JSON.stringify({
          error: "Failed to process OpenAPI specification",
          details: error.message,
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};

function isValidHostname(hostname: string): boolean {
  const hostnameRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
  return hostnameRegex.test(hostname) && hostname.length <= 253;
}

async function fetchOpenAPISpec(hostname: string): Promise<OpenAPISpec> {
  const urls = [
    `https://${hostname}/.well-known/openapi`,
    `https://${hostname}/openapi.json`,
    `https://${hostname}/openapi.yaml`,
    `https://${hostname}/openapi.yml`,
  ];

  for (const url of urls) {
    try {
      console.log(`Trying to fetch OpenAPI spec from: ${url}`);
      const response = await fetch(url, {
        headers: { Accept: "application/json, application/x-yaml, text/yaml" },
      });

      if (response.ok) {
        const contentType = response.headers.get("content-type") || "";
        const text = await response.text();

        let spec: any;
        if (
          contentType.includes("yaml") ||
          contentType.includes("yml") ||
          url.includes(".yaml") ||
          url.includes(".yml")
        ) {
          spec = YAML.parse(text);
        } else {
          spec = JSON.parse(text);
        }

        // Validate it's an OpenAPI spec
        if (spec.paths && spec.info) {
          console.log(`Found OpenAPI spec at: ${url}`);
          return spec as OpenAPISpec;
        }
      }
    } catch (error) {
      console.log(`Failed to fetch ${url}:`, error.message);
      continue;
    }
  }

  throw new Error(
    `No valid OpenAPI specification found for hostname: ${hostname}`
  );
}

async function buildMcpConfig(
  openapi: OpenAPISpec,
  hostname: string
): Promise<McpConfig> {
  const allOperations = new Map<
    string,
    { path: string; method: string; operation: OpenAPIOperation }
  >();

  // Extract all operations
  for (const [path, methods] of Object.entries(openapi.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (operation.operationId) {
        allOperations.set(operation.operationId, { path, method, operation });
      }
    }
  }

  // Check for specific MCP operations
  const toolsListOp = allOperations.get("tools/list");
  const promptsListOp = allOperations.get("prompts/list");
  const resourcesListOp = allOperations.get("resources/list");

  let toolOperationIds: string[] = [];
  let promptOperationIds: string[] = [];
  let resourceOperationIds: string[] = [];

  if (toolsListOp || promptsListOp || resourcesListOp) {
    // Use specific MCP operations if they exist
    if (toolsListOp) toolOperationIds = ["tools/list"];
    if (promptsListOp) promptOperationIds = ["prompts/list"];
    if (resourcesListOp) resourceOperationIds = ["resources/list"];
  } else {
    // Treat all operations as tools if no specific MCP operations found
    toolOperationIds = Array.from(allOperations.keys());
  }

  // Check for authorization requirements
  const { requiresAuth, authOperation } = await checkAuthRequirements(
    openapi,
    allOperations,
    hostname
  );

  return {
    protocolVersion: "2025-03-26",
    serverInfo: {
      name: openapi.info.title || `${hostname} API`,
      version: openapi.info.version || "1.0.0",
    },
    toolOperationIds,
    promptOperationIds,
    resourceOperationIds,
    requiresAuth,
    authOperation,
    allOperations,
    openapi,
  };
}

async function checkAuthRequirements(
  openapi: OpenAPISpec,
  allOperations: Map<
    string,
    { path: string; method: string; operation: OpenAPIOperation }
  >,
  hostname: string
): Promise<{ requiresAuth: boolean; authOperation?: any }> {
  // Check if there's global security or any operation has security
  const hasGlobalSecurity = openapi.security && openapi.security.length > 0;

  // Find first operation that requires auth
  let authOperation = null;

  for (const [opId, { path, method, operation }] of allOperations) {
    const hasSecurity = operation.security && operation.security.length > 0;

    if (hasGlobalSecurity || hasSecurity) {
      authOperation = { path, method, operation };
      break;
    }
  }

  if (!authOperation) {
    return { requiresAuth: false };
  }

  // Test the auth operation to see if it returns proper auth challenges
  try {
    const testUrl = `https://${hostname}${authOperation.path}`;
    console.log(
      `Testing auth with: ${authOperation.method.toUpperCase()} ${testUrl}`
    );

    const testResponse = await fetch(testUrl, {
      method: authOperation.method.toUpperCase(),
      headers: { Accept: "application/json" },
    });

    if (testResponse.status === 401) {
      const wwwAuth = testResponse.headers.get("www-authenticate");

      if (!wwwAuth) {
        // Check if resource metadata endpoint exists
        const resourceMetadataUrl = `https://${hostname}/.well-known/oauth-protected-resource`;
        try {
          console.log(`Checking resource metadata at: ${resourceMetadataUrl}`);
          const metadataResponse = await fetch(resourceMetadataUrl);
          if (!metadataResponse.ok) {
            throw new Error(
              "No www-authenticate header and no resource metadata endpoint"
            );
          }
          console.log("Found resource metadata endpoint");
        } catch (error) {
          throw new Error(
            `Authorization required but no proper auth challenge: ${error.message}`
          );
        }
      }

      console.log(
        `Auth required for ${hostname}, www-authenticate: ${wwwAuth}`
      );
      return { requiresAuth: true, authOperation };
    }
  } catch (error) {
    console.log(`Auth test failed for ${hostname}:`, error.message);
  }

  return { requiresAuth: false };
}

async function handleMcpRequest(
  request: Request,
  config: McpConfig,
  hostname: string
): Promise<Response> {
  try {
    const message: any = await request.json();

    // Handle initialize
    if (message.method === "initialize") {
      if (config.requiresAuth) {
        const authResult = await checkAuth(request, config, hostname);
        if (authResult) {
          return authResult;
        }
      }

      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: config.protocolVersion,
            capabilities: {
              ...(config.promptOperationIds &&
                config.promptOperationIds.length > 0 && { prompts: {} }),
              ...(config.resourceOperationIds &&
                config.resourceOperationIds.length > 0 && { resources: {} }),
              ...(config.toolOperationIds &&
                config.toolOperationIds.length > 0 && { tools: {} }),
            },
            serverInfo: config.serverInfo,
          },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Handle initialized notification
    if (message.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }

    // Handle tools/list
    if (message.method === "tools/list") {
      if (config.requiresAuth) {
        const authResult = await checkAuth(request, config, hostname);
        if (authResult) {
          return authResult;
        }
      }

      // If we have a specific tools/list operation, proxy to it
      if (config.toolOperationIds.includes("tools/list")) {
        return await proxyToOperation(
          "tools/list",
          {},
          request,
          hostname,
          config
        );
      }

      // Otherwise, return all tool operations as tools
      const tools = config.toolOperationIds
        .filter((id) => id !== "tools/list")
        .map((opId) => {
          const op = config.allOperations.get(opId);
          return {
            name: opId,
            title: op?.operation.summary || opId,
            description:
              op?.operation.description || `Tool for operation: ${opId}`,
            inputSchema: extractInputSchema(op?.operation),
          };
        });

      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { tools },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Handle prompts/list
    if (message.method === "prompts/list") {
      if (config.requiresAuth) {
        const authResult = await checkAuth(request, config, hostname);
        if (authResult) {
          return authResult;
        }
      }

      if (config.promptOperationIds.includes("prompts/list")) {
        return await proxyToOperation(
          "prompts/list",
          {},
          request,
          hostname,
          config
        );
      }

      const prompts = config.promptOperationIds
        .filter((id) => id !== "prompts/list")
        .map((opId) => {
          const op = config.allOperations.get(opId);
          return {
            name: opId,
            title: op?.operation.summary || opId,
            description: op?.operation.description,
            arguments: extractArguments(op?.operation),
          };
        });

      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { prompts },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Handle resources/list
    if (message.method === "resources/list") {
      if (config.requiresAuth) {
        const authResult = await checkAuth(request, config, hostname);
        if (authResult) {
          return authResult;
        }
      }

      if (config.resourceOperationIds.includes("resources/list")) {
        return await proxyToOperation(
          "resources/list",
          {},
          request,
          hostname,
          config
        );
      }

      const resources = config.resourceOperationIds
        .filter((id) => id !== "resources/list")
        .map((opId) => {
          const op = config.allOperations.get(opId);
          return {
            uri: `resource://${opId}`,
            name: opId,
            title: op?.operation.summary || opId,
            description: op?.operation.description,
            mimeType: inferMimeType(op?.operation),
          };
        });

      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { resources },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // Handle tools/call
    if (message.method === "tools/call") {
      const { name, arguments: args } = message.params;

      if (!config.toolOperationIds.includes(name)) {
        return createError(message.id, -32602, `Unknown tool: ${name}`);
      }

      try {
        const apiResponse = await proxyToOperation(
          name,
          args,
          request,
          hostname,
          config
        );

        // If 401 or 402, proxy the response as-is
        if (apiResponse.status === 401 || apiResponse.status === 402) {
          return apiResponse;
        }

        const text = await apiResponse.text();

        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              content: [{ type: "text", text }],
              isError: !apiResponse.ok,
            },
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              content: [{ type: "text", text: `Error: ${error.message}` }],
              isError: true,
            },
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // Handle prompts/get
    if (message.method === "prompts/get") {
      const { name, arguments: args } = message.params;

      if (!config.promptOperationIds.includes(name)) {
        return createError(message.id, -32602, `Unknown prompt: ${name}`);
      }

      try {
        const apiResponse = await proxyToOperation(
          name,
          args,
          request,
          hostname,
          config
        );

        // If 401 or 402, proxy the response as-is
        if (apiResponse.status === 401 || apiResponse.status === 402) {
          return apiResponse;
        }

        const text = await apiResponse.text();

        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              description:
                config.allOperations.get(name)?.operation.description,
              messages: [
                {
                  role: "user",
                  content: {
                    type: "text",
                    text: apiResponse.ok
                      ? text
                      : `Error: ${apiResponse.status} ${apiResponse.statusText}\n${text}`,
                  },
                },
              ],
            },
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      } catch (error) {
        return createError(
          message.id,
          -32603,
          `Error executing prompt: ${error.message}`
        );
      }
    }

    // Handle resources/read
    if (message.method === "resources/read") {
      const { uri } = message.params;
      const opId = uri.replace("resource://", "");

      if (!config.resourceOperationIds.includes(opId)) {
        return createError(message.id, -32002, `Resource not found: ${uri}`);
      }

      try {
        const apiResponse = await proxyToOperation(
          opId,
          {},
          request,
          hostname,
          config
        );

        // If 401 or 402, proxy the response as-is
        if (apiResponse.status === 401 || apiResponse.status === 402) {
          return apiResponse;
        }

        const text = await apiResponse.text();
        const contentType =
          apiResponse.headers.get("content-type") || "text/plain";

        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id,
            result: {
              contents: [
                {
                  uri,
                  mimeType: contentType,
                  text,
                },
              ],
            },
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      } catch (error) {
        return createError(
          message.id,
          -32603,
          `Error reading resource: ${error.message}`
        );
      }
    }

    return createError(
      message.id,
      -32601,
      `Method not found: ${message.method}`
    );
  } catch (error) {
    return createError(null, -32700, "Parse error");
  }
}

async function checkAuth(
  request: Request,
  config: McpConfig,
  hostname: string
): Promise<Response | null> {
  if (!config.authOperation) {
    return null;
  }

  try {
    const apiResponse = await proxyToOperation(
      config.authOperation.operation.operationId,
      {},
      request,
      hostname,
      config
    );

    if (apiResponse.status === 401 || apiResponse.status === 402) {
      let wwwAuth = apiResponse.headers.get("www-authenticate");

      if (!wwwAuth) {
        // Add resource metadata if it exists
        const resourceMetadataUrl = `https://${hostname}/.well-known/oauth-protected-resource`;
        try {
          const metadataResponse = await fetch(resourceMetadataUrl);
          if (metadataResponse.ok) {
            wwwAuth = `resource_metadata="${resourceMetadataUrl}"`;
          }
        } catch (error) {
          // Ignore metadata fetch errors
        }
      }

      // Clone the response and add www-authenticate if needed
      const headers = new Headers(apiResponse.headers);
      if (wwwAuth && !headers.has("www-authenticate")) {
        headers.set("www-authenticate", wwwAuth);
      }

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        statusText: apiResponse.statusText,
        headers,
      });
    }

    return null; // Auth passed
  } catch (error) {
    return new Response(
      JSON.stringify({ error: "Authentication check failed" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}

async function proxyToOperation(
  operationId: string,
  args: any,
  originalRequest: Request,
  hostname: string,
  config: McpConfig
): Promise<Response> {
  const op = config.allOperations.get(operationId);
  if (!op) {
    throw new Error(`Operation not found: ${operationId}`);
  }

  // Build the API request URL
  let url = op.path;
  const queryParams = new URLSearchParams();
  const bodyData: any = {};

  // Handle path and query parameters
  if (op.operation.parameters) {
    for (const param of op.operation.parameters) {
      const value = args[param.name];
      if (value !== undefined) {
        if (param.in === "path") {
          url = url.replace(
            `{${param.name}}`,
            encodeURIComponent(String(value))
          );
        } else if (param.in === "query") {
          queryParams.set(param.name, String(value));
        }
      }
    }
  }

  // Handle request body - merge remaining args into body
  const usedParamNames = new Set(
    op.operation.parameters?.map((p) => p.name) || []
  );

  for (const [key, value] of Object.entries(args)) {
    if (!usedParamNames.has(key)) {
      bodyData[key] = value;
    }
  }

  // Determine base URL from OpenAPI servers or default to hostname
  let baseUrl = `https://${hostname}`;
  if (config.openapi.servers && config.openapi.servers.length > 0) {
    const server = config.openapi.servers[0];
    if (server.url.startsWith("http")) {
      baseUrl = server.url;
    } else if (server.url.startsWith("/")) {
      baseUrl = `https://${hostname}${server.url}`;
    } else {
      baseUrl = `https://${hostname}/${server.url}`;
    }
  }

  // Build final URL
  const finalUrl = new URL(url, baseUrl);
  if (queryParams.toString()) {
    finalUrl.search = queryParams.toString();
  }

  // Prepare headers
  const headers: HeadersInit = {
    Accept: "application/json",
    "User-Agent": "OpenAPI-MCP-Worker/1.0",
  };

  // Forward authorization header
  const authHeader = originalRequest.headers.get("Authorization");
  if (authHeader) {
    headers["Authorization"] = authHeader;
  }

  // Add content-type for requests with body
  if (op.method.toLowerCase() !== "get" && Object.keys(bodyData).length > 0) {
    headers["Content-Type"] = "application/json";
  }

  console.log(`Proxying to: ${op.method.toUpperCase()} ${finalUrl.toString()}`);
  console.log(`Headers:`, headers);
  if (Object.keys(bodyData).length > 0) {
    console.log(`Body:`, bodyData);
  }

  // Make the API request
  const apiRequest = new Request(finalUrl.toString(), {
    method: op.method.toUpperCase(),
    headers,
    ...(op.method.toLowerCase() !== "get" &&
      Object.keys(bodyData).length > 0 && {
        body: JSON.stringify(bodyData),
      }),
  });

  return fetch(apiRequest);
}

function extractArguments(operation?: OpenAPIOperation) {
  if (!operation) return [];

  const args = [];

  // Extract from parameters
  if (operation.parameters) {
    for (const param of operation.parameters) {
      args.push({
        name: param.name,
        description: param.description,
        required: param.required || false,
      });
    }
  }

  // Extract from request body schema properties
  if (
    operation.requestBody?.content?.["application/json"]?.schema?.properties
  ) {
    const props =
      operation.requestBody.content["application/json"].schema.properties;
    const required =
      operation.requestBody.content["application/json"].schema.required || [];

    for (const [name, schema] of Object.entries(props)) {
      args.push({
        name,
        description: (schema as any).description,
        required: required.includes(name),
      });
    }
  }

  return args;
}

function extractInputSchema(operation?: OpenAPIOperation) {
  if (!operation) {
    return {
      type: "object",
      properties: {},
    };
  }

  // Start with basic object schema
  const schema: any = {
    type: "object",
    properties: {},
    required: [],
  };

  // Add parameters as properties
  if (operation.parameters) {
    for (const param of operation.parameters) {
      schema.properties[param.name] = param.schema || { type: "string" };
      if (param.required) {
        schema.required.push(param.name);
      }
    }
  }

  // Merge request body schema
  if (operation.requestBody?.content?.["application/json"]?.schema) {
    const bodySchema = operation.requestBody.content["application/json"].schema;
    if (bodySchema.properties) {
      Object.assign(schema.properties, bodySchema.properties);
    }
    if (bodySchema.required) {
      schema.required.push(...bodySchema.required);
    }
  }

  return schema;
}

function inferMimeType(operation?: OpenAPIOperation): string {
  if (!operation) return "application/json";

  // Check response content types
  const responses = operation.responses;
  if (responses) {
    for (const response of Object.values(responses)) {
      if (response.content) {
        const contentTypes = Object.keys(response.content);
        if (contentTypes.length > 0) {
          const preferred = ["text/plain", "text/markdown", "application/json"];
          const pref = contentTypes.find((x) => preferred.includes(x));
          if (pref) {
            return pref;
          }
          return contentTypes[0];
        }
      }
    }
  }

  return "application/json";
}

function createError(id: any, code: number, message: string): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: { code, message },
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}
