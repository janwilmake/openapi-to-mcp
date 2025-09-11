import YAML from "yaml";

interface McpConfig {
  protocolVersion: string;
  serverInfo: {
    name: string;
    version: string;
  };
  authEndpoint?: string;
  promptOperationIds: string[];
  toolOperationIds: string[];
  resourceOperationIds: string[];
  requiresAuth: boolean;
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
    "x-mcp"?: {
      protocolVersion?: string;
      authEndpoint?: string;
      serverInfo?: {
        name: string;
        version: string;
      };
      promptOperationIds?: string[];
      toolOperationIds?: string[];
      resourceOperationIds?: string[];
    };
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

// Helper function to create response with proper CORS headers
function createCorsResponse(
  body: BodyInit | null,
  options: ResponseInit = {}
): Response {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, MCP-Protocol-Version",
    "Access-Control-Max-Age": "86400",
  };

  // Merge headers, ensuring CORS headers take precedence
  const headers = new Headers(options.headers);

  // Remove any existing CORS headers to prevent duplicates
  headers.delete("Access-Control-Allow-Origin");
  headers.delete("Access-Control-Allow-Methods");
  headers.delete("Access-Control-Allow-Headers");
  headers.delete("Access-Control-Max-Age");

  // Add our CORS headers
  Object.entries(corsHeaders).forEach(([key, value]) => {
    headers.set(key, value);
  });

  return new Response(body, {
    ...options,
    headers,
  });
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return createCorsResponse(null, { status: 204 });
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
          return createCorsResponse(
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

            // If successful, return the response with CORS headers
            if (response.ok) {
              const json: any = await response.json();
              json.resource = `${url.origin}/${hostname}/mcp`;
              const responseHeaders = new Headers();

              // Copy non-CORS headers from the original response
              response.headers.forEach((value, key) => {
                if (!key.toLowerCase().startsWith("access-control-")) {
                  responseHeaders.set(key, value);
                }
              });

              return createCorsResponse(JSON.stringify(json, undefined, 2), {
                status: response.status,
                statusText: response.statusText,
                headers: responseHeaders,
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

          if (!response.ok) {
            return response;
          }

          const json: any = await response.json();
          json.resource = `${url.origin}/${hostname}/mcp`;

          const responseHeaders = new Headers();

          // Copy non-CORS headers from the original response
          response.headers.forEach((value, key) => {
            if (!key.toLowerCase().startsWith("access-control-")) {
              responseHeaders.set(key, value);
            }
          });

          return createCorsResponse(JSON.stringify(json), {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
          });
        } catch (error) {
          return createCorsResponse(
            JSON.stringify({
              error: "Failed to proxy to oauth-protected-resource endpoint",
              details: error.message,
            }),
            {
              status: 502,
              headers: { "Content-Type": "application/json" },
            }
          );
        }
      }

      return createCorsResponse(
        JSON.stringify({
          error:
            "Invalid oauth-protected-resource URL structure. Use: /.well-known/oauth-protected-resource/{hostname}/mcp",
          example:
            "https://mcp.openapisearch.com/.well-known/oauth-protected-resource/api.example.com/mcp",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Parse URL structure: /{hostname}/mcp
    const pathParts = url.pathname.split("/").filter(Boolean);
    if (pathParts.length !== 2 || pathParts[1] !== "mcp") {
      return createCorsResponse(
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
      return createCorsResponse(
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

        // Create new response with proper CORS headers
        const responseBody = response.body;
        const responseHeaders = new Headers();

        // Copy non-CORS headers from the original response
        response.headers.forEach((value, key) => {
          if (!key.toLowerCase().startsWith("access-control-")) {
            responseHeaders.set(key, value);
          }
        });

        return createCorsResponse(responseBody, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      return createCorsResponse(
        `MCP endpoint ready for ${hostname}.\nUse POST requests with MCP protocol.\nAvailable tools: ${mcpConfig.toolOperationIds.join(
          ", "
        )}\nRequires auth: ${mcpConfig.requiresAuth}`,
        {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        }
      );
    } catch (error) {
      console.error("Error processing request:", error);
      return createCorsResponse(
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

  // Get x-mcp configuration or use defaults
  const xMcp = openapi.info["x-mcp"];

  const protocolVersion = xMcp?.protocolVersion || "2025-03-26";
  const serverInfo = xMcp?.serverInfo || {
    name: openapi.info.title || `${hostname} API`,
    version: openapi.info.version || "1.0.0",
  };

  // Default: all operations are tools unless explicitly specified in x-mcp
  let toolOperationIds: string[];
  let promptOperationIds: string[];
  let resourceOperationIds: string[];

  if (xMcp) {
    // Use explicit configuration from x-mcp
    toolOperationIds = xMcp.toolOperationIds || [];
    promptOperationIds = xMcp.promptOperationIds || [];
    resourceOperationIds = xMcp.resourceOperationIds || [];

    // If none are specified, default all to tools
    if (
      toolOperationIds.length === 0 &&
      promptOperationIds.length === 0 &&
      resourceOperationIds.length === 0
    ) {
      toolOperationIds = Array.from(allOperations.keys());
    }
  } else {
    // No x-mcp: treat all operations as tools
    toolOperationIds = Array.from(allOperations.keys());
    promptOperationIds = [];
    resourceOperationIds = [];
  }

  // Filter operation IDs to only include those that exist in the spec
  toolOperationIds = toolOperationIds.filter((id) => allOperations.has(id));
  promptOperationIds = promptOperationIds.filter((id) => allOperations.has(id));
  resourceOperationIds = resourceOperationIds.filter((id) =>
    allOperations.has(id)
  );

  // Check for authorization requirements
  const { requiresAuth } = await checkAuthRequirements(
    openapi,
    allOperations,
    hostname,
    xMcp?.authEndpoint
  );

  return {
    protocolVersion,
    serverInfo,
    authEndpoint: xMcp?.authEndpoint,
    toolOperationIds,
    promptOperationIds,
    resourceOperationIds,
    requiresAuth,
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
  hostname: string,
  authEndpoint?: string
): Promise<{ requiresAuth: boolean }> {
  // If authEndpoint is specified in x-mcp, test it
  if (authEndpoint) {
    try {
      const testUrl = `https://${hostname}${authEndpoint}`;
      console.log(`Testing auth with specified endpoint: ${testUrl}`);

      const testResponse = await fetch(testUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
      });

      if (testResponse.status === 401) {
        console.log(`Auth required for ${hostname} (via authEndpoint)`);
        return { requiresAuth: true };
      }

      return { requiresAuth: false };
    } catch (error) {
      console.log(`Auth test failed for ${hostname}:`, error.message);
      return { requiresAuth: false };
    }
  }

  // Check if there's global security or any operation has security
  const hasGlobalSecurity = openapi.security && openapi.security.length > 0;

  // Find first operation that requires auth
  let requiresAuth = false;

  for (const [opId, { path, method, operation }] of allOperations) {
    const hasSecurity = operation.security && operation.security.length > 0;

    if (hasGlobalSecurity || hasSecurity) {
      // Test the operation to see if it returns proper auth challenges
      try {
        const testUrl = `https://${hostname}${path}`;
        console.log(`Testing auth with: ${method.toUpperCase()} ${testUrl}`);

        const testResponse = await fetch(testUrl, {
          method: method.toUpperCase(),
          headers: { Accept: "application/json" },
        });

        if (testResponse.status === 401) {
          console.log(`Auth required for ${hostname} (via operation ${opId})`);
          requiresAuth = true;
          break;
        }
      } catch (error) {
        console.log(`Auth test failed for operation ${opId}:`, error.message);
      }
    }
  }

  return { requiresAuth };
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
              ...(config.promptOperationIds.length > 0 && { prompts: {} }),
              ...(config.resourceOperationIds.length > 0 && { resources: {} }),
              ...(config.toolOperationIds.length > 0 && { tools: {} }),
            },
            serverInfo: config.serverInfo,
          },
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    if (message.method === "ping") {
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
          result: {},
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

      const tools = config.toolOperationIds.map((opId) => {
        const op = config.allOperations.get(opId);
        return {
          name: opId,
          description:
            op?.operation.description ||
            op?.operation.summary ||
            `Tool for operation: ${opId}`,
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

      const prompts = config.promptOperationIds.map((opId) => {
        const op = config.allOperations.get(opId);
        return {
          name: opId,
          description: op?.operation.description || op?.operation.summary,
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

      const resources = config.resourceOperationIds.map((opId) => {
        const op = config.allOperations.get(opId);
        return {
          uri: `resource://${opId}`,
          name: opId,
          description: op?.operation.description || op?.operation.summary,
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
  // Use authEndpoint if specified, otherwise find first operation that requires auth
  let testEndpoint = config.authEndpoint;

  if (!testEndpoint) {
    // Find first operation that might require auth
    for (const [opId, { path, method, operation }] of config.allOperations) {
      const hasGlobalSecurity =
        config.openapi.security && config.openapi.security.length > 0;
      const hasSecurity = operation.security && operation.security.length > 0;

      if (hasGlobalSecurity || hasSecurity) {
        testEndpoint = path;
        break;
      }
    }
  }

  if (!testEndpoint) {
    return null; // No auth required
  }

  try {
    const apiResponse = await fetch(`https://${hostname}${testEndpoint}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: request.headers.get("Authorization") || "",
      },
    });

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

      // Create new headers without existing CORS headers
      const headers = new Headers();
      apiResponse.headers.forEach((value, key) => {
        if (!key.toLowerCase().startsWith("access-control-")) {
          headers.set(key, value);
        }
      });

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
