# Attempt at creating an MCP for every OpenAPI

![](openapi-to-mcp.drawio.png)

[![](https://badge.xymake.com/janwilmake/status/1913196601679523922)](https://xymake.com/janwilmake/status/1913196601679523922)

![](toolflare.drawio.png)

[![](https://badge.xymake.com/janwilmake/status/1913660585356501195)](https://xymake.com/janwilmake/status/1913660585356501195)

SPECS

- Swagger (openapi 2) - https://docs.swagger.io/spec.html
- Openapi 3 https://raw.githubusercontent.com/OAI/OpenAPI-Specification/refs/heads/main/versions/3.1.1.md
- Moonwalk (openapi 4) https://github.com/OAI/sig-moonwalk
- Arazzo specification - https://raw.githubusercontent.com/OAI/Arazzo-Specification/refs/heads/main/schemas/v1.0/schema.json
- A2A (Google) https://github.com/google/A2A/blob/main/specification/json/a2a.json
- Agents.json - https://raw.githubusercontent.com/wild-card-ai/agents-json/refs/heads/master/agents_json/agentsJson.schema.json
- MCP (Anthropic) - https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/refs/heads/main/schema/2025-03-26/schema.json
- OAuth2 Server Metadata https://datatracker.ietf.org/doc/html/rfc8414

Idea:

- Improve openapisearch such that it tracks used openapi specs found through the MCP (see https://github.com/janwilmake/openapisearch)
- Create remote MCP-server for each OpenAPI (this repo)
- Create remote A2A-server for each OpenAPI (not started)
- Set this up in a modular way such that others can easily contribute other specs (not started)

[Experiments](experiments):

- `cloudflare-remote-mcp-demo-analysis`: took the code from https://github.com/cloudflare/ai/tree/main/demos/remote-mcp-server and some dependencies to prompt its spec
- `dynamic-remote-mcp-server` adaptation of https://github.com/cloudflare/ai/tree/main/demos/remote-mcp-server trying to make that dynamic

Ongoing work (to be announced):

- https://github.com/janwilmake/curlmcp
