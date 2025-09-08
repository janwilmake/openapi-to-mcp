based on: https://uithub.com/janwilmake/with-mcp

openapi-to-mcp-worker that exposes MCPs requirements for any hostname that exposes an openapi.json?

https://openapimcp.com/{hostname}/mcp

How it should work:

- validate hostname to have a valid openapi
- look for `tools/list`, `prompts/list`, and `resources/list` operations and proxy to these. If none available, all operations are deemed tools.
- check if openapi has authorization. if so, find first operation that requires it, and call it and respond with its response incase we get a 401. incase that doesn't include www-authenticate, add it with `resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`

<!-- https://letmeprompt.com/rules-httpsuithu-8xtxyv0 -->
