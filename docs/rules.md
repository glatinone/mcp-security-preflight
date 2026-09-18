# Rules

- MCP-001 blocks unsafe command declarations.
- MCP-002 flags broad filesystem and network scope.
- MCP-003 detects and redacts secret-like metadata.
- MCP-004 flags input flowing into sensitive operations.
- MCP-005 flags credentials forwarded in tool metadata (e.g. an auth/bearer header baked into the declaration instead of supplied at runtime).
- MCP-006 flags write operations declared with no tenant scoping.
- MCP-007 flags caller-controlled tenant identity: a tool that accepts `tenant_id` as a plain parameter with no identity-provider reference.
- MCP-008 flags instruction-like text inside a tool description (prompt injection via tool metadata; descriptions are data, never instructions).
- MCP-009 flags tool name shadowing: the same tool name declared by more than one source, which lets an untrusted or compromised source silently hijack calls meant for a trusted tool.
- Behavioral checks cover tenant boundaries, approval gates, and quota.
