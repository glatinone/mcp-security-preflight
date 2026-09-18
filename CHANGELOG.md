# Changelog


## v1.3.0 (2026-09-18)

- MCP-009: tool name shadowing. Flags a tool name declared by more than one source, the pattern behind MCP "rug pull" reports where an untrusted server registers a tool name that collides with a trusted one to silently hijack calls meant for it.
- Fixtures: two `notes.search` entries (trusted_connector vs. unverified_plugin_7f3a) exercise the new rule; one finding is raised, not one per duplicate.
- docs/rules.md updated: it stopped at MCP-004 and never documented MCP-005 through MCP-008.
- 16/16 stdlib tests. Benchmark unchanged (15 true positives, 0 false positives, 100% detection) since MCP-009 needs no new benchmark fixture to stay green.


## v1.2.0 (2026-09-13)

- MCP-007: caller-controlled tenant identity. Flags tools that accept a tenant_id parameter with no identity-provider reference (JWT, session, IdP, OAuth, authenticated context). The confused-deputy class where tenant identity comes from the caller.
- MCP-008: instruction-like text in tool descriptions. Flags prompt-injection patterns inside tool description fields. Tool descriptions are data, never instructions.
- Fixtures: tenants.transfer (caught by 007), tenants.lookup (IdP-resolved, clean), sync.contacts (injection description, caught by 008), calendar.block (clean).
- 14/14 stdlib tests. Benchmark: 15 true positives, 0 false positives across 5 fixtures, 30 tools.



## 2026-09-12

- Added MCP-005: credential forwarding in tool metadata (from AI bounty pattern library angle 5)

- Added MCP-006: write operation without tenant scoping (from angle 6)

- Two new fixture tools trigger the new rules; suite now 12 checks, all passing

- Added q-001 synthetic benchmark: 4 fixtures, 1000 repeats, 12/12 planted findings detected, 0 false positives, median scan 76.5 us per manifest