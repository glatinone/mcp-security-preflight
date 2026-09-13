# Changelog


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