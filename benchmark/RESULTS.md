# q-001 synthetic benchmark results

Date: 2026-09-12  
Python: 3.13.12  
Repeats per fixture: 1000  
Ground truth: hand labeled per tool. TP = expected rule fired, FP = unexpected rule fired, FN = expected rule missed.

| fixture | tools | findings | TP | FP | FN | median scan | p95 scan |
|---|---|---|---|---|---|---|---|
| safe_notes | 3 | 0 | 0 | 0 | 0 | 32.5 us | 43.2 us |
| risky_ops | 4 | 6 | 6 | 0 | 0 | 72.3 us | 107.6 us |
| mixed_shop | 8 | 3 | 3 | 0 | 0 | 111.5 us | 166.4 us |
| payment_tools | 6 | 3 | 3 | 0 | 0 | 82.3 us | 131.3 us |
| leaky_agent | 3 | 2 | 2 | 0 | 0 | 89.1 us | 100.4 us |

## Aggregate

- Total tools: 24
- Planted findings detected: 14/14 (100.0%)
- False positives: 0
- Rule hits: MCP-001: 1, MCP-002: 4, MCP-003: 3, MCP-004: 4, MCP-005: 1, MCP-006: 1
- Median scan time per manifest: 82.3 us

Scope note: synthetic fixtures in a container, single thread. This measures rule engine behavior, not real world server latency.
