# q-001 synthetic benchmark results

Date: 2026-09-12  
Python: 3.12.10  
Repeats per fixture: 1000  
Ground truth: hand labeled per tool. TP = expected rule fired, FP = unexpected rule fired, FN = expected rule missed.

| fixture | tools | findings | TP | FP | FN | median scan | p95 scan |
|---|---|---|---|---|---|---|---|
| safe_notes | 3 | 0 | 0 | 0 | 0 | 30.3 us | 35.1 us |
| risky_ops | 4 | 6 | 6 | 0 | 0 | 60.4 us | 70.5 us |
| mixed_shop | 8 | 3 | 3 | 0 | 0 | 99.5 us | 137.4 us |
| payment_tools | 6 | 3 | 3 | 0 | 0 | 76.7 us | 89.5 us |
| leaky_agent | 3 | 3 | 3 | 0 | 0 | 88.8 us | 106.1 us |

## Aggregate

- Total tools: 24
- Planted findings detected: 15/15 (100.0%)
- False positives: 0
- Rule hits: MCP-001: 1, MCP-002: 4, MCP-003: 3, MCP-004: 4, MCP-005: 1, MCP-006: 1, MCP-007: 1
- Median scan time per manifest: 76.7 us

Scope note: synthetic fixtures in a container, single thread. This measures rule engine behavior, not real world server latency.
