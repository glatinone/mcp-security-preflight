# q-001 synthetic benchmark results

Date: 2026-09-12  
Python: 3.12.10  
Repeats per fixture: 1000  
Ground truth: hand labeled per tool. TP = expected rule fired, FP = unexpected rule fired, FN = expected rule missed.

| fixture | tools | findings | TP | FP | FN | median scan | p95 scan |
|---|---|---|---|---|---|---|---|
| safe_notes | 3 | 0 | 0 | 0 | 0 | 20.7 us | 26.9 us |
| risky_ops | 4 | 6 | 6 | 0 | 0 | 44.5 us | 53.7 us |
| mixed_shop | 8 | 3 | 3 | 0 | 0 | 68.7 us | 87.1 us |
| payment_tools | 6 | 3 | 3 | 0 | 0 | 54.3 us | 118.9 us |

## Aggregate

- Total tools: 21
- Planted findings detected: 12/12 (100.0%)
- False positives: 0
- Rule hits: MCP-001: 1, MCP-002: 4, MCP-003: 3, MCP-004: 4
- Median scan time per manifest: 49.4 us

Scope note: synthetic fixtures in a container, single thread. This measures rule engine behavior, not real world server latency.
