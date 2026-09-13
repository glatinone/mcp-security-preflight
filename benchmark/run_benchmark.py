import json, platform, statistics, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.rules import scan_tools
BENCH = Path(__file__).resolve().parent
FIXTURES = ["safe_notes", "risky_ops", "mixed_shop", "payment_tools", "leaky_agent"]
EXPECTED = {
  "safe_notes": {},
  "risky_ops": {
    "shell.run": ["MCP-001", "MCP-002", "MCP-004"],
    "fetch.export": ["MCP-002"],
    "creds.check": ["MCP-003"],
    "admin.act": ["MCP-004"]},
  "mixed_shop": {
    "sync.payments": ["MCP-002"],
    "report.generate": ["MCP-004"],
    "metrics.push": ["MCP-003"]},
  "payment_tools": {
    "export.ledger": ["MCP-002"],
    "payout.sync": ["MCP-004"],
    "gateway.health": ["MCP-003"]},
  "leaky_agent": {
    "proxy.fetch": ["MCP-005"],
    "admin.users.update": ["MCP-006"],
    "notes.list": ["MCP-007"]},
}
rows, rule_counts = [], {}
tp_all = fp_all = fn_all = 0
for fx in FIXTURES:
    tools = json.loads((BENCH / "fixtures" / (fx + ".json")).read_text())["tools"]
    durs, findings = [], []
    for _ in range(1000):
        t0 = time.perf_counter()
        findings = scan_tools(tools)
        durs.append(time.perf_counter() - t0)
    exp, got = EXPECTED[fx], {}
    for f in findings:
        got.setdefault(f.tool, []).append(f.id)
        rule_counts[f.id] = rule_counts.get(f.id, 0) + 1
    tp = fp = fn = 0
    for tool, ids in got.items():
        e = exp.get(tool, [])
        tp += sum(1 for i in ids if i in e)
        fp += sum(1 for i in ids if i not in e)
    for tool, e in exp.items():
        g = got.get(tool, [])
        fn += sum(1 for i in e if i not in g)
    tp_all += tp; fp_all += fp; fn_all += fn
    durs_us = sorted(d * 1e6 for d in durs)
    rows.append({"fixture": fx, "tools": len(tools), "findings": len(findings), "tp": tp, "fp": fp, "fn": fn,
                 "median_us": round(statistics.median(durs_us), 1),
                 "p95_us": round(durs_us[int(0.95 * len(durs_us)) - 1], 1)})
detection = round(100 * tp_all / (tp_all + fn_all), 1) if tp_all + fn_all else 100.0
agg = {"tools": sum(r["tools"] for r in rows), "findings": sum(r["findings"] for r in rows),
       "true_positives": tp_all, "false_positives": fp_all, "false_negatives": fn_all,
       "detection_rate_pct": detection, "rule_counts": dict(sorted(rule_counts.items())),
       "median_scan_us_per_manifest": round(statistics.median([r["median_us"] for r in rows]), 1)}
result = {"date": "2026-09-12", "python": platform.python_version(), "repeats": 1000, "rows": rows, "aggregate": agg}
(BENCH / "results.json").write_text(json.dumps(result, indent=2) + "\n")
lines = ["# q-001 synthetic benchmark results", "", f"Date: {result['date']}  ", f"Python: {result['python']}  ", "Repeats per fixture: 1000  ", "Ground truth: hand labeled per tool. TP = expected rule fired, FP = unexpected rule fired, FN = expected rule missed.", "",
         "| fixture | tools | findings | TP | FP | FN | median scan | p95 scan |", "|---|---|---|---|---|---|---|---|"]
for r in rows:
    lines.append(f"| {r['fixture']} | {r['tools']} | {r['findings']} | {r['tp']} | {r['fp']} | {r['fn']} | {r['median_us']} us | {r['p95_us']} us |")
lines += ["", "## Aggregate", "", f"- Total tools: {agg['tools']}", f"- Planted findings detected: {tp_all}/{tp_all + fn_all} ({detection}%)", f"- False positives: {fp_all}", f"- Rule hits: " + ", ".join(f"{k}: {v}" for k, v in agg['rule_counts'].items()), f"- Median scan time per manifest: {agg['median_scan_us_per_manifest']} us", "", "Scope note: synthetic fixtures in a container, single thread. This measures rule engine behavior, not real world server latency."]
(BENCH / "RESULTS.md").write_text("\n".join(lines) + "\n")
print(json.dumps(agg, indent=2))
for r in rows: print(r)
