import json
from pathlib import Path

def write_reports(run_id, findings, checks, audit_events):
    root=Path(__file__).resolve().parents[1]/"reports"; root.mkdir(exist_ok=True)
    data={"run_id":run_id,"status":"completed","finding_count":len(findings),"findings":[f.as_dict() for f in findings],"checks":checks,"audit_events":audit_events}
    (root/(run_id+".json")).write_text(json.dumps(data,indent=2)+"\n")
    lines=[f"# MCP Security Preflight {run_id}","",f"Finding count: {len(findings)}","","## Findings"]
    for f in findings: lines += [f"### {f.id} - {f.severity.upper()} - {f.tool}",f"- Title: {f.title}",f"- Evidence: {f.evidence}",f"- Remediation: {f.remediation}",""]
    lines += ["## Checks",""]+[f"- {c['name']}: {c['status']} ({c.get('detail','')})" for c in checks]
    (root/(run_id+".md")).write_text("\n".join(lines)+"\n")
    return root/(run_id+".md"), root/(run_id+".json")
