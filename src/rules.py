import re
from .core import Finding, redact

def scan_tools(tools):
    out=[]
    for t in tools:
        desc=t.get("description","")
        if t.get("risk_class")=="command" or re.search(r'\b(shell|bash|exec|command)\b', desc, re.I):
            out.append(Finding("MCP-001","high",t["name"],"Unsafe command capability",redact("unsafe command pattern in tool declaration"),"Remove shell access or isolate execution."))
        scopes=t.get("declared_scopes",[])
        if any(s in ("filesystem:*","network:*","network:egress") for s in scopes):
            out.append(Finding("MCP-002","medium",t["name"],"Excessive permission scope",redact("declared scope: "+", ".join(scopes)),"Reduce filesystem and network scope to the minimum required."))
        joined=json_text(t)
        if re.search(r'(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s,;]+', joined):
            out.append(Finding("MCP-003","high",t["name"],"Secret-like value exposed",redact("secret-like value found in tool metadata"),"Remove the value and rotate any real credential."))
        if any(x in joined.lower() for x in ("{input}","user input","from input")):
            out.append(Finding("MCP-004","medium",t["name"],"Untrusted input reaches sensitive operation",redact("input placeholder reaches tool operation"),"Validate and constrain input before invoking the tool."))
    return out

def json_text(value):
    import json
    return json.dumps(value,sort_keys=True)
