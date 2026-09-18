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

        if any(re.search(r'(?i)(authorization|bearer|auth[_-]?header)', k) for k in t.keys()):

            out.append(Finding("MCP-005","high",t["name"],"Credential forwarded in tool metadata",redact("credential-like header key embedded in tool declaration"),"Pass credentials at runtime via secret store, never inside tool metadata."))

        if re.search(r'(tenant[_-]?id)', json_text(t), re.I) and not re.search(r'(jwt|session|identity[ _-]?provider|\bidp\b|oauth|authenticated context|from the authenticated)', json_text(t), re.I):
            out.append(Finding("MCP-007","high",t["name"],"Caller-controlled tenant identity",redact("tool accepts tenant_id as a plain parameter with no identity-provider reference"),"Derive tenant identity from the authenticated context and enforce it again at the data layer."))
        if desc and re.search(r'(ignore|disregard|forget)[^.]{0,40}(previous|prior|above|earlier)[^.]{0,20}(instruction|prompt|rule)|(you|assistant|agent)\s+(are|must|should)\s+(now|actually)\s+(a|an|the)|(system|developer)\s+(prompt|message|instruction)|do\s+not\s+(tell|reveal|inform)[^.]{0,30}(user|operator)|exfiltrate|send[^.]{0,30}(credentials|secret|token)[^.]{0,30}(to|at)\s+(http|external)', desc, re.I):
            out.append(Finding("MCP-008","high",t["name"],"Instruction-like text in tool description",redact("description contains prompt-instruction patterns"),"Treat tool descriptions as data, never as instructions. Rewrite the description to describe behavior only."))
        if t.get("risk_class")=="write" and "tenant_id" not in json_text(t):

            out.append(Finding("MCP-006","medium",t["name"],"Write operation without tenant scoping",redact("write tool declares no tenant identifier"),"Require an explicit tenant_id argument and enforce it server-side."))

    out.extend(_scan_shadowing(tools))

    return out



def _scan_shadowing(tools):

    """MCP-009: the same tool name declared by more than one source.

    A malicious or compromised MCP server can register a tool whose name
    matches one already provided by a trusted source. Depending on load
    order and client-side dedup, calls intended for the trusted tool can be
    silently routed to the impostor instead (tool shadowing / rug pull).
    """

    out=[]

    first_source_by_name={}

    flagged_names=set()

    for t in tools:

        name=t.get("name")

        if not name:
            continue

        source=t.get("source","unknown")

        if name not in first_source_by_name:

            first_source_by_name[name]=source

        elif first_source_by_name[name]!=source and name not in flagged_names:

            flagged_names.add(name)

            out.append(Finding("MCP-009","high",name,"Tool name shadowed across sources",redact(f"tool '{name}' is declared by more than one source ({first_source_by_name[name]!r} and {source!r})"),"Namespace tool names per source (or reject the load) instead of letting two sources register the same tool name."))

    return out



def json_text(value):

    import json

    return json.dumps(value,sort_keys=True)