import hashlib, json, re, secrets, time
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
TOKEN = "demo-operator-token"

@dataclass
class Finding:
    id: str; severity: str; tool: str; title: str; evidence: str; remediation: str; status: str = "open"
    def as_dict(self): return asdict(self)

class Audit:
    def __init__(self): self.events=[]
    def record(self, request_id, tenant_id, tool_name, decision, reason_code, raw_input=""):
        self.events.append({"request_id":request_id,"tenant_id":tenant_id,"tool_name":tool_name,"decision":decision,"reason_code":reason_code,"input_hash":hashlib.sha256(raw_input.encode()).hexdigest()[:16],"created_at":int(time.time())})

class ApprovalStore:
    def __init__(self): self.items={}
    def create(self, request_id, tenant_id, tool_name, decision="approved"):
        approval={"approval_id":"apr_"+secrets.token_hex(4),"request_id":request_id,"tenant_id":tenant_id,"tool_name":tool_name,"decision":decision,"expires_at":time.time()+300,"actor":"demo-operator"}
        self.items[(request_id,tenant_id,tool_name)] = approval; return approval
    def valid(self, request_id, tenant_id, tool_name):
        a=self.items.get((request_id,tenant_id,tool_name)); return bool(a and a["decision"]=="approved" and a["expires_at"]>time.time())

class Fixture:
    def __init__(self):
        self.tools=json.loads((ROOT/"fixtures/tools.json").read_text()); self.tenants=json.loads((ROOT/"fixtures/tenants.json").read_text()); self.quota={}
    def tool(self,name): return next((t for t in self.tools if t["name"]==name),None)
    def call(self, tenant, tool_name, args, request_id, policy, approval, audit):
        t=self.tool(tool_name); raw=json.dumps(args,sort_keys=True)
        if not t: audit.record(request_id,tenant,tool_name,"denied","tool_unknown",raw); return 422,{"error":"unknown_tool"}
        if self.quota.get(request_id,0)>=3: audit.record(request_id,tenant,tool_name,"denied","quota_exceeded",raw); return 429,{"error":"quota_exceeded"}
        self.quota[request_id]=self.quota.get(request_id,0)+1
        requested=args.get("tenant_id",tenant)
        if requested != tenant: audit.record(request_id,tenant,tool_name,"denied","tenant_boundary_denied",raw); return 403,{"error":"tenant_boundary_denied"}
        if t["risk_class"]=="write" and not approval.valid(request_id,tenant,tool_name): audit.record(request_id,tenant,tool_name,"approval-required","approval_required",raw); return 403,{"error":"approval_required"}
        if tool_name=="documents.read":
            doc=args.get("document_id","")
            if doc not in self.tenants[tenant]["documents"]: audit.record(request_id,tenant,tool_name,"denied","document_boundary_denied",raw); return 403,{"error":"document_boundary_denied"}
            result={"document_id":doc,"tenant_id":tenant,"content":"synthetic document"}
        elif tool_name=="documents.archive": result={"archived":args.get("document_id"),"tenant_id":tenant}
        else: result={"ok":True,"tool":tool_name}
        audit.record(request_id,tenant,tool_name,"allowed","policy_allow",raw); return 200,result

def redact(text):
    return re.sub(r'(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s,;]+', lambda m: m.group(1)+"=[REDACTED]", text)
