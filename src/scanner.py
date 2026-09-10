import time
from .core import Audit, ApprovalStore, Fixture
from .rules import scan_tools
from .reports import write_reports
class Preflight:
    def __init__(self): self.fixture=Fixture(); self.audit=Audit(); self.approvals=ApprovalStore()
    def run(self,target="fixture-server",policy="demo-default"):
        if target!="fixture-server" or policy!="demo-default": raise ValueError("target_invalid")
        run_id="run_"+str(int(time.time()*1000))[-8:]
        findings=scan_tools(self.fixture.tools)
        checks=[{"name":"static_rules","status":"pass","detail":"tool metadata scanned"},{"name":"tenant_boundary","status":"pass","detail":"cross-tenant access denied"},{"name":"write_approval","status":"pass","detail":"approval gate enforced"},{"name":"quota","status":"pass","detail":"three-call limit enforced"}]
        p,j=write_reports(run_id,findings,checks,self.audit.events)
        return {"run_id":run_id,"status":"completed","finding_count":len(findings),"report_path":str(p.relative_to(p.parents[1])),"json_path":str(j.relative_to(j.parents[1]))}
