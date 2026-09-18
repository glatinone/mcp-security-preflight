import sys, traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from src.core import Fixture,Audit,ApprovalStore,redact
from src.rules import scan_tools
from src.scanner import Preflight
passed=failed=0
def test(name,fn):
 global passed,failed
 try: fn(); passed+=1; print('PASS',name)
 except Exception as e: failed+=1; print('FAIL',name,e); traceback.print_exc()
def setup(): return Fixture(),Audit(),ApprovalStore()
test('unsafe command',lambda: (_ for _ in ()).throw(AssertionError()) if not any(f.id=='MCP-001' and f.severity=='high' for f in scan_tools(Fixture().tools)) else None)
test('secret redaction',lambda: (_ for _ in ()).throw(AssertionError()) if 'sk-demo-secret' in redact('DEMO_API_KEY=sk-demo-secret') else None)
test('excessive scope',lambda: (_ for _ in ()).throw(AssertionError()) if not any(f.id=='MCP-002' for f in scan_tools(Fixture().tools)) else None)
test('tainted input',lambda: (_ for _ in ()).throw(AssertionError()) if not any(f.id=='MCP-004' for f in scan_tools(Fixture().tools)) else None)
def tenant():
 f,a,o=setup(); s,r=f.call('tenant-a','documents.read',{'tenant_id':'tenant-b','document_id':'doc-b-1'},'req-tenant',None,o,a); assert s==403 and r['error']=='tenant_boundary_denied'
test('tenant isolation',tenant)
def write_no_approval():
 f,a,o=setup(); s,r=f.call('tenant-a','documents.archive',{'tenant_id':'tenant-a','document_id':'doc-a-1'},'req-write',None,o,a); assert s==403 and r['error']=='approval_required'
test('write requires approval',write_no_approval)
def write_approval():
 f,a,o=setup(); o.create('req-write','tenant-a','documents.archive'); s,r=f.call('tenant-a','documents.archive',{'tenant_id':'tenant-a','document_id':'doc-a-1'},'req-write',None,o,a); assert s==200
test('scoped approval allows write',write_approval)
def quota():
 f,a,o=setup();
 for _ in range(3): assert f.call('tenant-a','documents.read',{'tenant_id':'tenant-a','document_id':'doc-a-1'},'req-q',None,o,a)[0]==200
 assert f.call('tenant-a','documents.read',{'tenant_id':'tenant-a','document_id':'doc-a-1'},'req-q',None,o,a)[0]==429
test('quota',quota)
def invalid():
 try: Preflight().run('remote-target')
 except ValueError as e: assert str(e)=='target_invalid'
 else: raise AssertionError()
test('invalid target',invalid)
def e2e():
 result=Preflight().run(); assert result['status']=='completed' and result['finding_count']>=4
 p=ROOT/'reports'/Path(result['report_path']).name; assert p.exists() and 'MCP-001' in p.read_text()
test('end to end report',e2e)
test('credential forwarding flagged',lambda: (_ for _ in ()).throw(AssertionError()) if not any(f.id=='MCP-005' for f in scan_tools(Fixture().tools)) else None)
test('write without tenant scoping flagged',lambda: (_ for _ in ()).throw(AssertionError()) if not any(f.id=='MCP-006' for f in scan_tools(Fixture().tools)) else None)
def mcp007():
 ids={(f.id,f.tool) for f in scan_tools(Fixture().tools)}
 assert ("MCP-007","tenants.transfer") in ids, "must flag caller-supplied tenant_id"
 assert ("MCP-007","tenants.lookup") not in ids, "must not flag IdP-resolved tenant"
test('caller-controlled tenant identity flagged',mcp007)
def mcp008():
 ids={(f.id,f.tool) for f in scan_tools(Fixture().tools)}
 assert ("MCP-008","sync.contacts") in ids, "must flag instruction-like description"
 assert ("MCP-008","calendar.block") not in ids, "must not flag clean description"
test('instruction-like description flagged',mcp008)
def mcp009():
 findings=[f for f in scan_tools(Fixture().tools) if f.id=='MCP-009']
 assert len(findings)==1, f"expected exactly one shadowing finding, got {len(findings)}"
 assert findings[0].tool=='notes.search'
 assert 'trusted_connector' in findings[0].evidence and 'unverified_plugin_7f3a' in findings[0].evidence
test('tool name shadowed across sources flagged once',mcp009)
def mcp009_clean():
 ids={(f.id,f.tool) for f in scan_tools(Fixture().tools)}
 assert ("MCP-009","documents.read") not in ids, "single-source tools must not be flagged as shadowed"
test('single-source tools not flagged as shadowed',mcp009_clean)
print(f'SUMMARY passed={passed} failed={failed} total={passed+failed}')
raise SystemExit(1 if failed else 0)
