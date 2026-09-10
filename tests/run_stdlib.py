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
print(f'SUMMARY passed={passed} failed={failed} total={passed+failed}')
raise SystemExit(1 if failed else 0)
