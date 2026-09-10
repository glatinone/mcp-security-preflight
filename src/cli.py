import argparse,json,shutil
from .scanner import Preflight
from .core import TOKEN

def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd"); sub.add_parser("preflight"); call=sub.add_parser("call"); call.add_argument("tool"); call.add_argument("--tenant",default="tenant-a"); call.add_argument("--request",default="req_001"); call.add_argument("--document",default="doc-a-1"); appr=sub.add_parser("approve"); appr.add_argument("tool",default="documents.archive",nargs="?"); appr.add_argument("--tenant",default="tenant-a"); appr.add_argument("--request",default="req_001"); sub.add_parser("reset"); a=p.parse_args()
 if a.cmd=="preflight": print(json.dumps(Preflight().run(),indent=2)); return 0
 if a.cmd=="reset":
  for f in (Preflight().fixture.__class__.__module__,): pass
  root=__import__('pathlib').Path(__file__).resolve().parents[1]/'reports'; [x.unlink() for x in root.glob('run_*')]; print('reset complete'); return 0
 if a.cmd in ('call','approve'):
  lab=Preflight(); req=a.request
  if a.cmd=='approve': print(json.dumps(lab.approvals.create(req,a.tenant,a.tool),indent=2)); return 0
  args={'tenant_id':a.tenant};
  if a.tool=='documents.read': args['document_id']=a.document
  status,result=lab.fixture.call(a.tenant,a.tool,args,req,lab,lab.approvals,lab.audit); print(json.dumps({'status':status,'result':result},indent=2)); return 0
 return 2
if __name__=='__main__': raise SystemExit(main())
