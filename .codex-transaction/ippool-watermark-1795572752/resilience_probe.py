import ast,importlib.util,json,pathlib,sys,time
ip_path=pathlib.Path(sys.argv[1]); simple_path=pathlib.Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('probe_pool',ip_path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
def fake_fetcher(pool, requests):
 serial=[0]
 def fetch(num):
  requests.append(num); start=serial[0]; serial[0]+=num
  return [f'socks5h://137.184.119.209:{10000+i}' for i in range(start,start+num)]
 pool._fetch=fetch
# Same warm input on baseline and candidate.
warm_requests=[]; warm=mod.IpPool('http://fixture/{num}',threads=800,ttl=50,batch=1000,refill_interval=.5); fake_fetcher(warm,warm_requests); warmed=warm.warm(extra=1)
# Same five endpoints behind one gateway, configured limit=3 where supported.
gw=mod.IpPool('http://fixture/{num}',threads=5,ttl=50,batch=10,refill_interval=.5)
if hasattr(gw,'gateway_limit'): gw.gateway_limit=3
gw_requests=[]; fake_fetcher(gw,gw_requests); gw.warm(extra=1)
first=[bool(gw.acquire_nowait(i)[0]) for i in range(5)]
# Release one reserved endpoint and prove a waiting endpoint can advance.
if first[0]:
 proxy='socks5h://137.184.119.209:10000'; gw.release(0,proxy,time.monotonic()+40,healthy=True)
after_release=bool(gw.acquire_nowait(3)[0])
# Near-expiry lease input: five seconds remain.
ttl=mod.IpPool('http://fixture/{num}',threads=1,ttl=10,batch=1,refill_interval=.5)
if hasattr(ttl,'lease_margin'): ttl.lease_margin=8.0
ttl._local[0].append(('socks5h://137.184.119.209:19001',time.monotonic()+5))
near_expiry_returned=bool(ttl.acquire_nowait(0)[0])
# Failed endpoint is offered again by API.
q=mod.IpPool('http://fixture/{num}',threads=1,ttl=50,batch=1,refill_interval=.5)
q._local[0].append(('socks5h://137.184.119.209:19999',time.monotonic()+40))
proxy,exp=q.acquire_nowait(0); q.release(0,proxy,exp,healthy=False)
accepted_again=len(q._accept(['socks5h://137.184.119.209:19999']))
# Extract simple_async policy helpers without importing its runtime dependencies.
text=simple_path.read_text(encoding='utf-8'); tree=ast.parse(text); funcs={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
registration=224
if '_needs_device_registration' in funcs:
 ns={}; node=funcs['_needs_device_registration']; exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(simple_path),'exec'),ns); registration=sum(ns['_needs_device_registration'](True,False) for _ in range(224))
if '_should_retire_proxy' in funcs:
 def retry_kind(result,final): return (None,'') if final=='wrong_password' else ('http0','http=0')
 ns={'retry_kind':retry_kind}; node=funcs['_should_retire_proxy']; exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(simple_path),'exec'),ns); retire_timeout=ns['_should_retire_proxy']({'http':0},'timeout'); retire_verdict=ns['_should_retire_proxy']({'http':200},'wrong_password')
else:
 retire_timeout=False; retire_verdict=False
print(json.dumps({'warm_input':{'threads':800,'extra':1},'warmed':warmed,'warm_requests':warm_requests,'gateway_input':{'endpoints':5,'same_host':True,'limit':3},'gateway_first_acquired':sum(first),'gateway_waiter_after_release':after_release,'near_expiry_5s_returned':near_expiry_returned,'failed_endpoint_accepted_again':accepted_again,'queued_ready_display_registering':registration,'final_timeout_retires_proxy':retire_timeout,'final_verdict_retires_proxy':retire_verdict},sort_keys=True))
