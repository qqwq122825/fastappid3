import importlib.util, json, pathlib, sys
path = pathlib.Path(sys.argv[1]); spec = importlib.util.spec_from_file_location('probe_ippool', path)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
pool = mod.IpPool('http://fixture/{num}', threads=800, ttl=50, batch=1000, refill_interval=.5)
requests=[]; serial=[0]
def fetch(num):
    requests.append(num); start=serial[0]; serial[0]+=num
    return [f'socks5h://10.0.{i//250}.{i%250}:1080' for i in range(start, start+num)]
pool._fetch=fetch
warmed=pool.warm(extra=1); success=0
for n in range(1400):
    proxy,_=pool.acquire_nowait(n % 800); success += bool(proxy)
before=pool.snapshot()
class OneCycle:
    def __init__(self): self.n=0
    def is_set(self): self.n+=1; return self.n>1
    def wait(self, timeout): return True
class Wake:
    def wait(self, timeout): return True
    def clear(self): pass
    def set(self): pass
pool._stop=OneCycle()
if hasattr(pool, '_refill_wakeup'): pool._refill_wakeup=Wake()
pool._supply_loop(); after=pool.snapshot()
print(json.dumps({'threads':800,'warm_extra':1,'acquire_attempts':1400,'warmed':warmed,
 'acquire_success':success,'available_before':before['local_live']+before['shared'],
 'tracked_before':before['tracked'],'fetch_requests':requests,
 'available_after':after['local_live']+after['shared'],
 'refill_calls':after.get('refill_calls','legacy')},sort_keys=True))
