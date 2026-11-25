import importlib.util, json, sys
from pathlib import Path
path = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("probe_simple", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fn = getattr(module, "wait_for_proxy_when_tasks_remain", None)
# The pristine branch has an unconditional `break` when acquire() returns None.
action = "WAIT" if fn is not None and fn(130, stopped=False) else "EXIT"
print(json.dumps({"proxy": None, "pending": 130, "stopped": False,
                  "action": action}, sort_keys=True))
