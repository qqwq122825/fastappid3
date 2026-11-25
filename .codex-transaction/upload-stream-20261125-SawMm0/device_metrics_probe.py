import importlib.util, json, sys, tempfile, time
from pathlib import Path
module_path = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("probe_run_mp", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    jobs = []
    fixture = {"finished": False, "done": 1, "device_ready": 2,
               "device_registered": 2, "device_in_use": 1,
               "device_registering": 0}
    for index in range(2):
        live = root / f"live-{index}.json"
        live.write_text(json.dumps(fixture), encoding="utf-8")
        jobs.append({"live": str(live), "threads": 1, "limit": 1})
    result = module.merge(jobs, time.monotonic() - 1, expected_total=2)
    print(json.dumps({"device_ready": result.get("device_ready"),
                      "device_registered": result.get("device_registered"),
                      "device_in_use": result.get("device_in_use")},
                     ensure_ascii=False, sort_keys=True))
