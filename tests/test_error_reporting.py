import json
import tempfile
import time
import unittest
from pathlib import Path

from fastcheck.devices import DevicePool as PersistentDevicePool, count_registered_devices
from fastcheck.protocols import gsa_status
from fastcheck.status import result_bucket
from simple import (finalize_retry_exhausted, local_exception_result,
                    local_exception_used_proxy, retry_kind,
                    wait_for_proxy_when_tasks_remain)
from run_mp import merge


def test_transport_exception_becomes_retryable_timeout():
    result = local_exception_result(TimeoutError("secret proxy URL"))
    assert result["status"] == "timeout"
    assert result["http"] == 0
    assert result_bucket(result) == "timeout"
    assert "TimeoutError" in result["detail"]
    assert "secret proxy URL" not in result["detail"]


def test_requests_timeout_uses_independent_connect_and_read_limits():
    assert gsa_status._requests_timeout(3.25) == (3.25, 3.25)
    assert gsa_status._requests_timeout(25) == (
        gsa_status._CONNECT_TIMEOUT_CAP, 25.0)




def test_direct_local_exception_does_not_blame_task_proxy():
    assert local_exception_used_proxy(False, False) is False
    assert local_exception_used_proxy(False, True) is True
    assert local_exception_used_proxy(True, False) is True


def test_programming_exception_remains_visible_undetermined():
    result = local_exception_result(KeyError("secret account"))
    assert result["status"] == "error"
    assert "http" not in result
    assert result_bucket(result) == "undetermined"
    assert "KeyError" in result["detail"]
    assert "secret account" not in result["detail"]


def test_account_information_incorrect_retries_then_becomes_wrong_password():
    result = {
        "status": "error",
        "http": 200,
        "apple_message": "Your account information was entered incorrectly.",
    }
    bucket = result_bucket(result)
    assert bucket == "timeout"
    assert retry_kind(result, bucket)[0] is not None

    finalize_retry_exhausted(result)
    assert result["retry_exhausted"] == "account_information_incorrect"
    assert result_bucket(result) == "wrong_password"
    assert retry_kind(result, result_bucket(result))[0] is None


def test_proxy_starvation_keeps_pending_worker_alive():
    assert wait_for_proxy_when_tasks_remain(130, stopped=False) is True
    assert wait_for_proxy_when_tasks_remain(0, stopped=False) is False
    assert wait_for_proxy_when_tasks_remain(130, stopped=True) is False


def test_multiprocess_merge_keeps_retry_counters(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_multiprocess_merge_keeps_retry_counters(Path(directory))
    jobs = []
    for index, payload in enumerate((
        {"done": 2, "retried": 1, "by_retry": {"http=0": 1}, "budget_hit": 0},
        {"done": 3, "retried": 2,
         "by_retry": {"http=0": 1, "local_http=0": 1}, "budget_hit": 1},
    )):
        path = tmp_path / f"live-{index}.json"
        path.write_text(json.dumps({"finished": False, **payload}), encoding="utf-8")
        jobs.append({"live": str(path), "threads": 100, "limit": payload["done"]})
    result = merge(jobs, time.monotonic() - 1, expected_total=5)
    assert result["retried"] == 3
    assert result["by_retry"] == {"http=0": 2, "local_http=0": 1}
    assert result["budget_hit"] == 1


def test_multiprocess_merge_uses_global_latency_distribution(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_multiprocess_merge_uses_global_latency_distribution(Path(directory))
    payloads = (
        {"done": 9, "p50": 10, "p90": 10, "latency_hist": {"10": 9}},
        {"done": 1, "p50": 1010, "p90": 1010, "latency_hist": {"1010": 1}},
    )
    jobs = []
    for index, payload in enumerate(payloads):
        path = tmp_path / f"live-{index}.json"
        path.write_text(json.dumps({"finished": False, **payload}), encoding="utf-8")
        jobs.append({"live": str(path), "threads": 1, "limit": payload["done"]})
    result = merge(jobs, time.monotonic() - 1, expected_total=10)
    assert result["p50"] == 10
    assert result["latency_hist"] == {10: 9, 1010: 1}
    assert "总体分位数" in result["p50_note"]


def test_registered_devices_are_persisted_total_not_live_workers(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_registered_devices_are_persisted_total_not_live_workers(Path(directory))
    origin = "https://new.ani.sidestore.io"
    import base64
    import hashlib
    key = hashlib.sha256(origin.encode()).hexdigest()[:24]
    for slot, registered in ((1, True), (2, True), (3, False)):
        directory = tmp_path / key / "devices" / str(slot)
        directory.mkdir(parents=True)
        state = {
            "identifier": base64.b64encode(bytes([slot]) * 16).decode(),
            "adi_pb": base64.b64encode(b"registered").decode() if registered else None,
        }
        (directory / f"{key}.json").write_text(
            json.dumps({"schema": 2, "origin": origin, "state": state}),
            encoding="utf-8")
    assert count_registered_devices(tmp_path, origin) == 2

    jobs = []
    for index in range(2):
        path = tmp_path / f"live-{index}.json"
        path.write_text(json.dumps({
            "finished": False, "done": 1, "device_registered": 2,
            "device_in_use": 1, "device_registering": 0,
        }), encoding="utf-8")
        jobs.append({"live": str(path), "threads": 1, "limit": 1})
    result = merge(jobs, time.monotonic() - 1, expected_total=2)
    assert result["device_registered"] == 2  # 全局总数不随进程数翻倍
    assert result["device_in_use"] == 2      # 使用中则是各进程之和


def test_memory_device_store_loads_once_and_writes_through(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_memory_device_store_loads_once_and_writes_through(Path(directory))
    import base64
    origin = 'https://new.ani.sidestore.io'
    pool = PersistentDevicePool(tmp_path, origin, max_devices=1, in_memory=True)
    store = pool.store(1)
    with store.lock(1):
        state = store.load()
        state['adi_pb'] = base64.b64encode(b'registered').decode()
        store.save(state)
    persisted = store.path
    assert persisted.exists()

    # Removing the persisted copy proves the registered wrapper reads the
    # shared process memory rather than reopening the slot file.
    persisted.unlink()
    registered = pool.store(1, registered=True)
    with registered.lock(1):
        loaded = registered.load()
    assert loaded == state
    assert not list(registered.path.parent.glob('*.lock'))


class ErrorReportingTest(unittest.TestCase):
    def test_requests_total_timeout(self):
        test_requests_timeout_uses_independent_connect_and_read_limits()

    def test_local_exception_proxy_attribution(self):
        test_direct_local_exception_does_not_blame_task_proxy()

    def test_account_information_retry_exhaustion(self):
        test_account_information_incorrect_retries_then_becomes_wrong_password()

    def test_transport_exception(self):
        test_transport_exception_becomes_retryable_timeout()

    def test_programming_exception(self):
        test_programming_exception_remains_visible_undetermined()

    def test_proxy_starvation_keeps_worker(self):
        test_proxy_starvation_keeps_pending_worker_alive()

    def test_merge_retry_counters(self):
        test_multiprocess_merge_keeps_retry_counters()

    def test_global_latency_distribution(self):
        test_multiprocess_merge_uses_global_latency_distribution()

    def test_registered_device_metrics(self):
        test_registered_devices_are_persisted_total_not_live_workers()

    def test_memory_device_store(self):
        test_memory_device_store_loads_once_and_writes_through()


if __name__ == "__main__":
    unittest.main()
