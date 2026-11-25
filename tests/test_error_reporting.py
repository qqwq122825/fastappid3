import json
import tempfile
import time
import unittest
from pathlib import Path

from fastcheck.devices import count_registered_devices
from fastcheck.status import result_bucket
from run_mp import merge
from simple import (finalize_retry_exhausted, local_exception_result, retry_kind,
                    wait_for_proxy_when_tasks_remain)


def test_transport_exception_becomes_retryable_timeout():
    result = local_exception_result(TimeoutError("secret proxy URL"))
    assert result["status"] == "timeout"
    assert result["http"] == 0
    assert result_bucket(result) == "timeout"
    assert "TimeoutError" in result["detail"]
    assert "secret proxy URL" not in result["detail"]


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


class ErrorReportingTest(unittest.TestCase):
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

    def test_registered_device_metrics(self):
        test_registered_devices_are_persisted_total_not_live_workers()


if __name__ == "__main__":
    unittest.main()
