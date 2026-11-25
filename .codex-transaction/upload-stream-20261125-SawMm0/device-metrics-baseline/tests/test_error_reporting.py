import json
import tempfile
import time
import unittest
from pathlib import Path

from fastcheck.status import result_bucket
from run_mp import merge
from simple import local_exception_result


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


class ErrorReportingTest(unittest.TestCase):
    def test_transport_exception(self):
        test_transport_exception_becomes_retryable_timeout()

    def test_programming_exception(self):
        test_programming_exception_remains_visible_undetermined()

    def test_merge_retry_counters(self):
        test_multiprocess_merge_keeps_retry_counters()


if __name__ == "__main__":
    unittest.main()
