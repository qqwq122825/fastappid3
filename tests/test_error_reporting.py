import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from fastcheck.devices import DevicePool as PersistentDevicePool, count_registered_devices
from fastcheck.protocols import gsa_status
from fastcheck.status import result_bucket
from simple import (ProcessDeviceHeaderCache, classify_web, classify_web_method,
                    final_progress_fields, refine_repair_web_status,
                    finalize_retry_exhausted, local_exception_result,
                    local_exception_used_proxy, retry_kind,
                    wait_for_proxy_when_tasks_remain, wait_for_ready_device,
                    web_retryable)


class RepairWebClassificationTests(unittest.TestCase):
    def test_complete_trace_http_prevents_false_web_timeout(self):
        web = {'status': 'need_2fa', 'detail': 'authType=hsa2'}
        trace = {'complete': {'auth_type': 'hsa2', 'http': 409}}
        self.assertEqual('need_2fa', classify_web(web, trace))

    def test_only_transient_web_failures_rotate_proxy(self):
        self.assertTrue(web_retryable('web_timeout'))
        self.assertTrue(web_retryable('web_unavailable'))
        self.assertFalse(web_retryable('need_2fa'))
        self.assertFalse(web_retryable('valid'))

    def test_sa_and_non_sa_web_completion_count_as_password_correct(self):
        for auth_type, status in (('sa', 'valid'), ('non-sa', 'needs_setup')):
            with self.subTest(auth_type=auth_type, status=status):
                trace = {'complete': {'auth_type': auth_type, 'http': 200}}
                web = {'status': status}
                self.assertEqual('security_repair', classify_web_method(web, trace))
                self.assertEqual('valid', refine_repair_web_status('need_2fa', web, trace))

    def test_non_password_web_results_do_not_override_gsa_repair(self):
        cases = (
            ({'status': 'need_2fa'}, {'complete': {'auth_type': 'hsa2'}}),
            ({'status': 'error'}, {'complete': {'auth_type': 'sa'}}),
            ({'status': 'error'}, {'complete': {'auth_type': 'dnu'}}),
        )
        for web, trace in cases:
            with self.subTest(web=web, trace=trace):
                self.assertEqual(
                    'need_2fa', refine_repair_web_status('need_2fa', web, trace))


class FinalProgressTests(unittest.TestCase):
    def test_uses_all_finished_rows_not_stale_periodic_snapshot(self):
        rows = [{'status': 'locked', 'seq': i} for i in range(1, 4)]
        final = {'by_status': {'locked': 1}, 'recent': rows[:1]}
        final.update(final_progress_fields(
            {'by_status': {'locked': 3}, 'recent': rows}))
        self.assertEqual({'locked': 3}, final['by_status'])
        self.assertEqual(rows, final['recent'])
from run_mp import assign_device_slots, merge


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


def test_multiprocess_merge_keeps_each_process_ip_pool(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_multiprocess_merge_keeps_each_process_ip_pool(Path(directory))
    jobs = []
    pools = (
        {'available': 310, 'low_water': 250, 'high_water': 500,
         'supplier_alive': True, 'api_calls': 3, 'fetched': 600},
        {'available': 280, 'low_water': 250, 'high_water': 500,
         'supplier_alive': False, 'api_calls': 4, 'fetched': 550},
    )
    for index, pool in enumerate(pools):
        live = tmp_path / f'live-p{index}.json'
        live.write_text(json.dumps({
            'done': 1, 'finished': False, 'ip_pool': pool,
        }), encoding='utf-8')
        jobs.append({'index': index, 'live': str(live), 'threads': 500, 'limit': 1})
    result = merge(jobs, time.monotonic() - 1, expected_total=2)
    merged = result['ip_pool']
    assert merged['available'] == 590
    assert merged['low_water'] == 500
    assert merged['high_water'] == 1000
    assert merged['supplier_alive'] is False
    assert [item['available'] for item in merged['by_process']] == [310, 280]
    assert [item['process'] for item in merged['by_process']] == [1, 2]


def test_multiprocess_merge_reports_child_startup_progress(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_multiprocess_merge_reports_child_startup_progress(Path(directory))
    jobs = []
    payloads = (
        {'phase': 'device_register', 'message': '正在准备设备',
         'process_ready': 1, 'process_total': 2,
         'device_loaded': 400, 'device_ready': 420, 'device_target': 500,
         'device_registering': 10, 'proxy_fetched': 500,
         'proxy_target': 500, 'proxy_available': 480, 'proxy_api_calls': 2,
         'workers_started': 500, 'public_header_waiting': 128,
         'public_header_ready': 20, 'public_header_limit': 128},
        {'phase': 'proxy_fetch', 'message': '正在拉取代理 IP',
         'process_ready': 1, 'process_total': 2,
         'device_loaded': 350, 'device_ready': 350, 'device_target': 500,
         'proxy_fetched': 300, 'proxy_target': 500,
         'proxy_available': 300, 'proxy_api_calls': 1,
         'workers_started': 500, 'public_header_waiting': 128,
         'public_header_ready': 10, 'public_header_limit': 128},
    )
    for index, startup in enumerate(payloads):
        path = tmp_path / f'live-startup-{index}.json'
        path.write_text(json.dumps({
            'done': 0, 'finished': False, 'startup': startup,
        }), encoding='utf-8')
        jobs.append({'index': index, 'live': str(path),
                     'threads': 500, 'limit': 1})
    result = merge(jobs, time.monotonic() - 1, expected_total=2)
    startup = result['startup']
    assert startup['phase'] == 'proxy_fetch'
    assert startup['process_ready'] == 2
    assert startup['process_total'] == 2
    assert startup['device_loaded'] == 750
    assert startup['device_ready'] == 770
    assert startup['proxy_fetched'] == 800
    assert startup['proxy_api_calls'] == 3
    assert startup['workers_started'] == 1000
    assert startup['public_header_waiting'] == 256
    assert startup['public_header_ready'] == 30
    assert startup['public_header_limit'] == 256


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


def test_worker_slot_pool_uses_least_used_idle_then_allocates_when_busy(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_worker_slot_pool_uses_least_used_idle_then_allocates_when_busy(Path(directory))
    import base64
    import hashlib
    origin = 'https://new.ani.sidestore.io'
    key = hashlib.sha256(origin.encode()).hexdigest()[:24]
    for slot in (1, 2):
        directory = tmp_path / key / 'devices' / f'{slot:02d}'
        directory.mkdir(parents=True)
        state = {
            'identifier': base64.b64encode(bytes([slot]) * 16).decode(),
            'adi_pb': base64.b64encode(b'registered').decode(),
        }
        (directory / f'{key}.json').write_text(
            json.dumps({'schema': 2, 'origin': origin, 'state': state}),
            encoding='utf-8')
    pool = PersistentDevicePool(tmp_path, origin, max_devices=3, in_memory=True)
    assert pool.configure_worker_slots([1, 2], new_slot_start=3) == 2
    first = pool.acquire_worker_slot()
    second = pool.acquire_worker_slot()
    third = pool.acquire_worker_slot()
    assert first.ready and second.ready
    assert {first.slot, second.slot} == {1, 2}
    assert not third.ready and third.slot == 3
    first.close()
    second.close()
    fourth = pool.acquire_worker_slot()
    fourth_slot = fourth.slot
    pool.consume_worker_slot(fourth_slot)
    fourth.close()
    fifth = pool.acquire_worker_slot()
    try:
        # The fourth claim makes that device's use count 2, so the fifth must
        # choose the other idle device whose count is still 1.
        assert fourth.ready and fifth.ready
        assert fifth.slot != fourth_slot
    finally:
        fifth.close()
        third.close()


def test_worker_device_is_destroyed_after_completed_account_limit(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_worker_device_is_destroyed_after_completed_account_limit(Path(directory))
    import base64
    import hashlib
    origin = 'https://new.ani.sidestore.io'
    key = hashlib.sha256(origin.encode()).hexdigest()[:24]
    directory = tmp_path / key / 'devices' / '01'
    directory.mkdir(parents=True)
    state = {
        'identifier': base64.b64encode(b'1' * 16).decode(),
        'adi_pb': base64.b64encode(b'registered').decode(),
    }
    (directory / f'{key}.json').write_text(
        json.dumps({'schema': 2, 'origin': origin, 'state': state}),
        encoding='utf-8')
    pool = PersistentDevicePool(
        tmp_path, origin, max_devices=2, in_memory=True, worker_use_limit=2)
    assert pool.configure_worker_slots([1], new_slot_start=2) == 1
    lease = pool.acquire_ready_worker_slot()
    first_meta = pool.worker_slot_result_metadata(lease.slot)
    assert first_meta == {'device_id': 'MTExMTEx', 'device_uses': 1}
    assert pool.consume_worker_slot(lease.slot) is False
    assert directory.exists()
    final_meta = pool.worker_slot_result_metadata(lease.slot)
    assert final_meta == {'device_id': 'MTExMTEx', 'device_uses': 2}
    assert pool.consume_worker_slot(lease.slot) is True
    assert not directory.exists()
    lease.close()
    assert pool.acquire_ready_worker_slot() is None
    replacement = pool.reserve_new_worker_slot()
    try:
        assert replacement.slot == 2 and not replacement.ready
        assert pool.worker_slots_retired == 1
    finally:
        replacement.close()


def test_multiprocess_device_assignment_is_even_and_disjoint():
    jobs = [{'index': i} for i in range(2)]
    assign_device_slots(jobs, list(range(1, 10)))
    assert jobs[0]['device_slots'] == [1, 3, 5, 7, 9]
    assert jobs[1]['device_slots'] == [2, 4, 6, 8]
    assert set(jobs[0]['device_slots']).isdisjoint(jobs[1]['device_slots'])
    assert (jobs[0]['new_slot_start'], jobs[0]['new_slot_step']) == (10, 2)
    assert (jobs[1]['new_slot_start'], jobs[1]['new_slot_step']) == (11, 2)
    sparse = [{'index': i} for i in range(3)]
    assign_device_slots(sparse, [5])
    assert [job['device_slots'] for job in sparse] == [[5], [], []]
    assert [(job['new_slot_start'], job['new_slot_step']) for job in sparse] == [
        (6, 3), (7, 3), (8, 3)]


def test_public_header_cache_is_bound_to_device_usage_and_ttl():
    now = [100.0]
    cache = ProcessDeviceHeaderCache(clock=lambda: now[0])
    cache.bind_used(7, {'X-Test': 'header'}, ttl=50, reuse=3)
    assert cache.take(7, 3) == {'X-Test': 'header'}  # use 2
    assert cache.take(7, 3) == {'X-Test': 'header'}  # use 3
    assert cache.take(7, 3) is None                  # exhausted
    cache.bind_used(7, {'X-Test': 'new'}, ttl=10, reuse=3)
    now[0] = 111.0
    assert cache.take(7, 3) is None                  # expired


def test_device_registration_is_a_producer_consumer_stage():
    import inspect
    import simple
    source = inspect.getsource(simple.main)
    producer = source[source.index('    def device_registrar'):source.index('    def worker(tid):')]
    worker = source[source.index('    def worker(tid):'):source.index("    results['started'] = started")]
    header = source.index('identity = device_headers.take')
    claim = source.index('task = retry_tasks.pop() if retry_tasks else take_task()')
    assert header < claim
    assert 'record_setup_timeout' not in source
    assert 'reserve_new_worker_slot()' in producer
    assert 'registered=False' in producer
    assert 'mark_worker_slot_ready(slot)' in producer
    assert 'wait_for_ready_device(' in worker
    assert 'reserve_new_worker_slot()' not in worker
    assert 'registered=False' not in worker


def test_business_worker_waits_until_producer_publishes_ready_device(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_business_worker_waits_until_producer_publishes_ready_device(
                Path(directory))
    origin = 'https://new.ani.sidestore.io'
    pool = PersistentDevicePool(tmp_path, origin, max_devices=1, in_memory=True)
    pool.configure_worker_slots([], new_slot_start=1)
    pending = pool.reserve_new_worker_slot()
    slot = pending.slot
    pending.close()
    condition = threading.Condition()
    stop = threading.Event()
    leases = []
    consumer = threading.Thread(target=lambda: leases.append(
        wait_for_ready_device(pool, condition, stop, lambda: 1, timeout=0.02)))
    consumer.start()
    time.sleep(0.05)
    assert leases == []
    pool.mark_worker_slot_ready(slot)
    with condition:
        condition.notify_all()
    consumer.join(1)
    assert len(leases) == 1 and leases[0] is not None
    assert leases[0].ready and leases[0].slot == slot
    leases[0].close()


def test_unregistered_worker_slot_is_not_leasable(tmp_path=None):
    if tmp_path is None:
        with tempfile.TemporaryDirectory() as directory:
            return test_unregistered_worker_slot_is_not_leasable(Path(directory))
    origin = 'https://new.ani.sidestore.io'
    pool = PersistentDevicePool(tmp_path, origin, max_devices=1, in_memory=True)
    assert pool.configure_worker_slots([], new_slot_start=1) == 0
    pending = pool.reserve_new_worker_slot()
    slot = pending.slot
    pending.close()
    assert pool.acquire_ready_worker_slot() is None
    pool.mark_worker_slot_ready(slot)
    ready = pool.acquire_ready_worker_slot()
    try:
        assert ready is not None and ready.ready and ready.slot == slot
    finally:
        ready.close()


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

    def test_multiprocess_ip_pool_details(self):
        test_multiprocess_merge_keeps_each_process_ip_pool()

    def test_global_latency_distribution(self):
        test_multiprocess_merge_uses_global_latency_distribution()

    def test_registered_device_metrics(self):
        test_registered_devices_are_persisted_total_not_live_workers()

    def test_memory_device_store(self):
        test_memory_device_store_loads_once_and_writes_through()

    def test_least_used_worker_device_pool(self):
        test_worker_slot_pool_uses_least_used_idle_then_allocates_when_busy()

    def test_worker_device_usage_limit(self):
        test_worker_device_is_destroyed_after_completed_account_limit()

    def test_multiprocess_device_assignment(self):
        test_multiprocess_device_assignment_is_even_and_disjoint()

    def test_process_device_header_cache(self):
        test_public_header_cache_is_bound_to_device_usage_and_ttl()

    def test_device_setup_waits_before_claiming_account(self):
        test_device_registration_is_a_producer_consumer_stage()

    def test_ready_device_publication_wakes_consumer(self):
        test_business_worker_waits_until_producer_publishes_ready_device()

    def test_pending_device_is_not_reused(self):
        test_unregistered_worker_slot_is_not_leasable()


if __name__ == "__main__":
    unittest.main()
