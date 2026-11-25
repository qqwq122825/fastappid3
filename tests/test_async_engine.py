import asyncio
import json
import os
import plistlib
import tempfile
import threading
import time
import unittest

from fastcheck.protocols import gsa_async
from fastcheck.status import result_bucket
from gsafast.ippool import IpPool
from simple_async import _attempt_slice
from simple import _new_state_lock, _shared_device_info


class AsyncEngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_transport_reuses_event_loop_socket(self):
        async def handler(reader, writer):
            headers = await reader.readuntil(b'\r\n\r\n')
            length = 0
            for line in headers.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    length = int(line.split(b':', 1)[1])
            if length:
                await reader.readexactly(length)
            body = plistlib.dumps({'Response': {'Status': {'ec': 0}}})
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/x-xml-plist\r\n'
                         + f'Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n'.encode()
                         + body)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, '127.0.0.1', 0)
        old = gsa_async.GSA_URL
        gsa_async.GSA_URL = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}/gsa'
        try:
            async with gsa_async.AsyncGsaSession(None) as session:
                outcome = await session.post(b'x', {}, 2, client_info='test')
        finally:
            gsa_async.GSA_URL = old
            server.close()
            await server.wait_closed()
        self.assertEqual(200, outcome.http_status)
        self.assertEqual(0, outcome.payload['Response']['Status']['ec'])

    async def test_mock_check_yields_without_network(self):
        old = os.environ.get('FASTCHECK_MOCK')
        os.environ['FASTCHECK_MOCK'] = '1'
        try:
            before = time.perf_counter()
            results = await asyncio.gather(*(
                gsa_async.check(f'user{i}@example.com', 'x', None, identity={})
                for i in range(100)
            ))
        finally:
            if old is None:
                os.environ.pop('FASTCHECK_MOCK', None)
            else:
                os.environ['FASTCHECK_MOCK'] = old
        self.assertEqual(100, len(results))
        self.assertLess(time.perf_counter() - before, 0.5)
        self.assertTrue(all('status' in row for row in results))

    def test_ip_pool_nowait_does_not_count_starvation(self):
        pool = IpPool('http://invalid/{num}', threads=1)
        before = pool.stats['blocked']
        self.assertEqual((None, 0.0), pool.acquire_nowait(0))
        self.assertEqual(before, pool.stats['blocked'])

    def test_live_state_lock_uses_waiter_queue(self):
        gate = _new_state_lock()
        self.assertIsInstance(gate, threading.Semaphore)
        self.assertTrue(gate.acquire(blocking=False))
        self.assertFalse(gate.acquire(blocking=False))
        gate.release()
        self.assertTrue(gate.acquire(blocking=False))
        gate.release()

    def test_device_info_avoids_file_lock_stampede(self):
        from unittest.mock import Mock
        gate = threading.Lock()
        pool = Mock()
        profile = {'client_info': 'fixture-client', 'user_agent': 'fixture-agent'}
        self.assertEqual(profile, _shared_device_info(
            pool, profile, {}, gate, 20, provider_direct=True))
        pool.info.assert_not_called()

        pool.info.return_value = dict(profile)
        cache = {}
        first = _shared_device_info(pool, None, cache, gate, 20,
                                    provider_direct=True)
        second = _shared_device_info(pool, None, cache, gate, 20,
                                     provider_direct=True)
        self.assertEqual(first, second)
        pool.info.assert_called_once_with(20, proxy=None, provider_direct=True)

    def test_multi_process_uses_thread_worker(self):
        import run_mp
        self.assertTrue(run_mp.WORKER.endswith('simple.py'))

    def test_single_process_uses_thread_worker(self):
        from pathlib import Path
        from unittest.mock import Mock, patch
        import web
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data').mkdir()
            accounts = root / 'accounts.txt'
            accounts.write_text('fixture@example.invalid----fixture\n')
            state = dict(web.STATE, proc=None, take_pending=False,
                         log=str(root / 'data' / 'run.log'))
            with patch.object(web, 'HERE', directory), \
                 patch.object(web, 'LIVE', str(root / 'data' / 'live.json')), \
                 patch.object(web, 'TASK_STATE', str(root / 'data' / 'task-process.json')), \
                 patch.object(web, 'STATE', state), \
                 patch.object(web, 'is_running', return_value=False), \
                 patch.object(web, 'proxy_api', return_value='http://fixture.invalid/{num}'), \
                 patch.object(web.subprocess, 'Popen', return_value=Mock(pid=123)) as launch:
                result = web.start_job(str(accounts), 2, 1)
            self.assertTrue(result['ok'])
            self.assertEqual('simple.py', Path(launch.call_args.args[0][1]).name)
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            task = json.loads((root / 'data' / 'task-process.json').read_text())
            self.assertEqual(123, task['pid'])

    def test_worker_priority_and_live_polling_protect_console(self):
        from unittest.mock import patch
        import web
        with patch.object(web.os, 'setpriority') as setpriority:
            self.assertTrue(web._lower_task_priority(123, 10))
        setpriority.assert_called_once_with(web.os.PRIO_PROCESS, 123, 10)
        self.assertIn('if(TICK_RUNNING) return', web.PAGE)
        self.assertIn('controller.abort(), 4000', web.PAGE)
        self.assertNotIn('fetch(\'/api/live?t=\'+Date.now())).json()', web.PAGE)

    def test_stop_uses_persisted_process_group_after_web_restart(self):
        from unittest.mock import patch
        import web
        record = {'pid': 321, 'pgid': 654, 'pid_start': 'token'}
        state = dict(web.STATE, proc=None)
        alive = iter((True, True, False, False, False))
        with patch.object(web, 'STATE', state), \
             patch.object(web, '_active_task_record', return_value=record), \
             patch.object(web, '_group_alive', side_effect=lambda pgid: next(alive)), \
             patch.object(web.os, 'killpg') as killpg, \
             patch.object(web, '_clear_task_record') as clear, \
             patch.object(web.time, 'sleep'):
            result = web.stop_job()
        self.assertTrue(result['ok'])
        killpg.assert_called_once_with(654, web.signal.SIGTERM)
        clear.assert_called_once_with()

    def test_linux_group_check_ignores_zombies(self):
        from pathlib import Path
        import web
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zombie = root / '101'
            live = root / '102'
            zombie.mkdir()
            live.mkdir()
            zombie.joinpath('stat').write_text('101 (worker) Z 1 654 0 0')
            live.joinpath('stat').write_text('102 (worker) S 1 654 0 0')
            self.assertTrue(web._linux_group_has_live_member(654, directory))
            live.joinpath('stat').unlink()
            self.assertFalse(web._linux_group_has_live_member(654, directory))

    def test_result_filter_scans_beyond_old_four_megabyte_tail(self):
        from pathlib import Path
        from unittest.mock import patch
        import web
        with tempfile.TemporaryDirectory() as directory:
            result_file = Path(directory) / 'run.jsonl'
            with result_file.open('w', encoding='utf-8') as handle:
                handle.write(json.dumps({
                    'email': 'first@example.invalid',
                    'status': 'undetermined',
                    'detail': 'fixture'}) + '\n')
                for index in range(50000):
                    handle.write(json.dumps({
                        'email': f'user{index}@example.invalid',
                        'status': 'wrong_password',
                        'detail': 'x' * 100}) + '\n')
            self.assertGreater(result_file.stat().st_size, 4 * 1024 * 1024)
            state = dict(web.STATE, run_out=str(result_file), started_at=1)
            with patch.object(web, 'STATE', state):
                result = object.__new__(web.Handler)._results('other', 100)
            self.assertEqual(1, result['total'])
            self.assertEqual('first@example.invalid', result['rows'][0]['email'])

    def test_stale_live_state_uses_incremental_result_progress(self):
        from pathlib import Path
        from unittest.mock import patch
        import web
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_file = root / 'live.json'
            result_file = root / 'run.jsonl'
            accounts = root / 'accounts.txt'
            accounts.write_text(''.join(
                f'user{i}@example.invalid----fixture\n' for i in range(10)))
            live_file.write_text(json.dumps({'done': 0}))
            os.utime(live_file, (1, 1))
            result_file.write_text(''.join(json.dumps({
                'email': f'user{i}@example.invalid',
                'status': 'wrong_password' if i < 2 else 'locked'}) + '\n'
                for i in range(3)))
            record = {'pid': 123, 'started_at': 1, 'threads': 2,
                      'processes': 1, 'limit': 0, 'accounts': str(accounts),
                      'run_out': str(result_file)}
            state = dict(web.STATE, accounts=str(accounts), total=0)
            with patch.object(web, 'LIVE', str(live_file)), \
                 patch.object(web, 'STATE', state), \
                 patch.object(web, '_active_task_record', return_value=record), \
                 patch.object(web.time, 'time', return_value=11):
                result = web._live_state_uncached()
            self.assertEqual(3, result['done'])
            self.assertEqual(0.3, result['rate'])
            self.assertEqual(1080, result['per_hour'])
            self.assertEqual(10, result['total'])
            self.assertEqual(2, result['threads'])
            self.assertEqual(1, result['processes'])
            self.assertEqual({'wrong_password': 2, 'locked': 1},
                             result['by_status'])
            self.assertEqual(3, len(result['recent']))
            self.assertTrue(result['live_fallback'])
            self.assertTrue(result['running'])
            self.assertEqual(123, result['pid'])

    def test_browser_live_endpoint_uses_resilient_state(self):
        from unittest.mock import patch
        import web
        expected = {'running': True, 'done': 7, 'live_fallback': True}
        with patch.object(web, 'live_state', return_value=expected) as state:
            self.assertIs(expected, web.read_live())
        state.assert_called_once_with()

    def test_result_table_formats_duration_as_seconds(self):
        import web
        self.assertIn('耗时（秒）', web.PAGE)
        self.assertEqual(2, web.PAGE.count(
            "const seconds = r.ms == null ? '--' : (Number(r.ms) / 1000).toFixed(2);"))
        self.assertEqual(2, web.PAGE.count('${seconds}</td>'))

    def test_transport_http_zero_is_classified_as_timeout(self):
        row = gsa_async._result(
            'error', 'init timeout', time.time(), kind='network', http=0)
        self.assertEqual(0, row['http'])
        self.assertEqual('timeout', result_bucket(row))

    def test_retry_attempts_share_item_budget_evenly(self):
        self.assertAlmostEqual(20 / 3, _attempt_slice(20, 2, 1), places=4)
        self.assertAlmostEqual(20 / 3, _attempt_slice(40 / 3, 2, 2), places=4)
        self.assertAlmostEqual(20 / 3, _attempt_slice(20 / 3, 2, 3), places=4)


if __name__ == '__main__':
    unittest.main()
