import asyncio
import os
import plistlib
import tempfile
import time
import unittest

from fastcheck.protocols import gsa_async
from fastcheck.status import result_bucket
from gsafast.ippool import IpPool
from simple_async import _attempt_slice


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

    def test_multi_process_uses_async_worker(self):
        import run_mp
        self.assertTrue(run_mp.WORKER.endswith('simple_async.py'))

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
