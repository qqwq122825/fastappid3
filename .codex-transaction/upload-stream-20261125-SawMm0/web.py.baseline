#!/usr/bin/env python3
"""GSA 极简模型 · 控制台

    python3 web.py                 # 打开 http://127.0.0.1:8777

功能：上传账号文件 → 设线程数 → 开始/停止 → 实时看速度与 CPU。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, 'data', 'live.json')
UPLOAD_DIR = os.path.join(HERE, 'data', 'uploads')
DEFAULT_ACCOUNTS = os.path.join(HERE, 'data', 'accounts.txt')
ACCOUNT_STATE = os.path.join(HERE, 'data', 'current-accounts.json')


NUM_RE = re.compile(r'([?&]num=)\d+')


def normalize_api(url):
    """把用户粘贴的接口地址统一成带 {num} 占位符的形式。

    ...&num=1&...          → ...&num={num}&...
    ...&num={num}&...      → 原样
    ...（没有 num 参数）   → 自动补 &num={num}
    """
    url = (url or '').strip()
    if not url:
        return ''
    if '{num}' in url:
        return url
    if NUM_RE.search(url):
        return NUM_RE.sub(r'\1{num}', url)
    return url + ('&' if '?' in url else '?') + 'num={num}'


def mask_api(url):
    """页面展示用：遮掉 password / token 的值。"""
    if not url:
        return ''
    return re.sub(r'(?i)((?:password|passwd|pwd|token|key)=)[^&\s]+', r'\1***', url)


def save_api(url):
    path = os.path.join(HERE, 'secrets.json')
    data = {}
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle) or {}
    except (OSError, ValueError):
        data = {}
    data['proxy_api'] = url
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=1)


def proxy_api():
    """凭据不进源码：环境变量优先，其次 secrets.json / conf.json。"""
    import os as _os
    env = _os.environ.get('GSA_PROXY_API')
    if env:
        return env
    for name in ('secrets.json', 'conf.json'):
        path = _os.path.join(HERE, name)
        try:
            with open(path, encoding='utf-8') as handle:
                value = json.load(handle).get('proxy_api')
            if isinstance(value, str) and '{num}' in value:
                return value
        except (OSError, ValueError):
            continue
    return ''
PYTHON = os.path.join(HERE, '.venv', 'bin', 'python')
MAX_THREADS = 2000

STATE = {
    'accounts': DEFAULT_ACCOUNTS,
    'proc': None,
    'threads': 0,
    'limit': 0,
    'started': None,
    'log': os.path.join(HERE, 'data', 'run.log'),
    'pending_accounts': None,
    'take_pending': False,
}
_ACCOUNT_CACHE = {}
_LOCK = threading.Lock()
PASSWORD = 'mtx123'          # 默认密码，--password 或 GSA_PASSWORD 可改


def _persistent_account_path(path):
    """只接受服务器 data/accounts.txt 或 data/uploads/ 里的文件。"""
    if not path:
        return None
    real = os.path.realpath(str(path))
    uploads = os.path.realpath(UPLOAD_DIR)
    try:
        in_uploads = os.path.commonpath((real, uploads)) == uploads
    except ValueError:
        in_uploads = False
    if real == os.path.realpath(DEFAULT_ACCOUNTS) or in_uploads:
        return real
    return None


def _remember_accounts(path):
    """记住最后一次上传，web 服务重启后仍能找到。"""
    path = _persistent_account_path(path)
    if not path or not os.path.isfile(path):
        return
    os.makedirs(os.path.dirname(ACCOUNT_STATE), exist_ok=True)
    tmp = ACCOUNT_STATE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump({'accounts': path}, handle, ensure_ascii=False)
    os.replace(tmp, ACCOUNT_STATE)


def _startup_accounts():
    """优先恢复记住的文件，其次选 uploads 里最新的文件。"""
    try:
        with open(ACCOUNT_STATE, encoding='utf-8') as handle:
            saved = json.load(handle).get('accounts')
        saved = _persistent_account_path(saved)
        if saved and os.path.isfile(saved):
            return saved
    except (OSError, ValueError, AttributeError):
        pass
    try:
        files = [os.path.join(UPLOAD_DIR, name) for name in os.listdir(UPLOAD_DIR)]
        files = [path for path in files if os.path.isfile(path)]
        if files:
            return max(files, key=os.path.getmtime)
    except OSError:
        pass
    return DEFAULT_ACCOUNTS


def _cookie_token():
    import hashlib
    return hashlib.sha256(('gsa|' + PASSWORD).encode()).hexdigest()[:32]


# ---------------------------------------------------------------- 账号解析
def analyse_accounts(path):
    import collections
    if not path or not os.path.exists(path):
        return {'error': f'文件不存在: {path}', 'path': path}
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        return {'error': f'无法读取: {exc}', 'path': path}
    if _ACCOUNT_CACHE.get('path') == path and _ACCOUNT_CACHE.get('mtime') == mtime:
        return _ACCOUNT_CACHE['data']
    domains, lengths = collections.Counter(), collections.Counter()
    total = bad = pw_eq = 0
    samples = []
    with open(path, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            total += 1
            if '----' not in line:
                bad += 1
                continue
            account, _, password = line.partition('----')
            local, _, domain = account.partition('@')
            domains[domain.lower() or '<no-at>'] += 1
            if password and password.lower() == local.lower():
                pw_eq += 1
            lengths[len(password)] += 1
            if len(samples) < 3:
                samples.append(account)
    data = {
        'path': path, 'name': os.path.basename(path), 'total': total,
        'unique_domains': len(domains), 'top_domains': domains.most_common(6),
        'format_error': bad, 'password_equals_account': pw_eq,
        'password_equals_ratio': round(pw_eq / total * 100, 1) if total else 0,
        'length_top': lengths.most_common(5), 'samples': samples,
        'size': os.path.getsize(path),
    }
    _ACCOUNT_CACHE.update(path=path, mtime=mtime, data=data)
    return data


def read_live():
    try:
        with open(LIVE, encoding='utf-8') as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return {'error': 'live.json 还没生成，先点「开始」', 'running': is_running()}
    payload['running'] = is_running()
    payload['accounts'] = STATE['accounts']
    return payload


def _path_allowed(path):
    """只允许访问当前任务使用的文件，或 data/uploads 下的上传文件。"""
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if real == os.path.realpath(STATE['accounts']):
        return True
    uploads = os.path.realpath(UPLOAD_DIR)
    return real.startswith(uploads + os.sep) or real == uploads


def is_running():
    proc = STATE['proc']
    return bool(proc is not None and proc.poll() is None)


_LIVE_CACHE = {'at': 0.0, 'data': None}


def live_state():
    """0.5 秒内的重复请求直接给缓存，避免多标签页把读盘打满。"""
    now = time.monotonic()
    if _LIVE_CACHE['data'] is not None and now - _LIVE_CACHE['at'] < 0.5:
        return _LIVE_CACHE['data']
    data = _live_state_uncached()
    _LIVE_CACHE.update(at=now, data=data)
    return data


def _live_state_uncached():
    running = is_running()
    try:
        with open(LIVE, encoding='utf-8') as handle:
            live = json.load(handle)
    except (OSError, ValueError):
        live = {}
    live = dict(live) if isinstance(live, dict) else {}
    live['running'] = running
    live['pid'] = STATE['proc'].pid if running else None
    live['accounts'] = STATE['accounts']
    if not live.get('total') and not running:
        live.setdefault('error', 'live.json 还没生成，先点「开始」')
    return live


# ---------------------------------------------------------------- 任务控制
def start_job(accounts, threads, limit, processes=1, verify_web=False,
              per_ip=6, ip_ttl=50.0, timeout=10.0, anisette_workers=0,
              no_register=False, retry=2, item_timeout=20.0, anisette_proxy=False):
    if is_running():
        return {'error': '已有任务在跑，先停止'}
    if STATE.get('take_pending') and STATE.get('pending_accounts'):
        accounts = STATE['pending_accounts']           # 点"开始"才切换到新文件
        STATE['take_pending'] = False
    if not os.path.exists(accounts):
        return {'error': f'账号文件不存在: {accounts}'}
    threads = max(1, min(int(threads or 0), MAX_THREADS))
    limit = max(0, int(limit or 0))
    os.makedirs(os.path.dirname(LIVE), exist_ok=True)
    try:
        os.remove(LIVE)
    except OSError:
        pass
    processes = max(1, min(int(processes or 1), 8))
    if processes > 1:
        # 多进程：4 核机器要吃满必须多进程（单进程被 GIL 卡在 1 核）
        cmd = [PYTHON, os.path.join(HERE, 'run_mp.py'),
               '--accounts', accounts, '--processes', str(processes),
               '--threads', str(threads)]
        cmd += ['--limit', str(limit)]
        api = proxy_api()
        if not api:
            return {'error': '没有代理接口：请设置环境变量 GSA_PROXY_API 或写 secrets.json'}
        cmd += ['--api', api]
        if verify_web:
            cmd.append('--verify-web')
        cmd += ['--per-ip', str(per_ip), '--ip-ttl', str(ip_ttl),
                '--timeout', str(timeout), '--retry', str(retry),
                '--item-timeout', str(item_timeout)]
        if anisette_workers:
            cmd += ['--anisette-workers', str(anisette_workers)]
        if no_register:
            cmd.append('--no-register')
        if anisette_proxy:
            cmd.append('--anisette-proxy')
    else:
        cmd = [PYTHON, os.path.join(HERE, 'simple.py'),
               '--accounts', accounts, '--threads', str(threads),
               '--live', LIVE, '--limit', str(limit),
               '--per-ip', str(per_ip), '--ip-ttl', str(ip_ttl),
               '--timeout', str(timeout), '--retry', str(retry),
               '--item-timeout', str(item_timeout)]
        if verify_web:
            cmd.append('--verify-web')
        if anisette_workers:
            cmd += ['--anisette-workers', str(anisette_workers)]
        if no_register:
            cmd.append('--no-register')
        if anisette_proxy:
            cmd.append('--anisette-proxy')
    # 追加而不是覆盖：否则上一次的报错会被这次清空，排查时看不到
    log = open(STATE['log'], 'a', encoding='utf-8')
    log.write(f'\n===== 启动 {time.strftime("%F %T")} =====\n')
    log.write(' '.join(cmd) + '\n')
    log.flush()
    proc = subprocess.Popen(cmd, cwd=HERE, stdout=log, stderr=subprocess.STDOUT)
    STATE.update(proc=proc, accounts=accounts, threads=threads, limit=limit,
                 processes=processes, started=time.time(), pending_accounts=None)
    total_threads = threads * processes
    return {'ok': True, 'pid': proc.pid, 'threads': threads, 'processes': processes,
            'limit': limit, 'total_threads': total_threads,
            'warmup_hint': (f'已启动 {processes} 进程 × {threads} 线程 = {total_threads} 线程；'
                            f'首轮注册设备约 {max(4, total_threads // 16)} 秒后才会有速度')}


def stop_job():
    proc = STATE['proc']
    if not is_running():
        return {'error': '没有正在跑的任务'}
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
    return {'ok': True}


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, body: bytes, ctype='application/json; charset=utf-8'):
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value):
        self._send(json.dumps(value, ensure_ascii=False).encode('utf-8'))

    def do_GET(self):
        try:
            return self._do_get()
        except Exception as exc:                                   # noqa: BLE001
            import traceback
            err = traceback.format_exc()
            log_path = os.path.join(HERE, 'data', 'web-error.log')
            try:
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                with open(log_path, 'a', encoding='utf-8') as handle:
                    handle.write(f'--- {time.strftime("%F %T")} GET {self.path}\n{err}\n')
            except OSError:
                pass
            try:
                return self._json({'error': f'后端异常：{type(exc).__name__}: {exc}'})
            except Exception:
                pass

    def _do_get(self):
        if self.path.startswith('/api/') and not self._authorized():
            return self._json({'error': '请先输入密码', 'need_login': True})
        if self.path.startswith('/api/results'):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            return self._json(self._results(
                (q.get('status') or ['all'])[0],
                int((q.get('limit') or ['60'])[0] or 60)))
        if self.path.startswith('/api/export'):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            want = (q.get('status') or [''])[0].strip()
            fmt = (q.get('fmt') or ['txt'])[0]
            return self._export(want, fmt)
        if self.path.startswith('/api/api-config'):
            current = proxy_api()
            return self._json({'api': mask_api(current),
                               'has_num': '{num}' in (current or ''),
                               'configured': bool(current)})
        if self.path.startswith('/api/live'):
            return self._json(read_live())
        if self.path.startswith('/api/accounts'):
            from urllib.parse import urlparse, parse_qs
            query = parse_qs(urlparse(self.path).query)
            default = STATE['accounts']
            target = (query.get('path') or [default])[0] or default
            if not _path_allowed(target):
                return self._json({'error': '只允许读取当前任务文件或 uploads 目录下的文件'})
            return self._json(analyse_accounts(target))
        if self.path.startswith('/api/state'):
            return self._json({'running': is_running(),
                               'accounts': STATE['accounts'],
                               'threads': STATE['threads'], 'limit': STATE['limit'],
                               'pid': STATE['proc'].pid if STATE['proc'] else None,
                               'log_tail': tail_log()})
        self._send(PAGE.encode('utf-8'), 'text/html; charset=utf-8')

    def _results(self, want, limit=60):
        """按状态查历史结果。只读每个 jsonl 的尾部 4MB，避免扫全文件。"""
        import glob as _glob
        limit = max(1, min(500, int(limit)))
        want = (want or 'all').strip()
        out, seen = [], set()
        for pat in ('simple-run.jsonl', 'mp-p*.jsonl'):
            for path in sorted(_glob.glob(os.path.join(HERE, 'data', pat))):
                try:
                    with open(path, 'rb') as handle:
                        handle.seek(0, os.SEEK_END)
                        size = handle.tell()
                        handle.seek(max(0, size - 4 * 1024 * 1024))
                        chunk = handle.read().decode('utf-8', errors='replace')
                except OSError:
                    continue
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    st = str(r.get('status') or '')
                    if want == 'other':
                        if st not in ('undetermined', 'error'):
                            continue
                    elif want not in ('', 'all') and st != want:
                        continue
                    key = (r.get('email'), st)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({'email': r.get('email'), 'status': st,
                                'attempts': r.get('attempts'),
                                'http': r.get('http'), 'ec': r.get('ec'),
                                'ms': r.get('ms'), 'slot': r.get('slot'),
                                'cpu': r.get('thread_cpu_ms'),
                                'detail': r.get('detail')})
        out.reverse()                      # 新的在前
        return {'total': len(out), 'rows': out[:limit], 'status': want}

    def _export(self, want, fmt):
        """按状态筛选导出账号。只保留 邮箱----密码 两列，不带其他信息。"""
        import glob as _glob
        patterns = [os.path.join(HERE, 'data', 'simple-run.jsonl'),
                    os.path.join(HERE, 'data', 'mp-p*.jsonl')]
        rows, seen = [], set()
        for pat in patterns:
            for path in sorted(_glob.glob(pat)):
                try:
                    handle = open(path, encoding='utf-8', errors='replace')
                except OSError:
                    continue
                with handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        st = str(r.get('status') or '')
                        if want == 'other':
                            if st not in ('undetermined', 'error'):
                                continue
                        elif want and want != 'all' and st != want:
                            continue
                        email = str(r.get('email') or '')
                        if not email or email in seen:
                            continue
                        seen.add(email)
                        rows.append(r)
        if fmt == 'csv':
            import csv as _csv, io as _io
            buf = _io.StringIO()
            w = _csv.writer(buf)
            w.writerow(['email', 'status', 'attempts', 'http', 'ec', 'ms', 'detail'])
            for r in rows:
                w.writerow([r.get(k, '') for k in
                            ('email', 'status', 'attempts', 'http', 'ec', 'ms', 'detail')])
            out = buf.getvalue()
            ctype, name = 'text/csv; charset=utf-8', 'export.csv'
        else:
            src = {}
            acc = STATE['accounts']
            try:
                with open(acc, encoding='utf-8', errors='replace') as handle:
                    for line in handle:
                        line = line.strip()
                        if '----' in line:
                            src[line.split('----', 1)[0]] = line
            except OSError:
                pass
            body = []
            for r in rows:
                em = str(r.get('email') or '')
                line = src.get(em)
                if line:
                    body.append(line)
                elif em:
                    body.append(em)      # 原始文件里没有这行时只导 email
            out = '\n'.join(body) + ('\n' if body else '')
            ctype, name = 'text/plain; charset=utf-8', f'export-{want or "all"}.txt'
        data = out.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Disposition', f'attachment; filename="{name}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        """简单密码：浏览器登录后带 gsa_auth cookie。"""
        cookie = self.headers.get('Cookie') or ''
        want = 'gsa_auth=' + _cookie_token()
        return want in cookie

    def do_POST(self):
        try:
            return self._do_post()
        except Exception as exc:                                   # noqa: BLE001
            import traceback
            err = traceback.format_exc()
            log_path = os.path.join(HERE, 'data', 'web-error.log')
            try:
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                with open(log_path, 'a', encoding='utf-8') as handle:
                    handle.write(f'--- {time.strftime("%F %T")} POST {self.path}\n{err}\n')
            except OSError:
                pass
            try:
                return self._json({'error': f'后端异常：{type(exc).__name__}: {exc}',
                                   'trace': err.splitlines()[-3:]})
            except Exception:
                pass

    def _do_post(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length > 64 * 1024 * 1024:          # 上传上限 64MB
            return self._json({'error': '上传内容过大（上限 64MB）'})
        raw = self.rfile.read(length) if length else b'{}'
        try:
            payload = json.loads(raw.decode('utf-8'))
        except ValueError:
            return self._json({'error': '请求体不是合法 JSON'})

        if self.path.startswith('/api/set-api'):
            raw = str(payload.get('api') or '')
            if not raw.strip():
                return self._json({'error': '接口地址不能为空'})
            fixed = normalize_api(raw)
            if '{num}' not in fixed:
                return self._json({'error': '无法识别 num 参数，请确认地址里有 num=数字'})
            try:
                save_api(fixed)
            except OSError as exc:
                return self._json({'error': f'写 secrets.json 失败: {exc}'})
            return self._json({'ok': True, 'api': mask_api(fixed)})
        if self.path.startswith('/api/login'):
            if str(payload.get('password') or '') != PASSWORD:
                return self._json({'error': '密码不对'})
            body = json.dumps({'ok': True}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Set-Cookie',
                             f'gsa_auth={_cookie_token()}; Path=/; Max-Age=604800; HttpOnly')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._authorized():
            return self._json({'error': '请先输入密码', 'need_login': True})
        if self.path.startswith('/api/upload'):
            return self._json(self._upload(payload))
        if self.path.startswith('/api/start'):
            with _LOCK:
                result = start_job(payload.get('accounts') or STATE['accounts'],
                                   payload.get('threads') or 100,
                                   payload.get('limit') or 0,
                                   payload.get('processes') or 1,
                                   bool(payload.get('verify_web')),
                                   int(payload.get('per_ip') or 6),
                                   float(payload.get('ip_ttl') or 50),
                                   float(payload.get('timeout') or 10),
                                   int(payload.get('anisette_workers') or 0),
                                   bool(payload.get('no_register')),
                                   int(payload.get('retry') if payload.get('retry') is not None else 2),
                                   float(payload.get('item_timeout') or 20),
                                   bool(payload.get('anisette_proxy')))
            return self._json(result)
        if self.path.startswith('/api/stop'):
            with _LOCK:
                return self._json(stop_job())
        return self._json({'error': 'unknown endpoint'})

    def _upload(self, payload):
        name = os.path.basename(str(payload.get('name') or 'accounts.txt'))
        content = payload.get('content')
        if not isinstance(content, str) or not content.strip():
            return {'error': '文件内容为空'}
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        safe = ''.join(c for c in name if c.isalnum() or c in '._-') or 'accounts.txt'
        path = os.path.join(UPLOAD_DIR, f'{int(time.time())}-{safe}')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(content)
        # 不改 STATE['accounts']：正在跑的任务还在用旧文件，页面不能把新文件显示成当前
        STATE['pending_accounts'] = path
        STATE['take_pending'] = True
        _remember_accounts(path)
        _ACCOUNT_CACHE.clear()
        info = analyse_accounts(path)
        info['uploaded'] = True
        return info

    def log_message(self, *args):
        pass


def tail_log(lines=4, window=65536):
    """只读文件末尾一段，不整文件扫描（16 MiB 日志全扫一次约 32ms）。"""
    try:
        with open(STATE['log'], 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - window))
            chunk = handle.read().decode('utf-8', errors='replace')
    except OSError:
        return []
    rows = [r.rstrip() for r in chunk.splitlines()
            if r.strip() and 'Warning' not in r and 'warnings.warn' not in r]
    return rows[-lines:] if size > window else rows[-lines:]


PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GSA 校验控制台</title>
<style>
:root{--bg:#f5f7fa;--card:#fff;--line:#e5e7eb;--fg:#111827;--dim:#6b7280;
--blue:#2563eb;--green:#16a34a;--amber:#d97706;--red:#dc2626;--gray:#9ca3af}
*{box-sizing:border-box}
html,body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Hiragino Sans GB","Microsoft YaHei",Arial,sans-serif}
body{margin:0;background:var(--bg);color:var(--fg);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Hiragino Sans GB","Microsoft YaHei",Arial,sans-serif;
font-size:14px;line-height:1.55;
-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
a{color:var(--blue);text-decoration:none}
.top{background:#fff;border-bottom:1px solid var(--line);padding:14px 24px;
display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:20}
.top h1{font-size:17px;margin:0;font-weight:700}
.tag{background:#eef2ff;color:#4338ca;font-size:11px;padding:2px 8px;border-radius:6px}
.top .right{margin-left:auto;display:flex;align-items:center;gap:14px;font-size:12px;color:var(--dim)}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle}

.layout{display:grid;grid-template-columns:330px 1fr;gap:16px;padding:16px 24px;align-items:start}
@media(max-width:1080px){.layout{grid-template-columns:1fr}}

.panel{background:var(--card);border:1px solid var(--line);border-radius:10px}
.panel>.hd{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;
align-items:center;justify-content:space-between}
.panel>.hd b{font-size:14px}
.panel>.bd{padding:16px}

.field{margin-bottom:14px}
.field>label{display:block;font-size:12px;color:var(--dim);margin-bottom:6px}
.field>label b{color:var(--fg);font-weight:600}
input[type=number],input[type=password],input[type=text],select{font-family:inherit;
width:100%;border:1px solid var(--line);border-radius:8px;padding:8px 10px;
font-size:13px;background:#fff;color:var(--fg);font-variant-numeric:tabular-nums}
input:focus,select:focus{outline:2px solid #bfdbfe;border-color:var(--blue)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.drop{border:1.5px dashed var(--line);border-radius:8px;padding:16px;text-align:center;
color:var(--dim);font-size:12px;cursor:pointer;transition:.15s}
.drop:hover,.drop.on{border-color:var(--blue);background:#f8fbff;color:var(--blue)}
.btn{border:0;border-radius:8px;padding:10px 18px;font-size:13px;font-weight:600;
cursor:pointer;transition:.15s}
.btn.primary{background:var(--green);color:#fff}
.btn.primary:hover{background:#15803d}
.btn.danger{background:var(--red);color:#fff}
.btn.danger:hover{background:#b91c1c}
.btn.ghost{background:#fff;border:1px solid var(--line);color:var(--fg)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.chk{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--fg)}
.hint{font-size:11px;color:var(--dim);line-height:1.5;margin-top:5px}

.stats{display:grid;grid-template-columns:repeat(11,1fr);gap:0;
background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
@media(max-width:1500px){.stats{grid-template-columns:repeat(6,1fr)}}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{padding:12px 14px;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat .k{font-size:11px;color:var(--dim);margin-bottom:4px;white-space:nowrap}
.stat .v{font-size:23px;font-weight:700;letter-spacing:-.3px;
font-family:inherit;font-variant-numeric:tabular-nums;
font-feature-settings:"tnum" 1,"lnum" 1}
.stat .v.sm{font-size:17px}
.v-green{color:var(--green)}.v-red{color:var(--red)}.v-amber{color:var(--amber)}
.v-blue{color:var(--blue)}.v-gray{color:var(--gray)}

.prog{margin-top:12px}
.prog .bar{height:8px;background:#eef1f5;border-radius:6px;overflow:hidden}
.prog .bar>i{display:block;height:100%;width:0;background:var(--blue);transition:width .4s}
.prog .meta{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);
margin-top:7px;font-family:inherit;font-variant-numeric:tabular-nums}

.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;padding:9px 12px;color:var(--dim);font-weight:500;
font-size:11.5px;border-bottom:1px solid var(--line);background:#fafbfc;white-space:nowrap}
.tbl td{padding:9px 12px;border-bottom:1px solid #f3f4f6;white-space:nowrap;
font-family:inherit;font-variant-numeric:tabular-nums;
font-feature-settings:"tnum" 1,"lnum" 1}
.tbl tr:hover td{background:#fafbfc}
.badge{display:inline-block;padding:1.5px 8px;border-radius:5px;font-size:11px;font-weight:600}
.b-green{background:#dcfce7;color:#166534}
.b-red{background:#fee2e2;color:#991b1b}
.b-amber{background:#fef3c7;color:#92400e}
.b-gray{background:#f3f4f6;color:#4b5563}
.b-blue{background:#dbeafe;color:#1e40af}
.scroll{max-height:520px;overflow:auto}
.mono,.stat .v,.tbl td,.tbl th{font-family:inherit;
font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1,"lnum" 1}
#gate{position:fixed;inset:0;background:rgba(17,24,39,.55);z-index:99;display:none;
align-items:center;justify-content:center;backdrop-filter:blur(2px)}
#gate .panel{width:330px}
</style></head><body>

<div class="top">
  <h1>GSA 校验控制台</h1>
  <span class="tag">极简模型</span>
  <div class="right">
    <span id="stateTag"><span class="dot" style="background:#9ca3af"></span>未开始</span>
    <span>启动 <b id="started">--</b></span>
    <span>SRP <b id="backend">--</b></span>
    <a href="#" id="logout">换个密码</a>
  </div>
</div>

<div class="layout">
  <!-- 左：任务设置 -->
  <div class="panel">
    <div class="hd"><b>任务设置</b><span class="tag" id="modeTag">单进程</span></div>
    <div class="bd">
      <div class="field">
        <label>代理接口 <b id="apiState">未配置</b></label>
        <input type="text" id="api" placeholder="粘贴接口地址，num=1 会自动变成 {num}">
        <div style="display:flex;gap:8px;margin-top:6px">
          <button class="btn ghost" id="saveApi" style="flex:1">保存接口</button>
        </div>
        <div class="hint" id="apiHint">程序会按需要的数量自动替换 num</div>
      </div>

      <div class="field">
        <label>账号文件 <b id="accName">未选择</b></label>
        <div class="drop" id="drop">点击或拖入 .txt（账号----密码）</div>
        <input type="file" id="file" accept=".txt,.csv" style="display:none">
        <div class="hint" id="accInfo"></div>
      </div>

      <div class="field">
        <label>并发</label>
        <div class="row2">
          <div><input type="number" id="processes" value="2" min="1" max="8" placeholder="进程数">
            <div class="hint">进程数</div></div>
          <div><input type="number" id="threads" value="1000" min="1" max="2000" placeholder="线程/进程">
            <div class="hint">每进程线程</div></div>
        </div>
        <div class="hint" id="rechint"></div>
      </div>

      <div class="field">
        <label>条数（0 = 全部）</label>
        <input type="number" id="limit" value="0" min="0">
      </div>

      <div class="field">
        <label>代理参数</label>
        <div class="row2" style="margin-bottom:10px">
          <div><input type="number" id="perip" value="6" min="1" max="50">
            <div class="hint">每 IP 条数</div></div>
          <div><input type="number" id="ttl" value="50" min="10" max="600" step="5">
            <div class="hint">IP 有效期/秒</div></div>
        </div>
        <div class="row2">
          <div><input type="number" id="otpreuse" value="15" min="0" max="50">
            <div class="hint">公共头复用次数</div></div>
          <div><input type="number" id="timeout" value="10" min="3" max="60">
            <div class="hint">超时/秒</div></div>
        </div>
        <div class="row2" style="margin-top:10px">
          <div><input type="number" id="retry" value="2" min="0" max="5">
            <div class="hint">重试次数</div></div>
          <div><input type="number" id="itemto" value="20" min="5" max="120" step="5">
            <div class="hint">单条超时/秒</div></div>
        </div>
        <div class="hint" style="margin-top:4px">
          单条超时 = 这条账号的总预算（含所有重试），超了直接判超时，不再磕
        </div>
      </div>

      <div class="field">
        <label class="chk"><input type="checkbox" id="vweb"> GSA 判 au=repair 时用 web 复核</label>
        <label class="chk" style="margin-top:8px"><input type="checkbox" id="noreg"> 跳过设备注册检查</label>
        <label class="chk" style="margin-top:8px"><input type="checkbox" id="asproxy"> 公共头走代理 <span style="color:var(--amber);font-size:11px">（机房 IP 直连 sidestore 超时时勾）</span></label>
      </div>

      <div style="display:flex;gap:10px">
        <button class="btn primary" id="start" style="flex:1">开始</button>
        <button class="btn danger" id="stop" disabled>停止</button>
        <button class="btn ghost" id="refresh">刷新</button>
      </div>
      <div class="hint" id="hint" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- 右：进度与结果 -->
  <div>
    <div class="panel" style="margin-bottom:16px">
      <div class="hd"><b>进度与结果</b><span class="hint" id="modeHint">本地执行</span></div>
      <div class="bd" style="padding-bottom:0">
        <div class="stats">
          <div class="stat"><div class="k">总数</div><div class="v" id="sTotal">0</div></div>
          <div class="stat"><div class="k">完成</div><div class="v v-blue" id="sDone">0</div></div>
          <div class="stat"><div class="k">剩余</div><div class="v" id="sLeft">0</div></div>
          <div class="stat"><div class="k">当前速度</div><div class="v sm v-green" id="sRate">0</div></div>
          <div class="stat"><div class="k">密码错误</div><div class="v v-red" id="sWrong">0</div></div>
          <div class="stat"><div class="k">锁定</div><div class="v v-amber" id="sLock">0</div></div>
          <div class="stat"><div class="k">双重验证</div><div class="v" id="s2fa">0</div></div>
          <div class="stat"><div class="k">需要真机</div><div class="v v-amber" id="sMac">0</div></div>
          <div class="stat"><div class="k">不存在</div><div class="v" id="sNF">0</div></div>
          <div class="stat"><div class="k">超时</div><div class="v v-gray" id="sTO">0</div></div>
          <div class="stat"><div class="k">其他</div><div class="v v-gray" id="sOther">0</div></div>
        </div>

        <div class="prog">
          <div class="bar"><i id="bar"></i></div>
          <div class="meta">
            <span><b id="pText">0 / 0</b> <span id="pPct">0%</span></span>
            <span id="pSpeed">-- 条/小时</span>
          </div>
        </div>

        <div class="meta" style="display:flex;justify-content:space-between;
             padding:12px 0;border-top:1px solid var(--line);margin-top:12px;font-size:12px;color:var(--dim)">
          <span id="mThreads">-- 线程</span>
          <span id="mCpu">CPU -- 核</span>
          <span id="mP50">p50 -- ms</span>
          <span id="mOtp">公共头 命中 -- / 拉取 --</span>
          <span id="mRetry">重试 --</span>
          <span id="mEta">--</span>
        </div>
        <div class="meta" style="display:flex;justify-content:space-between;
             padding:10px 0 2px;border-top:1px solid var(--line);font-size:12px;color:var(--dim)">
          <span id="mDevices">设备池 已注册 -- / 使用中 -- / 注册中 --</span>
          <span id="mRegErr">注册换代理 --</span>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="hd"><b>最近结果</b>
        <span style="display:flex;gap:8px;align-items:center">
          <select id="filter" style="width:auto;padding:5px 9px;font-size:12px">
            <option value="all">全部结果</option>
            <option value="wrong_password">密码错误</option>
            <option value="locked">锁定</option>
            <option value="need_2fa">双重验证</option>
            <option value="need_mac">需要真机</option>
            <option value="not_found">不存在</option>
            <option value="timeout">超时</option>
            <option value="other">其他（未归类 + 错误）</option>
          </select>
          <button class="btn ghost" id="expTxt" style="padding:5px 12px;font-size:12px">导出账号</button>
          <button class="btn ghost" id="expCsv" style="padding:5px 12px;font-size:12px">导出明细</button>
          <span class="hint" id="tblHint">实时刷新</span>
        </span>
      </div>
      <div class="scroll">
        <table class="tbl">
          <thead><tr>
            <th style="width:52px">#</th><th>账号</th><th style="width:110px">状态</th>
            <th style="width:80px">耗时</th><th style="width:80px">CPU</th>
            <th style="width:60px">设备</th><th style="width:70px">HTTP</th>
            <th style="width:80px">业务码</th>
            <th>原因（Apple 原文）</th>
          </tr></thead>
          <tbody id="rows"><tr><td colspan="9" style="text-align:center;color:#9ca3af;padding:24px">
            还没有结果</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div id="gate"><div class="panel">
  <div class="hd"><b>输入控制台密码</b></div>
  <div class="bd">
    <input type="password" id="pwd" placeholder="密码">
    <button class="btn primary" id="login" style="width:100%;margin-top:10px">进入</button>
    <div class="hint" id="pwerr" style="color:var(--red)"></div>
  </div>
</div></div>

<script>
const $ = id => document.getElementById(id);
const num = n => (n ?? 0).toLocaleString();
const cls = s => !s ? 'b-gray'
  : ['valid'].includes(s) ? 'b-green'
  : ['wrong_password','not_found'].includes(s) ? 'b-red'
  : ['locked','security_lock','need_2fa','need_mac'].includes(s) ? 'b-amber'
  : ['timeout'].includes(s) ? 'b-gray' : 'b-blue';

let shownAccounts = null;

/* ---- 登录 ---- */
async function login(){
  const res = await (await fetch('/api/login',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:$('pwd').value})})).json();
  if(res.error){ $('pwerr').textContent = res.error; return; }
  $('gate').style.display='none'; loadAccounts(); tick();
}
$('login').onclick = login;
$('pwd').addEventListener('keydown', e => { if(e.key==='Enter') login(); });
$('logout').onclick = e => { e.preventDefault(); document.cookie='gsa_auth=; Max-Age=0; path=/'; location.reload(); };

/* ---- 代理接口 ---- */
async function loadApi(){
  try{
    const r = await (await fetch('/api/api-config')).json();
    if(r.api) $('api').value = r.api;
    $('apiState').textContent = r.configured ? '已配置' : '未配置';
    $('apiState').style.color = r.configured ? 'var(--green)' : 'var(--red)';
  }catch(e){}
}
async function saveApiFn(){
  const url = $('api').value.trim();
  if(!url){ $('apiHint').textContent='先粘贴接口地址'; return; }
  const r = await (await fetch('/api/set-api',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api:url})})).json();
  if(r.error){ $('apiHint').textContent = r.error; $('apiHint').style.color='var(--red)'; }
  else { $('apiHint').textContent = '已保存：' + r.api;
         $('apiHint').style.color='var(--green)';
         $('api').value = r.api; $('apiState').textContent='已配置';
         $('apiState').style.color='var(--green)'; }
}
$('saveApi').onclick = saveApiFn;
loadApi();

/* ---- 上传 ---- */
const fileInput = $('file');
$('drop').onclick = () => {
  // 先清空，否则重复选同一个文件时浏览器不会再触发 change。
  fileInput.value = '';
  fileInput.click();
};
fileInput.addEventListener('change', async e => {
  const file = e.target.files && e.target.files[0];
  if(!file) return;
  await upload(file);
  // 上传完继续清空，下次仍可选同名文件。
  e.target.value = '';
});
['dragenter','dragover'].forEach(k=>$('drop').addEventListener(k,e=>{
  e.preventDefault(); $('drop').classList.add('on');}));
['dragleave','drop'].forEach(k=>$('drop').addEventListener(k,e=>{
  e.preventDefault(); $('drop').classList.remove('on');}));
$('drop').addEventListener('drop', e => {
  if(e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });

async function upload(file){
  const status = $('accInfo');
  $('accName').textContent = file.name;
  status.textContent = `正在读取 ${file.name}…`;
  status.style.color = 'var(--dim)';
  try{
    const content = await file.text();
    status.textContent = `正在上传 ${file.name}…`;
    const response = await fetch('/api/upload',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:file.name, content})});
    const text = await response.text();
    let res;
    try{ res = JSON.parse(text); }
    catch(e){ throw new Error(`服务返回 HTTP ${response.status}：${text.slice(0,120)}`); }
    if(!response.ok || res.error) throw new Error(res.error || `HTTP ${response.status}`);
    renderAccounts(res);
    status.style.color = 'var(--green)';
    $('hint').textContent = `已上传 ${res.name}：${num(res.total)} 条`;
    $('hint').style.color = 'var(--green)';
  }catch(e){
    status.textContent = `上传失败：${e.message || e}`;
    status.style.color = 'var(--red)';
    $('hint').textContent = status.textContent;
    $('hint').style.color = 'var(--red)';
  }
}

function renderAccounts(a){
  if(!a || a.error){ $('accInfo').textContent = a ? a.error : ''; return; }
  $('accName').textContent = a.name || '';
  $('accInfo').textContent =
    `${num(a.total)} 条 · ${a.top_domains?.[0]?.[0]||'--'} · 密码=用户名 ${a.password_equals_ratio}%`
    + (a.format_error ? ` · 格式异常 ${a.format_error}` : '');
}

/* ---- 启停 ---- */
async function post(url, body){
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 30000);
  try{
    const r = await fetch(url, {method:'POST', signal:ctl.signal,
      headers:{'Content-Type':'application/json'},
      body: body ? JSON.stringify(body) : undefined});
    const text = await r.text();
    if(!r.ok){
      if(r.status === 401 || r.status === 403) return {error:'请重新输入密码'};
      return {error:`服务返回 HTTP ${r.status}：${text.slice(0,160)}`};
    }
    try{ return JSON.parse(text); }
    catch(e){ return {error:`返回不是 JSON：${text.slice(0,160)}`}; }
  }catch(e){
    return {error: e.name === 'AbortError'
      ? '请求超时 30 秒（服务器没响应）'
      : `请求失败：${e.message}`};
  }finally{ clearTimeout(timer); }
}

async function start(){
  const body = {threads:+$('threads').value, limit:+$('limit').value,
    processes:+$('processes').value, verify_web:$('vweb').checked,
    per_ip:+$('perip').value, ip_ttl:+$('ttl').value,
    timeout:+$('timeout').value, no_register:$('noreg').checked,
    retry:+$('retry').value, item_timeout:+$('itemto').value,
    anisette_proxy:$('asproxy').checked};
  $('start').disabled = true; $('hint').textContent='启动中…';
  $('hint').style.color = 'var(--dim)';
  const res = await post('/api/start', body);
  if(res.error){
    $('hint').textContent = '✕ ' + res.error;
    $('hint').style.color = 'var(--red)';
    $('start').disabled = false;
  }else{
    $('hint').textContent = res.warmup_hint || '已启动';
    $('hint').style.color = 'var(--green)';
  }
}
async function stop(){
  $('stop').disabled = true;
  const res = await post('/api/stop');
  $('hint').textContent = res.error ? ('✕ ' + res.error) : '已停止';
  $('hint').style.color = res.error ? 'var(--red)' : 'var(--dim)';
}
$('start').onclick = start;
$('stop').onclick = stop;
$('refresh').onclick = () => { shownAccounts=null; tick(); };

/* ---- 推荐提示 ---- */
function refreshHint(){
  const p=+$('processes').value, t=+$('threads').value, total=p*t, warn=[];
  if(p===1 && t>1200) warn.push('单进程超 1200 线程会变慢，建议多进程');
  if(total>3000) warn.push(`总线程 ${total} 可能超出 4G 内存`);
  if(p>1 && t>1200) warn.push('每进程超 1200 线程边际递减');
  $('rechint').textContent = warn.length ? '⚠ '+warn.join('；')
    : `共 ${total} 线程 · 4 核 4G 推荐 2 × 1000`;
  $('rechint').style.color = warn.length ? 'var(--amber)' : 'var(--dim)';
  $('modeTag').textContent = p>1 ? `${p} 进程` : '单进程';
  $('rechint').style.color = warn.length ? 'var(--amber)' : 'var(--dim)';
}
['processes','threads'].forEach(id=>$(id).addEventListener('input', refreshHint));
refreshHint();

/* ---- 导出 ---- */
function exportAs(fmt){
  const st = $('filter').value;
  const url = `/api/export?status=${encodeURIComponent(st)}&fmt=${fmt}`;
  const a = document.createElement('a');
  a.href = url; a.download = '';
  document.body.appendChild(a); a.click(); a.remove();
  $('tblHint').textContent = '已导出';
  setTimeout(()=>{ $('tblHint').textContent = '实时刷新'; }, 2000);
}
$('expTxt').onclick = () => exportAs('txt');
$('expCsv').onclick = () => exportAs('csv');
$('filter').onchange = () => {
  const want = $('filter').value;
  if(want && want !== 'all'){ loadHistory(want); }
  else { HIST = null; $('tblHint').textContent = '实时刷新'; renderRows(); }
};

/* ---- 主循环 ---- */
function setStat(id, v){ $(id).textContent = num(v); }

async function tick(){
  let d;
  try{ d = await (await fetch('/api/live?t='+Date.now())).json(); }
  catch(e){ $('stateTag').innerHTML='<span class="dot" style="background:#dc2626"></span>读取失败'; return; }
  if(d.error){
    if(d.need_login){ $('gate').style.display='flex'; $('pwd').focus(); return; }
    $('stateTag').innerHTML='<span class="dot" style="background:#9ca3af"></span>'+d.error;
    return;
  }
  const by = d.by_status || {};
  setStat('sTotal', d.total); setStat('sDone', d.done);
  setStat('sLeft', Math.max(0, (d.total||0)-(d.done||0)));
  $('sRate').textContent = (d.rate||0).toFixed(1);
  setStat('sWrong', by.wrong_password); setStat('sLock', by.locked);
  setStat('s2fa', by.need_2fa); setStat('sNF', by.not_found);
  setStat('sMac', by.need_mac);
  setStat('sTO', by.timeout);
  setStat('sOther', (by.undetermined||0)+(by.error||0));

  const pct = d.total ? d.done/d.total*100 : 0;
  $('bar').style.width = pct.toFixed(1)+'%';
  $('pText').textContent = `${num(d.done)} / ${num(d.total)}`;
  $('pPct').textContent = pct.toFixed(1)+'%';
  $('pSpeed').textContent = `${num(d.per_hour)} 条/小时`;

  $('started').textContent = d.started || '--';
  $('backend').textContent = d.backend || '--';
  $('backend').style.color = d.backend==='gmpy2' ? 'var(--green)' : 'var(--red)';
  $('mThreads').textContent = d.processes>1
    ? `${d.threads} 线程 × ${d.processes} 进程` : `${d.threads} 线程`;
  const procCores = d.proc_cpu_cores ?? d.cpu_cores ?? 0;
  $('mCpu').textContent = `CPU ${procCores.toFixed(2)} 核`
    + (d.cpu_per_account ? ` · ${d.cpu_per_account.toFixed(1)} ms/条` : '');
  $('mP50').textContent = `p50 ${d.p50 ?? '--'} ms · p90 ${d.p90 ?? '--'} ms`;
  $('mOtp').textContent = `公共头 命中 ${num(d.otp_hit)} / 拉取 ${num(d.otp_fetch)}`;
  const rk = d.by_retry || {};
  const rkText = Object.keys(rk).length
    ? ' · ' + Object.entries(rk).map(([k,v]) => `${k}:${v}`).join(' ') : '';
  $('mRetry').textContent = `重试 ${num(d.retried)}${rkText}`;
  $('mDevices').textContent = `设备池 已注册 ${num(d.device_ready)} / 使用中 ${num(d.device_in_use)} / 注册中 ${num(d.device_registering)}`;
  const re = d.register_error_types || {};
  const reTop = Object.entries(re).sort((a,b)=>b[1]-a[1]).slice(0,2)
    .map(([k,v])=>`${k} ${num(v)}`).join(' · ');
  $('mRegErr').textContent = `注册换代理 ${num(d.register_errors)}`
    + (reTop ? ` · ${reTop}` : '');
  $('mEta').textContent = d.eta == null ? '--' : `剩 ${Math.round(d.eta)} 秒`;

  $('stateTag').innerHTML = d.finished
    ? `<span class="dot" style="background:var(--green)"></span>${d.status==='complete'?'已完成':'部分完成'}`
    : '<span class="dot" style="background:var(--blue)"></span>运行中';
  // 只有确认状态后才改按钮；fetch 失败时保持原样，避免永久 disabled
  if(typeof d.running === 'boolean'){
    $('start').disabled = d.running;
    $('stop').disabled = !d.running;
  }
  $('modeHint').textContent = d.incomplete
    ? `⚠ 缺 ${num(d.incomplete)} 条` : '本地执行';

  LAST = d;
  const want = $('filter').value;
  if(!want || want === 'all') renderRows();   // 看历史时不被实时流覆盖
  else if(!HIST) renderRows();

  if(d.accounts && d.accounts !== shownAccounts){
    shownAccounts = d.accounts;
    loadAccounts(d.accounts);
  }
}

let LAST = null;
let HIST = null;          // 筛选时从 /api/results 拿的历史结果

function rowHtml(r, idx){
  const st = r.status || 'unknown';
  const att = (r.attempts && r.attempts > 1)
    ? ` <span class="badge b-blue" style="font-size:10px">×${r.attempts}</span>` : '';
  return `<tr>
    <td class="mono">${idx}</td>
    <td>${(r.email||'').slice(0,32)||'--'}</td>
    <td><span class="badge ${cls(st)}">${st}</span>${att}</td>
    <td class="mono">${r.ms ?? '--'}</td>
    <td class="mono">${r.cpu ?? r.thread_cpu_ms ?? '--'}</td>
    <td class="mono">${r.slot ?? '--'}</td>
    <td class="mono">${r.http ?? '--'}</td>
    <td class="mono">${r.ec ?? '--'}</td>
    <td style="color:#6b7280;font-size:11.5px;max-width:340px;overflow:hidden;
        text-overflow:ellipsis" title="${(r.detail||'').replace(/"/g,'&quot;')}">
      ${(r.detail||'--').slice(0,64)}</td>
  </tr>`;
}

async function loadHistory(want){
  $('tblHint').textContent = '查询中…';
  try{
    const r = await (await fetch(`/api/results?status=${encodeURIComponent(want)}&limit=100`)).json();
    HIST = r;
    $('tblHint').textContent = `共 ${num(r.total)} 条符合条件的记录`;
  }catch(e){ HIST = null; $('tblHint').textContent = '查询失败'; }
  renderRows();
}

function renderRows(){
  const want = $('filter').value;
  const useHist = want && want !== 'all';
  const rec = useHist ? ((HIST && HIST.rows) || [])
                      : ((LAST && LAST.recent) || []).slice().reverse();
  const base = useHist ? (HIST ? HIST.rows.length : 0)
                       : ((LAST && LAST.done) || 0);
  $('rows').innerHTML = rec.length ? rec.map((r,i)=>rowHtml(r, base - i)).join('')
    : `<tr><td colspan="9" style="text-align:center;color:#9ca3af;padding:24px">
        ${useHist ? '这个分类下还没有记录' : '还没有结果'}</td></tr>`;
}

function renderRowsOld(){
  const d = LAST;
  if(!d){ return; }
  const want = $('filter').value;
  let rec = (d.recent||[]).slice().reverse();
  if(want === 'other') rec = rec.filter(r =>
    ['undetermined','error'].includes(r.status||''));
  else if(want && want !== 'all') rec = rec.filter(r => (r.status||'') === want);
  $('rows').innerHTML = rec.length ? rec.map((r,i)=>{
    const st = r.status || 'unknown';
    const att = (r.attempts && r.attempts > 1)
      ? ` <span class="badge b-blue" style="font-size:10px">×${r.attempts}</span>` : '';
    return `<tr>
      <td class="mono">${(d.done-rec.length+i+1)}</td>
      <td>${(r.email||'').slice(0,32)||'--'}</td>
      <td><span class="badge ${cls(st)}">${st}</span>${att}</td>
      <td class="mono">${r.ms ?? '--'}</td>
      <td class="mono">${r.thread_cpu_ms ?? '--'}</td>
      <td class="mono">${r.slot ?? '--'}</td>
      <td class="mono">${r.http ?? '--'}</td>
      <td class="mono">${r.ec ?? '--'}</td>
      <td style="color:#6b7280;font-size:11.5px;max-width:340px;overflow:hidden;
          text-overflow:ellipsis" title="${(r.detail||'').replace(/"/g,'&quot;')}">
        ${(r.detail||'--').slice(0,64)}</td>
    </tr>`;
  }).join('') : `<tr><td colspan="9" style="text-align:center;color:#9ca3af;padding:24px">
    ${want === 'all' ? '还没有结果' : '这个分类下没有结果'}</td></tr>`;
}

async function loadAccounts(path){
  const q = path ? ('&path='+encodeURIComponent(path)) : '';
  const a = await (await fetch('/api/accounts?t='+Date.now()+q)).json();
  renderAccounts(a);
}
loadAccounts(); tick(); setInterval(tick, 1000);
</script></body></html>"""


def main():
    global PYTHON
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8777)
    ap.add_argument('--host', default='0.0.0.0', help='监听地址，默认对外')
    ap.add_argument('--password', default=os.environ.get('GSA_PASSWORD', 'mtx123'),
                    help='控制台密码，默认 mtx123')
    ap.add_argument('--accounts', default=None,
                    help='账号文件；不传时自动恢复最后一次上传')
    ap.add_argument('--python', default=PYTHON)
    args = ap.parse_args()
    STATE['accounts'] = args.accounts or _startup_accounts()
    PYTHON = args.python
    if not os.path.exists(PYTHON):
        print(f'警告: 找不到解释器 {PYTHON}')
    global PASSWORD
    PASSWORD = args.password or 'mtx123'
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'控制台: http://{args.host}:{args.port}   密码: {PASSWORD}')
    print(f'账号文件: {STATE["accounts"]}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_job()
        server.shutdown()


if __name__ == '__main__':
    main()
