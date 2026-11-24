#!/bin/bash
# SRP 性能诊断：拆开 srp_challenge 的 17ms
# 用法：bash bench-srp.sh

cd "$(dirname "$0")" || exit 1

WPID=$(pgrep -f "web\.py.*--port" | head -1)
if [ -n "$WPID" ]; then
  PY=$(readlink -f /proc/$WPID/exe 2>/dev/null || true)
fi
if [ -z "$PY" ] || [ ! -x "$PY" ]; then
  for c in .venv/bin/python \
           /www/server/pyporject_evn/versions/*/bin/python3* \
           /www/server/python_manager/versions/*/bin/python3* \
           "$(command -v python3)"; do
    [ -x "$c" ] || continue
    if $c -c "import gmpy2" 2>/dev/null; then PY="$c"; break; fi
  done
fi
[ -x "$PY" ] || { echo "找不到装了 gmpy2 的解释器"; exit 1; }

echo "解释器: $PY"
echo

"$PY" - <<'PYEOF'
import sys, time, secrets
sys.path.insert(0, '.')

try:
    import gmpy2
    print(f'gmpy2 {gmpy2.version()}  GMP {gmpy2.mp_version()}  MPFR {gmpy2.mpfr_version()}')
except ImportError:
    gmpy2 = None
    print('gmpy2 未安装')

from fastcheck.protocols import srp_auth as S
print(f'SRP 后端: {S.SRP_MATH_BACKEND}   N 位数: {S.N.bit_length()}')
print()

def bench(label, fn, n=30):
    fn()                                  # 预热
    t0 = time.thread_time()
    for _ in range(n): fn()
    ms = (time.thread_time() - t0) / n * 1000
    print(f'  {label:<34} {ms:8.3f} ms')
    return ms

print('=== ① 大整数模幂（SRP 主运算）===')
x = secrets.randbits(256)
a = secrets.randbits(256)
u = secrets.randbits(256)
exp2 = a + u * x
base = secrets.randbits(2048) % S.N
t_g = bench('mod_pow(g=2, 256位指数, N)', lambda: S.mod_pow(S.g, x, S.N), 50)
t_big = bench('mod_pow(2048位底, 512位指数)', lambda: S.mod_pow(base, exp2, S.N), 20)
print()

print('=== ② 密码派生（PBKDF2，轮数由 Apple 返回）===')
salt = secrets.token_bytes(16)
pw = 'Password123'
for iters in (1000, 2000, 5000, 10000, 20000, 30000):
    t = bench(f's2k_fo(iters={iters})', lambda i=iters: S.s2k_fo(pw, salt, i), 5)
print()

print('=== ③ 哈希与小转换 ===')
bench('H(32B, 32B)', lambda: S.H(b'x'*32, b'y'*32), 500)
bench('b2i(256B)', lambda: S.b2i(secrets.token_bytes(256)), 500)
big = secrets.randbits(2048)
bench('i2b(2048位)', lambda: S.i2b(big), 500)
print()

print('=== ④ 组合：模拟 process_challenge（不含网络）===')
class FakeSRP:
    pass
for iters in (10000, 20000):
    def one(i=iters):
        B_bytes = secrets.token_bytes(256)
        B = S.b2i(B_bytes)
        uu = S.b2i(S.H(base and base.to_bytes(256, 'big'), B_bytes))
        P_key = S.s2k_fo(pw, salt, i)
        inner = S.H(b':', P_key)
        xx = S.b2i(S.H(salt, inner))
        S.mod_pow((B - 3 * S.mod_pow(S.g, xx, S.N)) % S.N, a + uu * xx, S.N)
    bench(f'process_challenge 等价(iters={iters})', one, 10)
print()

print('=== ⑤ CPU / OpenSSL 信息 ===')
try:
    import ssl
    print(f'  OpenSSL: {ssl.OPENSSL_VERSION}')
except Exception:
    pass
import platform
print(f'  CPU: {platform.processor() or platform.machine()}')
try:
    with open('/proc/cpuinfo') as f:
        for line in f:
            if line.startswith('model name'):
                print(f'  {line.strip()}'); break
except OSError:
    pass
PYEOF
