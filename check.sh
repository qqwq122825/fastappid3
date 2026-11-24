#!/bin/bash
# 服务器一键诊断：自动找解释器、查代码版本、验证子进程能否启动
# 用法：bash check.sh

cd "$(dirname "$0")" || exit 1
echo "=============================================="
echo " GSA 服务器诊断  $(date '+%F %T')"
echo "=============================================="
echo

# ---------- 1. 找 web.py 和它的解释器 ----------
echo "【1】web.py 进程与解释器"
WEBPID=$(pgrep -f "web\.py.*--port" | head -1)
PY=""
if [ -n "$WEBPID" ]; then
  PY=$(readlink -f /proc/$WEBPID/exe 2>/dev/null || readlink /proc/$WEBPID/exe 2>/dev/null)
  [ -z "$PY" ] && PY=$(ps -o comm= -p "$WEBPID" 2>/dev/null)
  echo "  ✅ web.py 在跑  pid=$WEBPID"
  echo "  解释器: ${PY:-未知}"
  if [ -r /proc/$WEBPID/cmdline ]; then
    tr '\0' ' ' < /proc/$WEBPID/cmdline | sed 's/^/  命令: /'; echo
  else
    ps -o args= -p "$WEBPID" 2>/dev/null | sed 's/^/  命令: /'
  fi
else
  echo "  ⚠ web.py 没在跑（页面可能是缓存，Ctrl+Shift+R 强刷试试）"
fi

# 没找到就扫常见路径
if [ -z "$PY" ] || [ ! -x "$PY" ]; then
  for c in .venv/bin/python \
           /www/server/pyporject_evn/versions/*/bin/python3* \
           /www/server/python_manager/versions/*/bin/python3* \
           "$(which python3)"; do
    [ -x "$c" ] || continue
    if $c -c "import requests,gmpy2,websockets,socks" 2>/dev/null; then
      PY="$c"; echo "  → 找到依赖齐全的解释器: $PY"; break
    fi
  done
fi

if [ -z "$PY" ]; then
  echo "  ❌ 找不到装了 requests+gmpy2+websockets+socks 的解释器"
  echo "     装一下: python3 -m pip install requests PySocks gmpy2==2.3.2 websockets portalocker"
  exit 1
fi
echo

# ---------- 2. 依赖 ----------
echo "【2】依赖检查（用 $PY）"
for m in requests socks gmpy2 websockets portalocker; do
  if $PY -c "import $m" 2>/dev/null; then
    V=$($PY -c "import $m;print(getattr($m,'__version__','?'))" 2>/dev/null)
    printf "  ✅ %-14s %s\n" "$m" "$V"
  else
    printf "  ❌ %-14s 缺失\n" "$m"
  fi
done
echo

# ---------- 3. SRP 后端 ----------
echo "【3】SRP 后端（决定单条 CPU）"
SRP=$($PY -c "import sys;sys.path.insert(0,'.');from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND as b;print(b)" 2>&1 | tail -1)
if [ "$SRP" = "gmpy2" ]; then
  echo "  ✅ gmpy2（单条约 4ms）"
else
  echo "  ❌ $SRP（单条约 33ms，慢 8 倍）"
fi
echo

# ---------- 4. 代码版本 ----------
echo "【4】代码版本（关键：决定有没有 Client 缓存）"
for pat in cached_client device_profile otp_reuse item-timeout; do
  if grep -q -- "$pat" simple.py 2>/dev/null; then
    printf "  ✅ %-16s %s 处\n" "$pat" "$(grep -o -- "$pat" simple.py | wc -l)"
  else
    printf "  ❌ %-16s 0 处（旧代码）\n" "$pat"
  fi
done
echo "  simple.py: $(ls -la simple.py 2>/dev/null | awk '{print $6,$7,$8,$5"字节"}')"
echo

# ---------- 5. fastcheck ----------
echo "【5】包内 fastcheck"
if [ -d fastcheck ]; then
  echo "  ✅ 存在（$(find fastcheck -name '*.py' | wc -l) 个模块）"
  if grep -q "ssl_context" fastcheck/protocols/anisette_v3.py 2>/dev/null && \
     grep -q "VAR_KEYWORD" fastcheck/protocols/anisette_v3.py 2>/dev/null; then
    echo "  ✅ websockets 兼容分支已合入（12/15/17 都能跑）"
  else
    echo "  ❌ 缺 websockets 兼容分支（会报 unexpected keyword 'ssl'）"
  fi
else
  echo "  ❌ 没有 fastcheck/ 目录"
fi
echo

# ---------- 6. 子进程能否启动 ----------
echo "【6】子进程启动测试（跑 3 条）"
ACC=$(ls -t data/uploads/*.txt data/accounts.txt 2>/dev/null | head -1)
if [ -z "$ACC" ]; then
  echo "  ⚠ 没有账号文件，跳到权限检查"
else
  echo "  用: $ACC"
  TMPLOG=$(mktemp)
  TMO=$(command -v timeout || command -v gtimeout)
  if [ -n "$TMO" ]; then RUN="$TMO 120"; else RUN=""; fi
  $RUN $PY simple.py --accounts "$ACC" --threads 3 --limit 3 --per-ip 5 \
    --out /tmp/chk-$$.jsonl --live /tmp/chk-$$.json > "$TMPLOG" 2>&1
  RC=$?
  if [ $RC -eq 0 ]; then
    echo "  ✅ 子进程正常跑完 3 条"
    grep -E "^完成|状态（classify" "$TMPLOG" | sed 's/^/     /'
  else
    echo "  ❌ 子进程退出码 $RC，报错："
    grep -vE "Warning|warnings.warn" "$TMPLOG" | tail -12 | sed 's/^/     /'
  fi
  rm -f "$TMPLOG" /tmp/chk-$$.jsonl /tmp/chk-$$.json
fi
echo

# ---------- 7. 权限 ----------
echo "【7】权限"
OWNER=$(stat -c '%U:%G' data 2>/dev/null || stat -f '%Su:%Sg' data 2>/dev/null)
echo "  data/ 属主: $OWNER"
if [ "$OWNER" != "www:www" ]; then
  echo "  ⚠ 不是 www:www，若用 www 跑会写不进去 → chown -R www:www data"
fi
for d in data/devices data/uploads; do
  [ -d "$d" ] && echo "  ✅ $d" || echo "  ⚠ $d 不存在（首次跑会创建）"
done

# ---------- 8. 旧数据提示 ----------
echo
echo "【8】live.json 时间戳"
if [ -f data/live.json ]; then
  echo "  最后写入: $(stat -c '%y' data/live.json 2>/dev/null | cut -d. -f1 || stat -f '%Sm' data/live.json 2>/dev/null)"
  echo "  现在:     $(date '+%F %T')"
  echo "  （差太多说明页面显示的是旧数据，任务其实没在跑）"
else
  echo "  没有 live.json"
fi

echo
echo "=============================================="
echo " 结论"
echo "=============================================="
MISSING=""
$PY -c "import requests" 2>/dev/null || MISSING="$MISSING requests"
$PY -c "import gmpy2" 2>/dev/null    || MISSING="$MISSING gmpy2"
$PY -c "import websockets" 2>/dev/null || MISSING="$MISSING websockets"
$PY -c "import socks" 2>/dev/null    || MISSING="$MISSING PySocks"

if [ -n "$MISSING" ]; then
  echo "❌ 缺依赖:$MISSING"
  echo "   $PY -m pip install$MISSING"
elif [ "${SRP}" != "gmpy2" ]; then
  echo "❌ SRP 后端不是 gmpy2 → $PY -m pip install gmpy2==2.3.2"
elif [ "$(grep -c cached_client simple.py 2>/dev/null || echo 0)" -eq 0 ]; then
  echo "❌ simple.py 是旧版（无 Client 缓存）→ 解压新包覆盖"
  echo "   → 这就是单条 CPU 33ms 的原因"
else
  echo "✅ 环境正常。若页面仍显示旧数据，Ctrl+Shift+R 强刷。"
  echo "   建议线程配置: 2 进程 × 500 线程（每线程 2.7MB，4G 内存）"
fi
echo
