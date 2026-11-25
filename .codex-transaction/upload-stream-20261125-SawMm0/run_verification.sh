#!/bin/sh
set -eu
ART=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$ART/../.." && pwd)
TMP=$(mktemp -d)
trap 'find "$TMP" -depth -delete' EXIT INT TERM
run_case() {
  label=$1 source_file=$2 port=$3
  case_dir="$TMP/$label"; mkdir -p "$case_dir/data"; cp "$source_file" "$case_dir/web.py"
  (cd "$case_dir"; python3 web.py --host 127.0.0.1 --port "$port" --password testpass >server.stdout 2>server.stderr & echo $! >server.pid)
  pid=$(cat "$case_dir/server.pid"); i=0
  until curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; do i=$((i+1)); [ "$i" -lt 50 ] || return 1; sleep 0.05; done
  login_out=$(curl -sS -c "$case_dir/cookie" -H 'Content-Type: application/json' --data '{"password":"testpass"}' "http://127.0.0.1:$port/api/login"); login_status=$?
  printf 'alpha@example.com----pw\nbeta@example.com----pw2\n' > "$case_dir/fixture.txt"
  gzip -c "$case_dir/fixture.txt" > "$case_dir/fixture.txt.gz"
  raw_out=$(curl -sS -b "$case_dir/cookie" -H 'Content-Type: application/octet-stream' --data-binary @"$case_dir/fixture.txt" "http://127.0.0.1:$port/api/upload?name=raw.txt"); raw_status=$?
  gzip_out=$(curl -sS -b "$case_dir/cookie" -H 'Content-Type: application/octet-stream' -H 'Content-Encoding: gzip' --data-binary @"$case_dir/fixture.txt.gz" "http://127.0.0.1:$port/api/upload?name=gzip.txt"); gzip_status=$?
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  printf '%s_LOGIN_EXIT=%s\n%s_LOGIN_STDOUT=%s\n' "$label" "$login_status" "$label" "$login_out"
  printf '%s_RAW_EXIT=%s\n%s_RAW_STDOUT=%s\n' "$label" "$raw_status" "$label" "$raw_out"
  printf '%s_GZIP_EXIT=%s\n%s_GZIP_STDOUT=%s\n' "$label" "$gzip_status" "$label" "$gzip_out"
  printf '%s_SERVER_STDERR=%s\n' "$label" "$(cat "$case_dir/server.stderr")"
}
ORIGINAL_SHA=$(shasum -a 256 "$ART/web.py.baseline" | awk '{print $1}')
MODIFIED_SHA=$(shasum -a 256 "$ROOT/web.py" | awk '{print $1}')
printf 'ORIGINAL_SHA256=%s\nMODIFIED_SHA256=%s\n' "$ORIGINAL_SHA" "$MODIFIED_SHA"
run_case BASELINE "$ART/web.py.baseline" 18965
run_case MODIFIED "$ROOT/web.py" 18966
cp "$ROOT/web.py" "$TMP/rollback-copy.py"; "$ART/ROLLBACK.sh" "$TMP/rollback-copy.py"
ROLLBACK_SHA=$(shasum -a 256 "$TMP/rollback-copy.py" | awk '{print $1}')
printf 'ROLLBACK_SHA256=%s\nROLLBACK_MATCH=%s\n' "$ROLLBACK_SHA" "$( [ "$ROLLBACK_SHA" = "$ORIGINAL_SHA" ] && echo yes || echo no )"
run_case ROLLBACK "$TMP/rollback-copy.py" 18967
python3 -m py_compile "$ROOT/web.py"; printf 'PY_COMPILE_EXIT=0\n'
