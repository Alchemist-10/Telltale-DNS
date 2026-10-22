#!/usr/bin/env bash
# One-command verification + metrics collection for Telltale-DNS.
# Usage: bash dns-filter/scripts/verify.sh [--bench] [--duration SECONDS] [--sanitize] (from repo root)
#   (no flags)   build + unit tests + integration test (+ real-upstream check if online)
#   --bench      also run the load benchmark (default 10 s per mode)
#   --sanitize   also run the integration test under ThreadSanitizer and ASan/UBSan
# Writes results/metrics.md (machine info, test counts, benchmark table, resume bullet draft)
# plus raw outputs in results/ and build_verify/.   Requires: g++, python3.
set -u
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "ERROR: this project uses Linux/POSIX sockets and cannot build under MSYS2/MinGW/Cygwin."
    echo "Run it inside WSL2 (Ubuntu) or on Linux/macOS instead. See the README."
    exit 2 ;;
esac

BENCH=0; SAN=0; DUR=10
while [ $# -gt 0 ]; do
  case "$1" in
    --bench) BENCH=1 ;;
    --sanitize) SAN=1 ;;
    --duration) shift; DUR="${1:-10}" ;;
  esac; shift
done
WORKERS=${WORKERS:-4}; CLIENTS=${CLIENTS:-8}

OUT=build_verify; RES=results; mkdir -p "$OUT" "$RES"
PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP+1)); }

echo "== 1. Required files =="
FILES="CMakeLists.txt ../README.md blocklist.txt .gitignore
src/main.cpp src/server.h src/server.cpp src/dns_packet.h src/dns_packet.cpp
src/blocklist.h src/blocklist.cpp src/cache.h src/cache.cpp src/logger.h src/logger.cpp
src/detector.h src/detector.cpp
tests/test_parser.cpp tests/test_phase2.cpp tests/test_detector.cpp tests/integration_test.py
tools/dns_bench.cpp tools/fake_upstream.cpp scripts/update_feeds.sh"
for f in $FILES; do [ -s "$f" ] && ok "$f" || bad "missing or empty: $f"; done

echo "== 2. Key features present in the code =="
chk() { grep -q "$2" "$1" 2>/dev/null && ok "$3" || bad "$3 (pattern '$2' not found in $1)"; }
chk src/dns_packet.cpp "parse_query"             "hand-written DNS query parser"
chk src/dns_packet.cpp "response_cache_ttl"      "TTL extraction from responses"
chk src/dns_packet.cpp "build_sinkhole_response" "sinkhole response builder"
chk src/blocklist.cpp  "is_blocked"              "suffix-matching blocklist"
chk src/blocklist.h    "BlocklistHolder"         "hot-reload blocklist holder"
chk src/cache.cpp      "std::hash<std::string>"  "sharded cache"
chk src/server.cpp     "cv_.wait"                "thread pool with condition variable"
chk src/detector.cpp   "shannon_entropy"         "entropy detector"
chk src/detector.cpp   "unique_in_window"        "sliding-window subdomain detector"
chk src/main.cpp       "SIGHUP"                  "SIGHUP reload"

echo "== 3. Build (g++ -std=c++17) =="
CXX="g++ -std=c++17 -Wall -Wextra -O2 -pthread"
build() { local name=$1; shift
  if $CXX "$@" -o "$OUT/$name" 2> "$OUT/$name.err"; then ok "build $name"
  else bad "build $name (see $OUT/$name.err)"; head -5 "$OUT/$name.err"; fi; }
LIB="src/dns_packet.cpp src/blocklist.cpp src/cache.cpp src/logger.cpp src/detector.cpp src/server.cpp"
build telltale-dns  src/main.cpp $LIB
build test_parser   tests/test_parser.cpp src/dns_packet.cpp
build test_phase2   tests/test_phase2.cpp src/dns_packet.cpp src/blocklist.cpp src/cache.cpp
build test_detector tests/test_detector.cpp src/detector.cpp
build dns_bench     tools/dns_bench.cpp
build fake_upstream tools/fake_upstream.cpp

echo "== 4. Unit tests =="
for t in test_parser test_phase2 test_detector; do
  if [ -x "$OUT/$t" ] && "$OUT/$t" > "$OUT/$t.out" 2>&1; then ok "$t: $(tail -1 "$OUT/$t.out")"
  else bad "$t (see $OUT/$t.out)"; fi
done

echo "== 5. Integration test (fake upstream, no internet needed) =="
INTEG="not run"
if [ -x "$OUT/telltale-dns" ] && python3 tests/integration_test.py "$OUT/telltale-dns" > "$OUT/integration.out" 2>&1; then
  INTEG=$(tail -1 "$OUT/integration.out"); ok "integration: $INTEG"
else INTEG="FAILED or not run"; bad "integration test (see $OUT/integration.out)"; [ -f "$OUT/integration.out" ] && grep FAIL "$OUT/integration.out" | head -3; fi

echo "== 6. Real upstream (needs internet; SKIP if unavailable) =="
REAL="not run (resolver did not build)"
if [ -x "$OUT/telltale-dns" ]; then
  "$OUT/telltale-dns" --port 5390 --blocklist blocklist.txt --quiet --log "$OUT/real.log" >/dev/null 2>&1 &
  SPID=$!; sleep 1
  R=$(python3 - <<'PY'
import socket, struct
q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    s.sendto(q, ("127.0.0.1", 5390)); d, _ = s.recvfrom(4096)
    print("OK" if (d[3] & 15) == 0 and struct.unpack(">H", d[6:8])[0] >= 1 else "EMPTY")
except Exception:
    print("NOREPLY")
PY
)
  kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
  if [ "$R" = "OK" ]; then REAL="passed (example.com resolved via 8.8.8.8)"; ok "example.com resolved through the real upstream 8.8.8.8"
  else REAL="skipped (no answer: offline or UDP/53 blocked)"; skip "no real answer ($R): offline, or UDP/53 to 8.8.8.8 blocked. Test on your own machine."; fi
fi

TSAN="not run (use --sanitize)"; ASAN="not run (use --sanitize)"
if [ "$SAN" = 1 ]; then
  echo "== 6b. Sanitizers (integration test under TSan and ASan/UBSan) =="
  for kind in thread address,undefined; do
    name="san_${kind%%,*}"
    if g++ -std=c++17 -g -O1 -fsanitize=$kind -pthread src/main.cpp $LIB -o "$OUT/$name" 2> "$OUT/$name.err"; then
      python3 tests/integration_test.py "$OUT/$name" > "$OUT/$name.out" 2>&1; rc=$?
      W=$(grep -ci "ThreadSanitizer\|AddressSanitizer\|runtime error" "$OUT/$name.out")
      if [ $rc -eq 0 ] && [ "$W" = "0" ]; then ok "integration under -fsanitize=$kind: clean"; R="clean"
      else bad "integration under -fsanitize=$kind (see $OUT/$name.out; if TSan says 'unexpected memory mapping' try: sudo sysctl vm.mmap_rnd_bits=28)"; R="issues found"; fi
    else bad "build with -fsanitize=$kind (see $OUT/$name.err)"; R="build failed"; fi
    [ "$kind" = thread ] && TSAN=$R || ASAN=$R
  done
fi

field() { grep -o "$2=[0-9]*" "$RES/bench_$1.txt" 2>/dev/null | head -1 | cut -d= -f2; }
if [ "$BENCH" = 1 ]; then
  echo "== 7. Benchmark ($WORKERS workers, $CLIENTS client threads, ${DUR}s per mode, local fake upstream) =="
  "$OUT/fake_upstream" 5399 >/dev/null 2>&1 & UP=$!
  "$OUT/telltale-dns" --port 5300 --upstream 127.0.0.1:5399 --threads "$WORKERS" --blocklist blocklist.txt --quiet --log "$OUT/bench.log" >/dev/null 2>&1 & SP=$!
  sleep 1
  for m in hit block unique; do
    "$OUT/dns_bench" --mode $m --threads "$CLIENTS" --duration "$DUR" > "$RES/bench_$m.txt"
    sed -n '2,3p' "$RES/bench_$m.txt" | sed "s/^/  [$m] /"
  done
  kill $SP $UP 2>/dev/null; wait $SP $UP 2>/dev/null
fi

# ---------- write results/metrics.md ----------
CPU=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//')
[ -z "$CPU" ] && CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)
CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo ?)
MEM=$(awk '/MemTotal/ {printf "%.0f GB", $2/1048576}' /proc/meminfo 2>/dev/null)
OSV=$(uname -sr); GCCV=$(g++ --version | head -1)
LOC=$(cat src/*.cpp src/*.h | wc -l)
{
echo "# Telltale-DNS: measured results"
echo
echo "Generated by scripts/verify.sh on $(date '+%Y-%m-%d %H:%M')."
echo
echo "## Machine (put this next to any benchmark number)"
echo "- CPU: $CPU ($CORES logical cores${MEM:+, $MEM RAM})"
echo "- OS: $OSV"
echo "- Compiler: $GCCV (-O2, C++17)"
echo
echo "## Code and tests"
echo "- Source size: $LOC lines of C++ in src/"
echo "- Unit tests: $(tail -1 $OUT/test_parser.out 2>/dev/null); $(tail -1 $OUT/test_phase2.out 2>/dev/null); $(tail -1 $OUT/test_detector.out 2>/dev/null)"
echo "- Integration test (fake upstream): $INTEG"
echo "- Real upstream (8.8.8.8): $REAL"
echo "- ThreadSanitizer: $TSAN"
echo "- AddressSanitizer + UBSan: $ASAN"
echo "- Verification script totals: $PASS passed, $FAIL failed, $SKIP skipped"
echo
if [ "$BENCH" = 1 ]; then
  echo "## Benchmark"
  echo "Setup: $WORKERS worker threads, $CLIENTS closed-loop client threads, ${DUR} s per mode, load generator + resolver + fake upstream on the same machine (resolver overhead only; no real network round-trips). The query log (flushed per line) and the tunneling detector were ON."
  echo
  echo "| Mode | QPS | p50 (us) | p95 (us) | p99 (us) | timeouts/bad |"
  echo "|---|---|---|---|---|---|"
  for m in hit block unique; do
    label=$([ $m = hit ] && echo "cache hit" || ([ $m = block ] && echo "blocked (sinkhole)" || echo "cold (forwarded, unique names)"))
    echo "| $label | $(field $m QPS) | $(field $m p50) | $(field $m p95) | $(field $m p99) | $(field $m timeouts/bad) |"
  done
  echo
  echo "## Resume bullet draft (numbers filled in from this run)"
  echo '```'
  echo "Built Telltale-DNS, a multithreaded DNS filtering resolver in C++17 (hand-parsed RFC 1035 packets, sharded TTL cache, blocklist sinkholing with SIGHUP hot reload); sustained $(field hit QPS) QPS at $(field hit p95) us p95 on the cache-hit path and $(field block QPS) QPS on the blocklist path in local load tests ($WORKERS workers, $CORES-core machine)."
  echo "Implemented a DNS-tunneling detector (label length, Shannon entropy, sliding-window unique-subdomain rate) with flag/block modes and audit logging; validated with unit and integration tests$([ "$TSAN" = clean ] && [ "$ASAN" = clean ] && echo " and ThreadSanitizer/ASan runs")."
  echo '```'
else
  echo "## Benchmark"
  echo "Not run. Re-run with: bash scripts/verify.sh --bench --duration 10"
fi
} > "$RES/metrics.md"

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
echo "Metrics written to $RES/metrics.md (raw benchmark output in $RES/bench_*.txt)"
[ "$FAIL" -eq 0 ]
