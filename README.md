# Telltale-DNS

A multithreaded DNS security resolver in C++17 that sits between clients and an upstream resolver (such as 8.8.8.8),
**blocks malicious domains**, **caches answers by TTL**, **detects DNS tunneling**, and writes an
**audit log** of every query. DNS packets are parsed by hand from raw bytes (RFC 1035) with strict
bounds checking. No DNS libraries are used. Source code and build files are in [`dns-filter/`](dns-filter/).

```
                      +------------------------ Telltale-DNS process -------------------------+
                      |                                                                       |
 client --UDP query-->|  receiver thread --> bounded queue --> worker pool (N threads)        |
 (dig, apps)          |                                          |                            |
        <--reply------|                                          v                            |
                      |   parse + validate -> blocklist -> tunnel detector -> TTL cache       |
                      |                           |            |                 |            |
                      |                       sinkhole      flag / block      miss: forward --+--> upstream
                      |                                          \                |         |   (8.8.8.8)
                      |                                           +--> audit logger <        |
                      +-------------------------------------------------------------------------+
```

## Features
| Area | What it does |
|---|---|
| Packet parsing | Hand-written header and question parser; rejects truncated packets, labels over 63 bytes, names over 255 bytes, compression pointers in queries, QDCOUNT other than 1, and response packets sent as queries |
| Blocklist | Hash-set suffix matching: blocking `evil.com` also blocks `a.b.evil.com`. Accepts plain-domain and hosts-format files, so public threat feeds work. Several files can be combined |
| Hot reload | `kill -HUP <pid>` reloads every blocklist file with no downtime. Workers read an atomically swapped `shared_ptr` snapshot, so no lock sits on the query path |
| Sinkhole | `NXDOMAIN` (default), or `0.0.0.0` / `::` answers (`--sinkhole zero`) |
| Cache | 16 shards, each with its own mutex. TTL taken as the minimum over the answer records, capped at 300 s. Failures and truncated replies are not cached. The client's DNS ID is rewritten on a hit |
| Concurrency | One receiver thread, a bounded job queue (load is shed and logged as `DROP_OVERLOAD` when full), and a worker pool. Each worker owns its own upstream socket |
| Tunneling detector | Three signals (see below), with flag-only or blocking mode and a per-domain allowlist |
| Reliability | Upstream timeout answers `SERVFAIL`; upstream replies are accepted only from the right address with a matching ID; malformed packets are dropped and logged |
| Audit log | One line per query: `time | client | domain | type | action | latency` |

## Build and run (Linux / WSL2; not supported on native Windows / MinGW)

Start from the repository root:
```bash
cd dns-filter
sudo apt install -y build-essential cmake dnsutils
cmake -S . -B build
cmake --build build -j
cp blocklist.txt build/
cd build
./telltale-dns --threads 4            # listens on UDP 5300, upstream 8.8.8.8
```
Without CMake, run from `dns-filter/`: `g++ -std=c++17 -O2 -pthread src/*.cpp -o telltale-dns`.

With the resolver running in one terminal, use a second terminal from the repository root:
```bash
cd dns-filter/build
dig @127.0.0.1 -p 5300 example.com         # forwarded, then cached
dig @127.0.0.1 -p 5300 doubleclick.net     # NXDOMAIN (sinkholed)
tail -f queries.log
```

### Options
| Flag | Default | Meaning |
|---|---|---|
| `--port N` | 5300 | UDP port to listen on |
| `--upstream IP[:PORT]` | 8.8.8.8:53 | Upstream resolver |
| `--blocklist FILE` | blocklist.txt | Repeatable. Plain or hosts format |
| `--threads N` | 4 | Worker threads |
| `--sinkhole nxdomain\|zero` | nxdomain | Reply for blocked names |
| `--timeout-ms N` | 2000 | Upstream timeout |
| `--log FILE` / `--quiet` | queries.log / off | Log file; `--quiet` stops echoing to the terminal |
| `--no-detect` | detector on | Disable the tunneling detector |
| `--block-tunneling` | flag only | Sinkhole flagged queries |
| `--entropy X`, `--max-unique N`, `--window-sec N` | 3.6, 50, 60 | Detector thresholds |
| `--allow-domain D` | none | Repeatable. Never flag `D` or its subdomains |

### Threat feeds
Run `bash dns-filter/scripts/update_feeds.sh` from the repository root to download the StevenBlack hosts list (about 79k
domains, loads in well under a second, about 11 MB RSS). Then from `dns-filter/`, start the resolver with
`./telltale-dns --blocklist blocklist.txt --blocklist feeds/stevenblack.txt`; reload it with `kill -HUP $(pgrep telltale-dns)`.

## DNS tunneling detector
Attackers can smuggle data out through DNS names such as `<encoded-data>.evil.com`. Three independent signals:

1. **Length:** a label over 40 characters, or a whole name over 100 (the legal maximums are 63 and 253).
2. **Shannon entropy:** `H = -sum p(c) log2 p(c)` over the characters left of the base domain
   (checked only when there are at least 24 characters). Normal names score about 2 to 3.5 bits per
   character. Base32 and hex payloads score about 3.8 to 4.5.
3. **Rate:** the number of *distinct* subdomains of one base domain requested by one client inside a
   60 s sliding window (default limit 50). It uses a deque plus a count map, so each query is O(1)
   amortized, with sharded locks, idle-key cleanup, and a hard per-key memory cap.

Flagged queries are logged as `FLAG(long_label=48,entropy=4.41)`. With `--block-tunneling` they are
sinkholed and logged as `BLOCK_TUNNEL(...)`.

**Limits (heuristics, not proof):**
- *False positives:* CDNs, cloud providers, and some antivirus or telemetry services use random-looking
  names. Use `--allow-domain`. A long natural hostname can score about 3.65 bits per character, which is why
  the entropy check has a minimum length.
- *False negatives:* a slow, low-volume tunnel with short labels stays under every threshold. Short
  random labels (under 24 characters) are not judged at all.
- The base domain is the last two labels (three for suffixes such as `co.uk`). A production system would
  use the Public Suffix List.

## Tests
```bash
cd dns-filter/build
./test_parser && ./test_phase2 && ./test_detector          # unit tests
python3 ../tests/integration_test.py ./telltale-dns         # end to end, with a fake upstream (no internet)
```
The integration test starts several server instances against a local fake upstream and checks:
forwarding, caching and ID rewrite, blocking and subdomain matching, sinkhole modes, SERVFAIL on
timeout, survival of malformed packets, 500 concurrent queries, tunneling flag and block, the rate
signal, and SIGHUP reload.
One command runs everything (build, unit tests, integration test, a real-upstream check, optional
sanitizer runs and benchmark) and writes `results/metrics.md`:
```bash
bash dns-filter/scripts/verify.sh --bench --duration 10 --sanitize
```
The script writes the report to `dns-filter/results/metrics.md`.

## Benchmark
Closed-loop load generator (`tools/dns_bench.cpp`) against a local fake upstream (`tools/fake_upstream.cpp`).
This measures **resolver overhead only** and excludes real network round-trips to a public resolver.
Run these commands from the repository root:

```bash
cd dns-filter/build
./fake_upstream 5399 &
./telltale-dns --port 5300 --upstream 127.0.0.1:5399 --threads 4 --quiet &
./dns_bench --mode hit    --threads 8 --duration 10   # cache-hit path
./dns_bench --mode block  --threads 8 --duration 10   # blocklist / sinkhole path
./dns_bench --mode unique --threads 8 --duration 10   # cold path: every query is forwarded
```

**Measured on 2026-10-13:** Intel Core Ultra 5 125H laptop, WSL2 (Ubuntu 24.04), GCC 13.3, `-O2`, C++17.
4 resolver worker threads, 8 closed-loop client threads, 10 s per mode. Raw output is in `results/`.

| Mode | QPS | p50 | p95 | p99 | Timeouts |
|---|---|---|---|---|---|
| Cache hit | 35,902 | 196 us | 369 us | 511 us | 0 |
| Blocked (sinkhole) | 37,940 | 188 us | 343 us | 450 us | 0 |
| Cold (every query forwarded, unique names) | 13,983 | 554 us | 1,062 us | 1,358 us | 0 |

How to read these numbers:
- The load generator, resolver, and fake upstream all run on the same laptop and compete for CPU, so
  absolute throughput is conservative.
- The audit log writes and flushes one line per query and the tunneling detector is enabled. Both are
  included in these numbers. Buffered or asynchronous logging is the first optimization to try.
- The cold path is slower because every query is forwarded, parsed for its TTL, and inserted into the
  cache, while the detector tracks about 14K new names per second.
- Against a real upstream (8.8.8.8), a cold lookup took roughly 40 ms in manual testing, dominated by
  the network. A cache hit took about 0.5 to 1.2 ms.

## Sample audit log
Real lines from a manual run (`dig` against the resolver, upstream 8.8.8.8):
```
2026-10-12 16:15:06 | 127.0.0.1 | example.com | A | ALLOW | 45625us
2026-10-12 16:15:06 | 127.0.0.1 | example.com | A | CACHE_HIT | 1204us
2026-10-12 16:15:06 | 127.0.0.1 | doubleclick.net | A | BLOCK | 376us
2026-10-12 16:15:06 | 127.0.0.1 | aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk.evil.com | A | FLAG(long_label=44) | 618us
2026-10-12 16:15:33 | 127.0.0.1 | chunk51.exfil-site.org | A | FLAG(unique_subdomains=51/60s) | 96us
2026-10-12 16:15:18 | 127.0.0.1 | chunk27.exfil-site.org | A | UPSTREAM_TIMEOUT | 2006164us
```
A flagged query produces a `FLAG` line, then its normal line (`ALLOW`), because flag-only mode still
answers it. `UPSTREAM_TIMEOUT` means the client received `SERVFAIL` after the 2 s upstream timeout.

## Design decisions
- **Thread pool and bounded queue instead of thread-per-packet:** bounded memory and CPU under bursts, and
  load shedding instead of collapse.
- **Sharded cache:** threads asking about different names rarely contend for the same lock. No lock is held
  during upstream I/O.
- **Forward raw bytes, parse only what is needed:** less code to get wrong. Full parsing is limited to the
  question section and the answer TTLs.
- **Hot reload through an atomic `shared_ptr` swap:** readers never block, and the old list is freed when its last
  reader finishes.
- **Parser safety:** every read is bounds-checked, name walking always moves forward (no pointer loops), and the
  suite is sanitizer-clean.

## Limitations
- UDP and IPv4 only. Replies larger than the client's UDP size are relayed with the TC flag, and clients retry over
  TCP against the upstream directly, not through this resolver.
- Cached answers keep their original TTL values, so a client may hold one for up to about twice the TTL.
- No DNSSEC. Spoofing resistance is limited to checking the source address and ID of upstream replies.
- Cache eviction when full is arbitrary, not LRU.
- Heuristic detection (see above).
