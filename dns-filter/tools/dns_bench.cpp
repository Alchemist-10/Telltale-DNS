// Closed-loop DNS load generator: each thread sends one query, waits for the reply, repeats.
// Usage: ./dns_bench [--server 127.0.0.1:5300] [--threads 8] [--duration 10] [--mode hit|block|unique]
//   hit    : 100 fixed names (cache warmed first)     -> measures the cache-hit path
//   block  : many subdomains of blocked.example       -> measures the blocklist/sinkhole path
//   unique : a never-seen name every time             -> measures the full forward path (cold cache)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

static size_t build_query(uint8_t* b, const std::string& name, uint16_t id) {
    b[0] = id >> 8; b[1] = id & 0xFF; b[2] = 0x01; b[3] = 0x00; b[4] = 0; b[5] = 1;
    std::memset(b + 6, 0, 6);
    size_t off = 12, start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        b[off++] = uint8_t(dot - start);
        std::memcpy(b + off, name.data() + start, dot - start);
        off += dot - start;
        start = dot + 1;
    }
    b[off++] = 0; b[off++] = 0; b[off++] = 1; b[off++] = 0; b[off++] = 1;
    return off;
}

struct Result {
    std::vector<uint32_t> lat_us;
    uint64_t noerror = 0, nxdomain = 0, servfail = 0, other = 0, errors = 0;
};

int main(int argc, char** argv) {
    std::string host = "127.0.0.1", mode = "hit";
    int port = 5300, threads = 8, duration = 10;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { if (i + 1 >= argc) std::exit(2); return argv[++i]; };
        if (a == "--server") {
            std::string s = next(); size_t c = s.find(':');
            host = s.substr(0, c); if (c != std::string::npos) port = std::atoi(s.c_str() + c + 1);
        } else if (a == "--threads") threads = std::atoi(next().c_str());
        else if (a == "--duration") duration = std::atoi(next().c_str());
        else if (a == "--mode") mode = next();
        else { std::fprintf(stderr, "bad arg %s\n", a.c_str()); return 2; }
    }

    sockaddr_in srv{};
    srv.sin_family = AF_INET; srv.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &srv.sin_addr);

    auto open_sock = [&]() {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        timeval tv{1, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        connect(s, (sockaddr*)&srv, sizeof(srv));
        return s;
    };

    if (mode == "hit") {  // warm the cache so the measured run is (almost) all hits
        int s = open_sock(); uint8_t q[512], r[4096];
        for (int i = 0; i < 100; i++) {
            size_t n = build_query(q, "host" + std::to_string(i) + ".bench.test", 1);
            send(s, q, n, 0); recv(s, r, sizeof(r), 0);
        }
        close(s);
    }

    std::vector<Result> results(threads);
    std::atomic<bool> go{false};
    auto end_time = Clock::now() + std::chrono::seconds(duration) + std::chrono::milliseconds(200);

    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        pool.emplace_back([&, t] {
            Result& R = results[t];
            R.lat_us.reserve(1 << 20);
            int s = open_sock();
            std::mt19937 rng(12345 + t);
            uint8_t q[512], r[4096];
            uint64_t counter = 0;
            while (!go) std::this_thread::yield();
            while (Clock::now() < end_time) {
                std::string name;
                if (mode == "hit") name = "host" + std::to_string(rng() % 100) + ".bench.test";
                else if (mode == "block") name = "x" + std::to_string(rng() % 100000) + ".blocked.example";
                else name = "u" + std::to_string(t) + "-" + std::to_string(counter++) + ".bench.test";
                uint16_t id = uint16_t(rng());
                size_t n = build_query(q, name, id);
                auto t0 = Clock::now();
                send(s, q, n, 0);
                ssize_t rn = recv(s, r, sizeof(r), 0);
                auto t1 = Clock::now();
                if (rn < 12 || r[0] != (id >> 8) || r[1] != (id & 0xFF)) { R.errors++; continue; }
                R.lat_us.push_back(uint32_t(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));
                switch (r[3] & 0xF) { case 0: R.noerror++; break; case 3: R.nxdomain++; break;
                                      case 2: R.servfail++; break; default: R.other++; }
            }
            close(s);
        });
    }
    auto t_start = Clock::now();
    end_time = t_start + std::chrono::seconds(duration);
    go = true;
    for (auto& th : pool) th.join();
    double secs = std::chrono::duration<double>(Clock::now() - t_start).count();

    std::vector<uint32_t> all;
    Result tot;
    for (auto& R : results) {
        all.insert(all.end(), R.lat_us.begin(), R.lat_us.end());
        tot.noerror += R.noerror; tot.nxdomain += R.nxdomain; tot.servfail += R.servfail;
        tot.other += R.other; tot.errors += R.errors;
    }
    std::sort(all.begin(), all.end());
    auto pct = [&](double p) { return all.empty() ? 0u : all[std::min(all.size() - 1, size_t(p * all.size()))]; };

    std::printf("mode=%s threads=%d duration=%.1fs server=%s:%d\n", mode.c_str(), threads, secs, host.c_str(), port);
    std::printf("replies=%zu  QPS=%.0f  timeouts/bad=%lu\n", all.size(), all.size() / secs, (unsigned long)tot.errors);
    std::printf("latency (us): p50=%u  p95=%u  p99=%u  max=%u\n", pct(0.50), pct(0.95), pct(0.99), all.empty() ? 0u : all.back());
    std::printf("rcodes: NOERROR=%lu NXDOMAIN=%lu SERVFAIL=%lu other=%lu\n",
                (unsigned long)tot.noerror, (unsigned long)tot.nxdomain, (unsigned long)tot.servfail, (unsigned long)tot.other);
    return 0;
}
