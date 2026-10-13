// DNS filtering resolver
// Usage: ./dns-filter [--port 5300] [--upstream 8.8.8.8[:53]] [--blocklist FILE]... [--threads 4]
//        [--sinkhole nxdomain|zero] [--log queries.log] [--timeout-ms 2000] [--quiet]
//        [--no-detect] [--block-tunneling] [--entropy 3.6] [--max-unique 50] [--window-sec 60]
//        [--allow-domain DOMAIN]...
// Send SIGHUP to reload all blocklist files without restarting:  kill -HUP <pid>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "blocklist.h"
#include "cache.h"
#include "detector.h"
#include "logger.h"
#include "server.h"

static volatile std::sig_atomic_t g_running = 1;
static std::atomic<int> g_reload{0};
static void on_term(int) { g_running = 0; }
static void on_hup(int) { g_reload.store(1); }

static void usage(const char* prog) {
    std::fprintf(stderr,
        "usage: %s [--port N] [--upstream IP[:PORT]] [--blocklist FILE]... [--threads N]\n"
        "          [--sinkhole nxdomain|zero] [--log FILE] [--timeout-ms N] [--quiet]\n"
        "          [--no-detect] [--block-tunneling] [--entropy X] [--max-unique N]\n"
        "          [--window-sec N] [--allow-domain DOMAIN]...\n", prog);
}

int main(int argc, char** argv) {
    ServerConfig cfg;
    DetectorConfig dcfg;
    std::vector<std::string> bl_paths, allow;
    std::string log_path = "queries.log";
    bool quiet = false, detect = true;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) { usage(argv[0]); std::exit(2); }
            return argv[++i];
        };
        if (a == "--port") cfg.port = std::atoi(next());
        else if (a == "--upstream") {
            std::string u = next();
            size_t colon = u.find(':');
            cfg.upstream_ip = u.substr(0, colon);
            if (colon != std::string::npos) cfg.upstream_port = std::atoi(u.c_str() + colon + 1);
        }
        else if (a == "--blocklist") bl_paths.push_back(next());
        else if (a == "--threads") cfg.threads = std::atoi(next());
        else if (a == "--sinkhole") {
            std::string m = next();
            if (m == "zero") cfg.sinkhole = SinkholeMode::ZeroIp;
            else if (m == "nxdomain") cfg.sinkhole = SinkholeMode::NxDomain;
            else { usage(argv[0]); return 2; }
        }
        else if (a == "--log") log_path = next();
        else if (a == "--timeout-ms") cfg.upstream_timeout_ms = std::atoi(next());
        else if (a == "--quiet") quiet = true;
        else if (a == "--no-detect") detect = false;
        else if (a == "--block-tunneling") cfg.block_tunneling = true;
        else if (a == "--entropy") dcfg.entropy_threshold = std::atof(next());
        else if (a == "--max-unique") dcfg.max_unique_subdomains = std::strtoul(next(), nullptr, 10);
        else if (a == "--window-sec") dcfg.window_ms = std::atoi(next()) * 1000;
        else if (a == "--allow-domain") allow.push_back(next());
        else { usage(argv[0]); return 2; }
    }
    if (cfg.threads < 1) cfg.threads = 1;
    if (bl_paths.empty()) bl_paths.push_back("blocklist.txt");

    struct sigaction sa{};
    sa.sa_handler = on_term;  // no SA_RESTART: recvfrom is interrupted by Ctrl+C
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    struct sigaction hup{};
    hup.sa_handler = on_hup;
    sigaction(SIGHUP, &hup, nullptr);

    // Loads every blocklist/threat-feed file into one fresh Blocklist.
    auto build_blocklist = [&]() {
        auto b = std::make_shared<Blocklist>();
        for (const auto& p : bl_paths) {
            long n = b->load_file(p);
            if (n < 0) std::fprintf(stderr, "warning: could not open blocklist '%s'\n", p.c_str());
            else std::printf("  loaded %ld domains from %s\n", n, p.c_str());
        }
        return b;
    };
    BlocklistHolder holder(build_blocklist());

    DnsCache cache(16, 4096, 300);
    Logger logger(log_path, !quiet);

    TunnelDetector detector(dcfg);
    for (const auto& d : allow) detector.allow_domain(d);

    Server server(cfg, holder, cache, logger, detect ? &detector : nullptr);
    if (!server.start()) return 1;

    std::printf("dns-filter: UDP %d | upstream %s:%d | %d workers | %zu blocked domains | sinkhole=%s | "
                "detector=%s%s | log=%s\n",
                cfg.port, cfg.upstream_ip.c_str(), cfg.upstream_port, cfg.threads, holder.get()->size(),
                cfg.sinkhole == SinkholeMode::NxDomain ? "nxdomain" : "zero",
                detect ? "on" : "off", (detect && cfg.block_tunneling) ? "(blocking)" : "", log_path.c_str());

    std::fflush(stdout);

    // Small helper thread: waits for SIGHUP, then swaps in a freshly loaded blocklist.
    std::atomic<bool> stop_reloader{false};
    std::thread reloader([&] {
        while (!stop_reloader) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (g_reload.exchange(0)) {
                auto fresh = build_blocklist();
                holder.set(fresh);
                std::printf("blocklist reloaded: %zu domains\n", fresh->size());
                std::fflush(stdout);
            }
        }
    });

    server.run(g_running);
    stop_reloader = true;
    reloader.join();
    server.stop();

    const ServerStats& s = server.stats();
    std::printf("\n--- stats ---\nreceived=%lu forwarded=%lu blocked=%lu cache_hits=%lu "
                "upstream_timeouts=%lu malformed=%lu overload_drops=%lu flagged=%lu tunnel_blocked=%lu\n",
                (unsigned long)s.received, (unsigned long)s.forwarded, (unsigned long)s.blocked,
                (unsigned long)s.cache_hits, (unsigned long)s.upstream_timeouts,
                (unsigned long)s.malformed, (unsigned long)s.overload_drops,
                (unsigned long)s.flagged, (unsigned long)s.tunnel_blocked);
    return 0;
}
