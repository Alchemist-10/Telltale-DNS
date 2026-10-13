#include <cassert>
#include <chrono>
#include <cstdio>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "../src/detector.h"

using Clock = TunnelDetector::Clock;

static std::string random_base32(size_t n, unsigned seed) {
    static const char* abc = "abcdefghijklmnopqrstuvwxyz234567";
    std::mt19937 rng(seed);
    std::string s;
    for (size_t i = 0; i < n; i++) s.push_back(abc[rng() % 32]);
    return s;
}

static void test_entropy_and_base_domain() {
    assert(TunnelDetector::shannon_entropy("") == 0.0);
    assert(TunnelDetector::shannon_entropy("aaaaaaaa") == 0.0);
    assert(TunnelDetector::shannon_entropy("google") < 2.0);
    assert(TunnelDetector::shannon_entropy(random_base32(48, 1)) > 4.0);

    assert(TunnelDetector::base_domain("a.b.example.com") == "example.com");
    assert(TunnelDetector::base_domain("example.com") == "example.com");
    assert(TunnelDetector::base_domain("localhost") == "localhost");
    assert(TunnelDetector::base_domain("x.y.example.co.uk") == "example.co.uk");
    assert(TunnelDetector::base_domain("www.bbc.co.uk") == "bbc.co.uk");
}

static void test_benign_names_not_flagged() {
    TunnelDetector d;
    const char* ok[] = {"www.google.com", "mail.google.com", "api.github.com", "clients4.google.com",
                        "fonts.gstatic.com", "ocsp.digicert.com", "a.b.example.org",
                        "www.bbc.co.uk", "example.com", "d111111abcdef8.cloudfront.net",
                        "api-gateway.prod.internal.example.com", "update.googleapis.com"};
    for (auto n : ok) {
        Verdict v = d.analyze("10.0.0.1", n);
        if (v.flagged) std::printf("unexpected flag: %s -> %s\n", n, v.reason.c_str());
        assert(!v.flagged);
    }
}

static void test_static_signals() {
    TunnelDetector d;
    // long label
    Verdict v = d.analyze("c", std::string(50, 'a') + ".evil.com");
    assert(v.flagged && v.reason.find("long_label=50") != std::string::npos);
    // long total name made of short labels
    std::string longname;
    for (int i = 0; i < 12; i++) longname += "abcdefgh.";
    longname += "evil.com";
    v = d.analyze("c", longname);
    assert(v.flagged && v.reason.find("long_name=") != std::string::npos);
    // high entropy: base32 of 30 random bytes ~ a typical tunnel payload label
    v = d.analyze("c", random_base32(48, 7) + ".t.evil.com");
    assert(v.flagged && v.reason.find("entropy=") != std::string::npos);
    // hex payload (e.g. dnscat2-style) split across three labels: 48 hex chars, max entropy is 4.0
    std::mt19937 rng(11); std::string hex;
    for (int i = 0; i < 48; i++) hex.push_back("0123456789abcdef"[rng() % 16]);
    v = d.analyze("c", hex.substr(0, 16) + "." + hex.substr(16, 16) + "." + hex.substr(32) + ".evil.net");
    assert(v.flagged && v.reason.find("entropy=") != std::string::npos);
    // a short random-looking label is below the minimum length, so it is not judged (known blind spot)
    v = d.analyze("c", "x7qk9zpa2mwv.evil.org");
    assert(!v.flagged);
}

static void test_rate_signal() {
    DetectorConfig cfg; cfg.max_unique_subdomains = 50; cfg.window_ms = 60000;
    TunnelDetector d(cfg);
    auto t0 = Clock::now();

    for (int i = 0; i < 50; i++)   // exactly at the limit: not flagged
        assert(!d.analyze("10.0.0.5", "s" + std::to_string(i) + ".tun.example", t0 + std::chrono::milliseconds(i)).flagged);
    Verdict v = d.analyze("10.0.0.5", "s50.tun.example", t0 + std::chrono::milliseconds(50));
    assert(v.flagged && v.reason.find("unique_subdomains=51/60s") != std::string::npos);

    // the same names again do not add new uniques, but the window is still over the limit
    assert(d.analyze("10.0.0.5", "s1.tun.example", t0 + std::chrono::milliseconds(60)).flagged);

    // another client is tracked separately
    assert(!d.analyze("10.0.0.6", "s0.tun.example", t0 + std::chrono::milliseconds(70)).flagged);
    // another base domain from the same client is tracked separately
    assert(!d.analyze("10.0.0.5", "s0.other.example", t0 + std::chrono::milliseconds(80)).flagged);

    // 61 s later the old events have slid out of the window
    assert(!d.analyze("10.0.0.5", "fresh.tun.example", t0 + std::chrono::seconds(61)).flagged);
}

static void test_repeats_are_not_unique() {
    DetectorConfig cfg; cfg.max_unique_subdomains = 5;
    TunnelDetector d(cfg);
    auto t0 = Clock::now();
    for (int i = 0; i < 1000; i++)  // same name asked a thousand times (e.g. a real app polling)
        assert(!d.analyze("c", "www.example.com", t0 + std::chrono::milliseconds(i)).flagged);
}

static void test_allowlist() {
    TunnelDetector d;
    d.allow_domain("cdn.example");
    assert(!d.analyze("c", random_base32(48, 3) + ".cdn.example").flagged);
    assert(d.analyze("c", random_base32(48, 3) + ".other.example").flagged);
}

static void test_concurrent() {
    DetectorConfig cfg; cfg.max_unique_subdomains = 100000;
    TunnelDetector d(cfg);
    std::vector<std::thread> ts;
    for (int t = 0; t < 8; t++)
        ts.emplace_back([&, t] {
            for (int i = 0; i < 5000; i++)
                d.analyze("client" + std::to_string(t % 3), "n" + std::to_string(i % 700) + ".d" + std::to_string(i % 5) + ".example");
        });
    for (auto& t : ts) t.join();
}

int main() {
    test_entropy_and_base_domain();
    test_benign_names_not_flagged();
    test_static_signals();
    test_rate_signal();
    test_repeats_are_not_unique();
    test_allowlist();
    test_concurrent();
    std::puts("all detector tests passed");
    return 0;
}
