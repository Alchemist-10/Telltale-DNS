#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

#include "../src/blocklist.h"
#include "../src/cache.h"
#include "../src/dns_packet.h"

static std::vector<uint8_t> encode_name(const std::string& n) {
    std::vector<uint8_t> out;
    size_t start = 0;
    while (start <= n.size()) {
        size_t dot = n.find('.', start);
        if (dot == std::string::npos) dot = n.size();
        out.push_back(uint8_t(dot - start));
        out.insert(out.end(), n.begin() + start, n.begin() + dot);
        start = dot + 1;
    }
    out.push_back(0);
    return out;
}

static std::vector<uint8_t> make_query(const std::string& name, uint16_t qtype) {
    std::vector<uint8_t> p = {0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    auto nm = encode_name(name);
    p.insert(p.end(), nm.begin(), nm.end());
    p.push_back(qtype >> 8); p.push_back(qtype & 0xFF); p.push_back(0); p.push_back(1);
    return p;
}

static uint16_t u16(const std::vector<uint8_t>& v, size_t o) { return uint16_t((v[o] << 8) | v[o + 1]); }

static void test_blocklist() {
    Blocklist b;
    b.add("evil.com");
    std::string rule;
    assert(b.is_blocked("evil.com", &rule) && rule == "evil.com");
    assert(b.is_blocked("a.b.evil.com"));          // subdomains are blocked
    assert(!b.is_blocked("notevil.com"));          // not a label boundary
    assert(!b.is_blocked("evil.com.au"));
    assert(!b.is_blocked("good.org"));

    std::ofstream("/tmp/bl_test.txt") << "# comment\r\n0.0.0.0 ads.example\n127.0.0.1 localhost\n"
                                         "tracker.test  # trailing\n\nBAD.Test.\n";
    Blocklist c;
    assert(c.load_file("/tmp/bl_test.txt") == 3);
    assert(c.is_blocked("ads.example") && c.is_blocked("tracker.test") && c.is_blocked("bad.test"));
    assert(!c.is_blocked("localhost"));
    assert(c.load_file("/nonexistent/file") == -1);
}

static void test_sinkhole() {
    auto q = make_query("evil.com", 1);
    DnsQuestion dq; std::string err;
    assert(parse_query(q.data(), q.size(), dq, err));
    assert(dq.question_end == q.size());

    auto nx = build_sinkhole_response(q.data(), dq, SinkholeMode::NxDomain);
    assert(nx.size() == q.size());
    assert(u16(nx, 0) == 0xABCD);                    // same ID
    assert(nx[2] & 0x80);                            // QR=1
    assert((nx[3] & 0x0F) == 3);                     // NXDOMAIN
    assert(u16(nx, 6) == 0);

    auto z = build_sinkhole_response(q.data(), dq, SinkholeMode::ZeroIp);
    assert(z.size() == q.size() + 16);               // 2+2+2+4+2+4 = 16 bytes of answer
    assert((z[3] & 0x0F) == 0 && u16(z, 6) == 1);
    for (size_t i = z.size() - 4; i < z.size(); i++) assert(z[i] == 0);

    auto q6 = make_query("evil.com", 28);
    assert(parse_query(q6.data(), q6.size(), dq, err));
    auto z6 = build_sinkhole_response(q6.data(), dq, SinkholeMode::ZeroIp);
    assert(z6.size() == q6.size() + 28);

    auto qmx = make_query("evil.com", 15);
    assert(parse_query(qmx.data(), qmx.size(), dq, err));
    auto zm = build_sinkhole_response(qmx.data(), dq, SinkholeMode::ZeroIp);
    assert(zm.size() == qmx.size() && u16(zm, 6) == 0 && (zm[3] & 0x0F) == 0);

    auto sf = build_servfail(qmx.data(), dq);
    assert((sf[3] & 0x0F) == 2);
}

static std::vector<uint8_t> make_response(uint16_t flags, const std::vector<uint32_t>& ttls) {
    auto q = make_query("example.com", 1);
    q[2] = flags >> 8; q[3] = flags & 0xFF;
    q[6] = 0; q[7] = uint8_t(ttls.size());
    for (uint32_t t : ttls) {
        q.push_back(0xC0); q.push_back(0x0C);        // compressed name
        q.push_back(0); q.push_back(1); q.push_back(0); q.push_back(1);
        for (int s = 24; s >= 0; s -= 8) q.push_back(uint8_t(t >> s));
        q.push_back(0); q.push_back(4);
        for (int i = 0; i < 4; i++) q.push_back(uint8_t(i + 1));
    }
    return q;
}

static void test_ttl() {
    auto r = make_response(0x8180, {120, 30, 500});
    assert(response_cache_ttl(r.data(), r.size()) == 30);          // minimum over records
    auto nx = make_response(0x8183, {60});
    assert(response_cache_ttl(nx.data(), nx.size()) == -1);        // error RCODE
    auto tc = make_response(0x8380, {60});
    assert(response_cache_ttl(tc.data(), tc.size()) == -1);        // truncated
    auto noans = make_response(0x8180, {});
    assert(response_cache_ttl(noans.data(), noans.size()) == -1);  // no answers
    auto cut = make_response(0x8180, {60});
    assert(response_cache_ttl(cut.data(), cut.size() - 2) == -1);  // malformed (cut short)
    auto qr0 = make_response(0x0100, {60});
    assert(response_cache_ttl(qr0.data(), qr0.size()) == -1);      // not a response
}

static void test_cache() {
    DnsCache c(16, 100, 300);
    std::vector<uint8_t> out, v = {1, 2, 3};
    assert(!c.get("k", out));
    c.put("k", v, 1);
    assert(c.get("k", out) && out == v);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    assert(!c.get("k", out));                       // expired
    c.put("z", v, 0);
    assert(!c.get("z", out));                       // ttl 0 never cached

    DnsCache small(1, 2, 300);                      // eviction keeps size bounded
    for (int i = 0; i < 10; i++) small.put("key" + std::to_string(i), v, 60);
    assert(small.size() <= 2);

    DnsCache shared(16, 4096, 300);                 // hammer from many threads (run under TSan too)
    std::vector<std::thread> ts;
    for (int t = 0; t < 8; t++)
        ts.emplace_back([&, t] {
            std::vector<uint8_t> o;
            for (int i = 0; i < 5000; i++) {
                std::string k = "k" + std::to_string((i * 7 + t) % 300);
                shared.put(k, v, 30);
                shared.get(k, o);
            }
        });
    for (auto& t : ts) t.join();
    assert(shared.size() <= 300);
}

int main() {
    test_blocklist();
    test_sinkhole();
    test_ttl();
    test_cache();
    std::puts("all phase 2 unit tests passed");
    return 0;
}
