#include <cassert>
#include <cstdio>
#include <vector>
#include "../src/dns_packet.h"

// Builds a query packet for the given already-encoded name bytes.
static std::vector<uint8_t> make_query(const std::vector<uint8_t>& name, uint16_t qtype = 1,
                                       uint16_t qdcount = 1, uint16_t flags = 0x0100) {
    std::vector<uint8_t> p = {0x12, 0x34, uint8_t(flags >> 8), uint8_t(flags & 0xFF),
                              uint8_t(qdcount >> 8), uint8_t(qdcount & 0xFF), 0, 0, 0, 0, 0, 0};
    p.insert(p.end(), name.begin(), name.end());
    p.push_back(uint8_t(qtype >> 8)); p.push_back(uint8_t(qtype & 0xFF));
    p.push_back(0); p.push_back(1);
    return p;
}

int main() {
    DnsQuestion q; std::string err;

    // valid: 3www7example3com0 (mixed case to test lowercase)
    std::vector<uint8_t> name = {3,'W','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    auto ok = make_query(name);
    assert(parse_query(ok.data(), ok.size(), q, err));
    assert(q.qname == "www.example.com" && q.qtype == 1 && q.id == 0x1234);

    // truncated packet (cut in the middle of a label)
    assert(!parse_query(ok.data(), 16, q, err));
    // shorter than header
    assert(!parse_query(ok.data(), 5, q, err));
    // oversized label (64)
    std::vector<uint8_t> big = {64}; big.insert(big.end(), 64, 'a'); big.push_back(0);
    auto bad1 = make_query(big);
    assert(!parse_query(bad1.data(), bad1.size(), q, err));
    // compression pointer in question
    std::vector<uint8_t> ptr = {0xC0, 0x0C};
    auto bad2 = make_query(ptr);
    assert(!parse_query(bad2.data(), bad2.size(), q, err));
    // QDCOUNT = 2
    auto bad3 = make_query(name, 1, 2);
    assert(!parse_query(bad3.data(), bad3.size(), q, err));
    // response packet (QR=1) must be rejected
    auto bad4 = make_query(name, 1, 1, 0x8180);
    assert(!parse_query(bad4.data(), bad4.size(), q, err));

    std::puts("all parser tests passed");
    return 0;
}