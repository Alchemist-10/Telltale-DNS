#include "dns_packet.h"
#include <algorithm>
#include <cctype>
#include <climits>

namespace {
constexpr size_t kHeaderLen = 12;
constexpr size_t kMaxLabel = 63;
constexpr size_t kMaxName = 255;
constexpr uint32_t kTtlCeiling = 86400;  // 1 day, keeps the value inside int

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline void wr16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v & 0xFF); }
inline void put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(uint8_t(x >> 8)); v.push_back(uint8_t(x & 0xFF)); }
inline void put32(std::vector<uint8_t>& v, uint32_t x) { put16(v, uint16_t(x >> 16)); put16(v, uint16_t(x & 0xFFFF)); }

// Skips one (possibly compressed) name in a *response*. Each step moves `off` forward,
// so it always terminates. Returns false if the name runs past the end of the packet.
bool skip_name(const uint8_t* b, size_t len, size_t& off) {
    for (;;) {
        if (off >= len) return false;
        uint8_t l = b[off];
        if (l == 0) { off++; return true; }
        if ((l & 0xC0) == 0xC0) {               // 2-byte compression pointer, name ends here
            if (off + 2 > len) return false;
            off += 2;
            return true;
        }
        if ((l & 0xC0) != 0) return false;      // reserved label type
        if (off + 1 + l > len) return false;
        off += 1 + l;
    }
}

// Copies header+question of the query and rewrites the flags for a reply.
std::vector<uint8_t> make_reply_base(const uint8_t* query, const DnsQuestion& q,
                                     uint8_t rcode, uint16_t ancount) {
    std::vector<uint8_t> r(query, query + q.question_end);
    // QR=1, keep opcode and RD from the query, RA=1, set RCODE
    uint16_t flags = 0x8000 | (q.flags & 0x7800) | (q.flags & 0x0100) | 0x0080 | (rcode & 0x0F);
    wr16(&r[2], flags);
    wr16(&r[6], ancount);  // ANCOUNT
    wr16(&r[8], 0);        // NSCOUNT
    wr16(&r[10], 0);       // ARCOUNT (we drop any EDNS OPT record from the query)
    return r;
}
}  // namespace

// ---------------------------------------------------------------- Phase 1
bool parse_query(const uint8_t* buf, size_t len, DnsQuestion& out, std::string& err) {
    if (len < kHeaderLen) { err = "packet shorter than 12-byte header"; return false; }

    out.id      = rd16(buf);
    out.flags   = rd16(buf + 2);
    out.qdcount = rd16(buf + 4);

    if (out.flags & 0x8000) { err = "QR bit set: this is a response, not a query"; return false; }
    if (out.qdcount != 1)   { err = "QDCOUNT must be 1"; return false; }

    size_t off = kHeaderLen;
    std::string name;
    size_t name_wire_len = 1;  // the terminating zero byte

    for (;;) {
        if (off >= len) { err = "truncated name"; return false; }
        uint8_t l = buf[off];

        if (l == 0) { off++; break; }
        if ((l & 0xC0) != 0) { err = "compression pointer not allowed in query question"; return false; }
        if (l > kMaxLabel) { err = "label longer than 63"; return false; }
        if (off + 1 + l > len) { err = "label runs past end of packet"; return false; }

        name_wire_len += 1 + l;
        if (name_wire_len > kMaxName) { err = "name longer than 255"; return false; }

        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < l; i++)
            name.push_back(static_cast<char>(std::tolower(buf[off + 1 + i])));
        off += 1 + l;
    }

    if (off + 4 > len) { err = "missing QTYPE/QCLASS"; return false; }
    out.qtype  = rd16(buf + off);
    out.qclass = rd16(buf + off + 2);
    out.question_end = off + 4;
    out.qname  = name.empty() ? "." : name;
    return true;
}

std::string qtype_to_string(uint16_t t) {
    switch (t) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 65:  return "HTTPS";
        case 255: return "ANY";
        default:  return "TYPE" + std::to_string(t);
    }
}

// ---------------------------------------------------------------- Phase 2
std::vector<uint8_t> build_sinkhole_response(const uint8_t* query, const DnsQuestion& q,
                                             SinkholeMode mode) {
    if (mode == SinkholeMode::NxDomain)
        return make_reply_base(query, q, /*rcode=*/3, /*ancount=*/0);

    // ZeroIp mode
    const bool is_a = (q.qtype == 1), is_aaaa = (q.qtype == 28);
    if (!is_a && !is_aaaa)
        return make_reply_base(query, q, 0, 0);  // NOERROR, no data

    auto r = make_reply_base(query, q, 0, 1);
    r.push_back(0xC0); r.push_back(0x0C);        // name = pointer to offset 12 (the question name)
    put16(r, q.qtype);
    put16(r, 1);                                 // class IN
    put32(r, 60);                                // TTL 60 s
    put16(r, is_a ? 4 : 16);                     // RDLENGTH
    r.insert(r.end(), is_a ? 4 : 16, 0);         // 0.0.0.0 or ::
    return r;
}

std::vector<uint8_t> build_servfail(const uint8_t* query, const DnsQuestion& q) {
    return make_reply_base(query, q, /*rcode=*/2, 0);
}

int response_cache_ttl(const uint8_t* b, size_t len) {
    if (len < kHeaderLen) return -1;
    uint16_t flags = rd16(b + 2);
    if (!(flags & 0x8000)) return -1;        // not a response
    if (flags & 0x0200) return -1;           // TC: truncated, client must retry over TCP
    if ((flags & 0x000F) != 0) return -1;    // error RCODE (NXDOMAIN, SERVFAIL, ...)

    uint16_t qd = rd16(b + 4), an = rd16(b + 6);
    if (an == 0) return -1;

    size_t off = kHeaderLen;
    for (uint16_t i = 0; i < qd; i++) {
        if (!skip_name(b, len, off)) return -1;
        if (off + 4 > len) return -1;
        off += 4;
    }

    uint32_t min_ttl = UINT32_MAX;
    for (uint16_t i = 0; i < an; i++) {
        if (!skip_name(b, len, off)) return -1;
        if (off + 10 > len) return -1;       // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        uint32_t ttl = rd32(b + off + 4);
        uint16_t rdlen = rd16(b + off + 8);
        off += 10;
        if (off + rdlen > len) return -1;
        off += rdlen;
        min_ttl = std::min(min_ttl, ttl);
    }
    return static_cast<int>(std::min(min_ttl, kTtlCeiling));
}

void set_id(std::vector<uint8_t>& pkt, uint16_t id) {
    if (pkt.size() >= 2) wr16(pkt.data(), id);
}
