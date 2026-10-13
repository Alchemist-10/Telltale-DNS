#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Result of parsing the header + single question of a DNS *query*.
struct DnsQuestion {
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t qdcount = 0;
    std::string qname;       // lowercase, dot-separated, no trailing dot ("." for root)
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    size_t question_end = 0; // byte offset just after QCLASS (end of the question section)
};

// What to answer for a blocked domain.
enum class SinkholeMode {
    NxDomain,  // RCODE=3 "domain does not exist"
    ZeroIp     // A -> 0.0.0.0, AAAA -> ::, other types -> empty NOERROR
};

// Phase 1: parse a query. Never reads outside [buf, buf+len).
bool parse_query(const uint8_t* buf, size_t len, DnsQuestion& out, std::string& err);
std::string qtype_to_string(uint16_t qtype);

// Phase 2: response builders. `query` must be the same bytes that parse_query accepted.
std::vector<uint8_t> build_sinkhole_response(const uint8_t* query, const DnsQuestion& q,
                                             SinkholeMode mode);
std::vector<uint8_t> build_servfail(const uint8_t* query, const DnsQuestion& q);

// Walks an upstream response and returns the minimum TTL (seconds) over its answer records.
// Returns -1 if the response must NOT be cached (not a response, truncated, error RCODE,
// no answers, or malformed).
int response_cache_ttl(const uint8_t* resp, size_t len);

// Overwrite the 2-byte DNS ID of a packet (used when replying from cache).
void set_id(std::vector<uint8_t>& pkt, uint16_t id);
