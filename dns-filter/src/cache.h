#pragma once
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Sharded TTL cache. The key is hashed to one of N shards; each shard has its own mutex,
// so threads working on different keys rarely wait for each other.
class DnsCache {
public:
    explicit DnsCache(size_t shards = 16, size_t max_per_shard = 4096, int max_ttl_sec = 300);

    // On hit, copies the cached raw response into `out` and returns true. Expired entries are removed.
    bool get(const std::string& key, std::vector<uint8_t>& out);

    // Stores a raw response for min(ttl_sec, max_ttl) seconds. ttl_sec <= 0 is ignored.
    void put(const std::string& key, const std::vector<uint8_t>& data, int ttl_sec);

    size_t size();

private:
    using Clock = std::chrono::steady_clock;
    struct Entry {
        std::vector<uint8_t> data;
        Clock::time_point expiry;
    };
    struct Shard {
        std::mutex m;
        std::unordered_map<std::string, Entry> map;
    };

    Shard& shard_for(const std::string& key);

    std::vector<Shard> shards_;
    size_t max_per_shard_;
    int max_ttl_;
};
