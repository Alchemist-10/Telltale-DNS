#include "cache.h"
#include <algorithm>
#include <functional>

DnsCache::DnsCache(size_t shards, size_t max_per_shard, int max_ttl_sec)
    : shards_(std::max<size_t>(1, shards)),
      max_per_shard_(std::max<size_t>(1, max_per_shard)),
      max_ttl_(max_ttl_sec) {}

DnsCache::Shard& DnsCache::shard_for(const std::string& key) {
    return shards_[std::hash<std::string>{}(key) % shards_.size()];
}

bool DnsCache::get(const std::string& key, std::vector<uint8_t>& out) {
    Shard& s = shard_for(key);
    std::lock_guard<std::mutex> lk(s.m);   // lock only for the lookup + copy
    auto it = s.map.find(key);
    if (it == s.map.end()) return false;
    if (Clock::now() >= it->second.expiry) {
        s.map.erase(it);
        return false;
    }
    out = it->second.data;
    return true;
}

void DnsCache::put(const std::string& key, const std::vector<uint8_t>& data, int ttl_sec) {
    if (ttl_sec <= 0) return;
    ttl_sec = std::min(ttl_sec, max_ttl_);

    Shard& s = shard_for(key);
    std::lock_guard<std::mutex> lk(s.m);

    if (s.map.size() >= max_per_shard_ && s.map.find(key) == s.map.end()) {
        // Full: first drop expired entries, then (if still full) evict an arbitrary one.
        auto now = Clock::now();
        for (auto it = s.map.begin(); it != s.map.end();)
            it = (now >= it->second.expiry) ? s.map.erase(it) : std::next(it);
        if (s.map.size() >= max_per_shard_) s.map.erase(s.map.begin());
    }
    s.map[key] = Entry{data, Clock::now() + std::chrono::seconds(ttl_sec)};
}

size_t DnsCache::size() {
    size_t n = 0;
    for (auto& s : shards_) {
        std::lock_guard<std::mutex> lk(s.m);
        n += s.map.size();
    }
    return n;
}
