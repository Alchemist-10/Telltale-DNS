#pragma once
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct DetectorConfig {
    size_t max_label_len = 40;           // longest single label before we call it suspicious (max legal is 63)
    size_t max_name_len = 100;           // total name length (max legal is 253)
    double entropy_threshold = 3.6;      // bits/char of the subdomain part
    size_t entropy_min_len = 24;         // short strings can't score high (and long natural hostnames reach ~3.6), so skip them
    size_t max_unique_subdomains = 50;   // per (client, base domain) inside the window
    int window_ms = 60000;               // sliding window length
};

struct Verdict {
    bool flagged = false;
    std::string reason;  // e.g. "long_label=52,entropy=4.41"
};

// DNS tunneling heuristics. Three independent signals:
//   1. long label / long name        (stateless)
//   2. high Shannon entropy          (stateless)
//   3. many unique subdomains of one base domain from one client in a sliding window (stateful)
// Thread-safe: the stateful part is split into shards, each with its own mutex.
class TunnelDetector {
public:
    using Clock = std::chrono::steady_clock;

    explicit TunnelDetector(DetectorConfig cfg = DetectorConfig());

    // Base domains (e.g. "cloudfront.net") that are never flagged. Call before serving traffic.
    void allow_domain(const std::string& base_domain);

    Verdict analyze(const std::string& client, const std::string& qname) {
        return analyze(client, qname, Clock::now());
    }
    Verdict analyze(const std::string& client, const std::string& qname, Clock::time_point now);

    static double shannon_entropy(const std::string& s);   // bits per character
    static std::string base_domain(const std::string& qname);

private:
    struct State {
        std::deque<std::pair<Clock::time_point, std::string>> events;
        std::unordered_map<std::string, int> counts;   // subdomain -> occurrences inside window
        Clock::time_point last;
    };
    struct Shard {
        std::mutex m;
        std::unordered_map<std::string, State> states; // key = client + "|" + base domain
        unsigned long calls = 0;
    };
    static constexpr size_t kShards = 16;
    static constexpr size_t kMaxEventsPerKey = 4096;   // memory cap per (client, domain)

    size_t unique_in_window(const std::string& client, const std::string& base,
                            const std::string& sub, Clock::time_point now);

    DetectorConfig cfg_;
    std::unordered_set<std::string> allow_;
    std::vector<Shard> shards_;
};
