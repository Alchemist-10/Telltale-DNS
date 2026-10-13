#include "detector.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <functional>

TunnelDetector::TunnelDetector(DetectorConfig cfg) : cfg_(cfg), shards_(kShards) {}

void TunnelDetector::allow_domain(const std::string& d) { allow_.insert(d); }

double TunnelDetector::shannon_entropy(const std::string& s) {
    if (s.empty()) return 0.0;
    size_t counts[256] = {0};
    for (unsigned char c : s) counts[c]++;
    double h = 0.0;
    for (size_t n : counts) {
        if (!n) continue;
        double p = double(n) / double(s.size());
        h -= p * std::log2(p);
    }
    return h;
}

// Naive "registrable domain": last two labels, or last three for common two-level suffixes
// (co.uk, com.au, ...). A real implementation would use the Public Suffix List.
std::string TunnelDetector::base_domain(const std::string& q) {
    std::vector<size_t> dots;
    for (size_t i = 0; i < q.size(); i++) if (q[i] == '.') dots.push_back(i);
    if (dots.size() < 2) return q;

    auto label = [&](size_t from_end) {  // label counted from the right, 1 = TLD
        size_t end = (from_end == 1) ? q.size() : dots[dots.size() - from_end + 1];
        size_t start = dots[dots.size() - from_end] + 1;
        return q.substr(start, end - start);
    };
    std::string tld = label(1), sld = label(2);
    static const char* second_level[] = {"co", "com", "org", "net", "ac", "gov", "edu"};
    bool two_level = tld.size() == 2 &&
        std::find(std::begin(second_level), std::end(second_level), sld) != std::end(second_level);
    size_t keep = two_level ? 3 : 2;
    if (dots.size() < keep) return q;
    return q.substr(dots[dots.size() - keep] + 1);
}

size_t TunnelDetector::unique_in_window(const std::string& client, const std::string& base,
                                        const std::string& sub, Clock::time_point now) {
    const std::string key = client + "|" + base;
    Shard& sh = shards_[std::hash<std::string>{}(key) % kShards];
    const auto window = std::chrono::milliseconds(cfg_.window_ms);
    const auto cutoff = now - window;

    std::lock_guard<std::mutex> lk(sh.m);

    // Every 1024 calls, drop idle keys so memory can't grow forever.
    if (++sh.calls % 1024 == 0) {
        for (auto it = sh.states.begin(); it != sh.states.end();)
            it = (it->second.last < cutoff) ? sh.states.erase(it) : std::next(it);
    }

    State& st = sh.states[key];
    auto pop_front = [&] {
        auto c = st.counts.find(st.events.front().second);
        if (c != st.counts.end() && --c->second == 0) st.counts.erase(c);
        st.events.pop_front();
    };
    while (!st.events.empty() && st.events.front().first < cutoff) pop_front();  // slide the window
    while (st.events.size() >= kMaxEventsPerKey) pop_front();                    // hard memory cap

    st.events.emplace_back(now, sub);
    st.counts[sub]++;
    st.last = now;
    return st.counts.size();  // distinct subdomains currently inside the window
}

Verdict TunnelDetector::analyze(const std::string& client, const std::string& qname,
                                Clock::time_point now) {
    Verdict v;
    const std::string base = base_domain(qname);
    if (allow_.count(base)) return v;

    std::vector<std::string> reasons;
    char buf[64];

    // Signal 1: length
    size_t longest = 0, start = 0;
    while (start <= qname.size()) {
        size_t dot = qname.find('.', start);
        if (dot == std::string::npos) dot = qname.size();
        longest = std::max(longest, dot - start);
        start = dot + 1;
    }
    if (longest > cfg_.max_label_len) {
        std::snprintf(buf, sizeof(buf), "long_label=%zu", longest);
        reasons.push_back(buf);
    }
    if (qname.size() > cfg_.max_name_len) {
        std::snprintf(buf, sizeof(buf), "long_name=%zu", qname.size());
        reasons.push_back(buf);
    }

    // The part of the name an attacker controls: everything left of the base domain.
    if (qname.size() > base.size() + 1) {
        const std::string sub = qname.substr(0, qname.size() - base.size() - 1);

        // Signal 2: entropy of the subdomain characters (dots removed)
        std::string chars;
        for (char c : sub) if (c != '.') chars.push_back(c);
        if (chars.size() >= cfg_.entropy_min_len) {
            double h = shannon_entropy(chars);
            if (h > cfg_.entropy_threshold) {
                std::snprintf(buf, sizeof(buf), "entropy=%.2f", h);
                reasons.push_back(buf);
            }
        }

        // Signal 3: how many different subdomains of this base domain did this client ask for lately?
        size_t uniq = unique_in_window(client, base, sub, now);
        if (uniq > cfg_.max_unique_subdomains) {
            std::snprintf(buf, sizeof(buf), "unique_subdomains=%zu/%ds", uniq, cfg_.window_ms / 1000);
            reasons.push_back(buf);
        }
    }

    if (!reasons.empty()) {
        v.flagged = true;
        for (size_t i = 0; i < reasons.size(); i++) v.reason += (i ? "," : "") + reasons[i];
    }
    return v;
}
