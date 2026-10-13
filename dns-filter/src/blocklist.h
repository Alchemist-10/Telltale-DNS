#pragma once
#include <memory>
#include <string>
#include <unordered_set>

// Domain blocklist with suffix matching: blocking "evil.com" also blocks "a.b.evil.com".
// Loaded once at startup and only read afterwards, so lookups need no locking.
class Blocklist {
public:
    // Loads a file in either "domain" or hosts ("0.0.0.0 domain") format.
    // Returns the number of domains added, or -1 if the file could not be opened.
    long load_file(const std::string& path);

    void add(const std::string& domain);

    // `qname` must already be lowercase. If blocked, `matched` (optional) gets the rule hit.
    bool is_blocked(const std::string& qname, std::string* matched = nullptr) const;

    size_t size() const { return set_.size(); }

private:
    std::unordered_set<std::string> set_;
};

// Lets the server swap in a freshly loaded blocklist (SIGHUP) without stopping or locking
// the query path: workers grab a shared_ptr snapshot; the old list is freed when the last
// worker using it finishes.
class BlocklistHolder {
public:
    explicit BlocklistHolder(std::shared_ptr<const Blocklist> b) : p_(std::move(b)) {}
    std::shared_ptr<const Blocklist> get() const { return std::atomic_load(&p_); }
    void set(std::shared_ptr<const Blocklist> b) { std::atomic_store(&p_, std::move(b)); }

private:
    std::shared_ptr<const Blocklist> p_;
};
