#pragma once
#include <cstdio>
#include <mutex>
#include <string>

// Thread-safe audit log: one line per query.
// Format: <time> | <client> | <domain> | <type> | <action> | <latency>us
class Logger {
public:
    Logger(const std::string& path, bool echo_to_stdout);
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void log(const std::string& client, const std::string& domain, const std::string& type,
             const std::string& action, long latency_us);

private:
    std::mutex m_;
    FILE* file_ = nullptr;
    bool echo_;
};
