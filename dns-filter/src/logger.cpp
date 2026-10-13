#include "logger.h"
#include <ctime>

Logger::Logger(const std::string& path, bool echo) : echo_(echo) {
    file_ = std::fopen(path.c_str(), "a");
    if (!file_) std::fprintf(stderr, "warning: cannot open log file '%s'\n", path.c_str());
}

Logger::~Logger() {
    if (file_) std::fclose(file_);
}

void Logger::log(const std::string& client, const std::string& domain, const std::string& type,
                 const std::string& action, long latency_us) {
    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv;
    localtime_r(&t, &tmv);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    std::string line = std::string(ts) + " | " + client + " | " + domain + " | " + type + " | " +
                       action + " | " + std::to_string(latency_us) + "us\n";

    std::lock_guard<std::mutex> lk(m_);
    if (file_) { std::fputs(line.c_str(), file_); std::fflush(file_); }
    if (echo_) std::fputs(line.c_str(), stdout);
}
