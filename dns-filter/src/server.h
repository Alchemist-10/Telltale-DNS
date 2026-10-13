#pragma once
#include <netinet/in.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "blocklist.h"
#include "cache.h"
#include "detector.h"
#include "dns_packet.h"
#include "logger.h"

struct ServerConfig {
    int port = 5300;
    std::string upstream_ip = "8.8.8.8";
    int upstream_port = 53;
    int threads = 4;
    size_t queue_capacity = 1024;
    int upstream_timeout_ms = 2000;
    SinkholeMode sinkhole = SinkholeMode::NxDomain;
    bool block_tunneling = false;  // false = flag + log only
};

struct ServerStats {
    std::atomic<uint64_t> received{0}, forwarded{0}, blocked{0}, cache_hits{0},
        upstream_timeouts{0}, malformed{0}, overload_drops{0}, flagged{0}, tunnel_blocked{0};
};

// One receiver thread (run()) pushes packets onto a bounded queue; N worker threads pop
// them and run: parse -> blocklist -> cache -> upstream -> reply.
class Server {
public:
    Server(const ServerConfig& cfg, BlocklistHolder& bl, DnsCache& cache, Logger& log,
           TunnelDetector* detector = nullptr);
    ~Server();

    bool start();                                       // bind socket + spawn workers
    void run(const volatile std::sig_atomic_t& running);// receive loop; returns when running == 0
    void stop();                                        // drain queue, join workers
    const ServerStats& stats() const { return stats_; }

private:
    struct Job {
        sockaddr_in client;
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point received;
    };

    void worker_loop();
    void handle(const Job& job, int upstream_sock);
    ssize_t forward(int upstream_sock, const std::vector<uint8_t>& pkt, uint8_t* reply, size_t cap);
    void send_to_client(const std::vector<uint8_t>& pkt, const sockaddr_in& client);

    ServerConfig cfg_;
    BlocklistHolder& blocklist_;
    DnsCache& cache_;
    Logger& logger_;
    TunnelDetector* detector_;  // may be null (detection disabled)

    int srv_ = -1;
    sockaddr_in up_addr_{};

    std::vector<std::thread> workers_;
    std::queue<Job> queue_;
    std::mutex qm_;
    std::condition_variable cv_;
    bool stop_ = false;
    bool stopped_ = false;

    ServerStats stats_;
};
