#include "server.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

using Clock = std::chrono::steady_clock;

Server::Server(const ServerConfig& cfg, BlocklistHolder& bl, DnsCache& cache, Logger& log,
               TunnelDetector* detector)
    : cfg_(cfg), blocklist_(bl), cache_(cache), logger_(log), detector_(detector) {}

Server::~Server() { stop(); }

bool Server::start() {
    srv_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_ < 0) { perror("socket"); return false; } 

    int rcvbuf = 1 << 20;  // absorb short bursts in the kernel
    setsockopt(srv_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    timeval tv{0, 500000};  // wake up every 0.5 s so run() can notice Ctrl+C
    setsockopt(srv_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(cfg_.port));
    if (bind(srv_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return false;
    }

    up_addr_.sin_family = AF_INET;
    up_addr_.sin_port = htons(static_cast<uint16_t>(cfg_.upstream_port));
    if (inet_pton(AF_INET, cfg_.upstream_ip.c_str(), &up_addr_.sin_addr) != 1) {
        std::fprintf(stderr, "bad upstream ip: %s\n", cfg_.upstream_ip.c_str());
        return false;
    }

    for (int i = 0; i < cfg_.threads; i++) workers_.emplace_back(&Server::worker_loop, this);
    return true;
}

void Server::run(const volatile std::sig_atomic_t& running) {
    uint8_t buf[4096];
    while (running) {
        sockaddr_in client{};
        socklen_t clen = sizeof(client);
        ssize_t n = recvfrom(srv_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&client), &clen);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvfrom");
            continue;
        }
        stats_.received++;

        bool queued = false;
        {
            std::lock_guard<std::mutex> lk(qm_);
            if (queue_.size() < cfg_.queue_capacity) {
                queue_.push(Job{client, std::vector<uint8_t>(buf, buf + n), Clock::now()});
                queued = true;
            }
        }
        if (queued) {
            cv_.notify_one();
        } else {  // queue full: shed load instead of growing without bound
            stats_.overload_drops++;
            char cip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client.sin_addr, cip, sizeof(cip));
            logger_.log(cip, "-", "-", "DROP_OVERLOAD", 0);
        }
    }
}

void Server::stop() {
    if (stopped_) return;
    stopped_ = true;
    {
        std::lock_guard<std::mutex> lk(qm_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_) t.join();
    workers_.clear();
    if (srv_ >= 0) { close(srv_); srv_ = -1; }
}

void Server::worker_loop() {
    // Each worker owns its upstream socket, so no socket is ever shared between threads.
    int up = socket(AF_INET, SOCK_DGRAM, 0);
    if (up < 0) { perror("socket(upstream)"); return; }
    timeval tv{cfg_.upstream_timeout_ms / 1000, (cfg_.upstream_timeout_ms % 1000) * 1000};
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(qm_);
            cv_.wait(lk, [&] { return stop_ || !queue_.empty(); });
            if (queue_.empty()) break;  // stop requested and nothing left to drain
            job = std::move(queue_.front());
            queue_.pop();
        }
        handle(job, up);  // lock is NOT held while we do (slow) network work
    }
    close(up);
}

void Server::send_to_client(const std::vector<uint8_t>& pkt, const sockaddr_in& client) {
    sendto(srv_, pkt.data(), pkt.size(), 0, reinterpret_cast<const sockaddr*>(&client), sizeof(client));
}

ssize_t Server::forward(int up, const std::vector<uint8_t>& pkt, uint8_t* reply, size_t cap) {
    if (sendto(up, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&up_addr_), sizeof(up_addr_)) < 0)
        return -1;

    auto deadline = Clock::now() + std::chrono::milliseconds(cfg_.upstream_timeout_ms);
    while (Clock::now() < deadline) {
        sockaddr_in from{};
        socklen_t flen = sizeof(from);
        ssize_t rn = recvfrom(up, reply, cap, 0, reinterpret_cast<sockaddr*>(&from), &flen);
        if (rn < 0) return -1;  // timeout or error
        bool same_src = from.sin_addr.s_addr == up_addr_.sin_addr.s_addr && from.sin_port == up_addr_.sin_port;
        bool same_id = rn >= 2 && reply[0] == pkt[0] && reply[1] == pkt[1];
        if (same_src && same_id) return rn;  // otherwise: stray/forged packet, keep waiting
    }
    return -1;
}

void Server::handle(const Job& job, int up) {
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &job.client.sin_addr, cip, sizeof(cip));
    auto latency = [&] {
        return static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - job.received).count());
    };

    // 1. parse
    DnsQuestion q;
    std::string err;
    if (!parse_query(job.data.data(), job.data.size(), q, err)) {
        stats_.malformed++;
        logger_.log(cip, "-", "-", "DROP_MALFORMED", latency());
        return;
    }
    const std::string type = qtype_to_string(q.qtype);

    // 2. blocklist -> sinkhole
    if (blocklist_.get()->is_blocked(q.qname)) {  // snapshot: safe even if SIGHUP swaps the list
        send_to_client(build_sinkhole_response(job.data.data(), q, cfg_.sinkhole), job.client);
        stats_.blocked++;
        logger_.log(cip, q.qname, type, "BLOCK", latency());
        return;
    }

    // 2b. DNS tunneling heuristics
    if (detector_) {
        Verdict v = detector_->analyze(cip, q.qname);
        if (v.flagged) {
            stats_.flagged++;
            if (cfg_.block_tunneling) {
                send_to_client(build_sinkhole_response(job.data.data(), q, cfg_.sinkhole), job.client);
                stats_.tunnel_blocked++;
                logger_.log(cip, q.qname, type, "BLOCK_TUNNEL(" + v.reason + ")", latency());
                return;
            }
            logger_.log(cip, q.qname, type, "FLAG(" + v.reason + ")", latency());  // then continue normally
        }
    }

    // 3. cache
    const std::string key = q.qname + "|" + std::to_string(q.qtype) + "|" + std::to_string(q.qclass);
    std::vector<uint8_t> cached;
    if (cache_.get(key, cached)) {
        set_id(cached, q.id);  // the cached bytes carry the ID of whoever asked first
        send_to_client(cached, job.client);
        stats_.cache_hits++;
        logger_.log(cip, q.qname, type, "CACHE_HIT", latency());
        return;
    }

    // 4. upstream
    uint8_t reply[4096];
    ssize_t rn = forward(up, job.data, reply, sizeof(reply));
    if (rn < 0) {
        send_to_client(build_servfail(job.data.data(), q), job.client);
        stats_.upstream_timeouts++;
        logger_.log(cip, q.qname, type, "UPSTREAM_TIMEOUT", latency());
        return;
    }

    int ttl = response_cache_ttl(reply, static_cast<size_t>(rn));
    if (ttl > 0) cache_.put(key, std::vector<uint8_t>(reply, reply + rn), ttl);

    send_to_client(std::vector<uint8_t>(reply, reply + rn), job.client);
    stats_.forwarded++;
    logger_.log(cip, q.qname, type, "ALLOW", latency());
}
