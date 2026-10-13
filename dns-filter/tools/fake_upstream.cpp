// Tiny UDP "upstream resolver" for benchmarking the resolver in isolation:
// answers every A query with 1.2.3.4 (TTL 60). Usage: ./fake_upstream [port=5399]
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    int port = argc > 1 ? std::atoi(argv[1]) : 5399;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    std::printf("fake upstream on 127.0.0.1:%d\n", port);

    uint8_t buf[4096];
    for (;;) {
        sockaddr_in c{}; socklen_t cl = sizeof(c);
        ssize_t n = recvfrom(s, buf, sizeof(buf) - 16, 0, (sockaddr*)&c, &cl);
        if (n < 12) continue;
        size_t off = 12;
        while (off < (size_t)n && buf[off] != 0) off += buf[off] + 1;
        off += 5;                                   // zero byte + QTYPE + QCLASS
        if (off > (size_t)n) continue;
        buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = 1; buf[8] = buf[9] = buf[10] = buf[11] = 0;
        const uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4};
        std::memcpy(buf + off, ans, sizeof(ans));
        sendto(s, buf, off + sizeof(ans), 0, (sockaddr*)&c, cl);
    }
}
