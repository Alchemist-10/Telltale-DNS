cmake_minimum_required(VERSION 3.10)
project(Telltale-DNS LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2)
find_package(Threads REQUIRED)

add_library(dnscore
    src/dns_packet.cpp src/blocklist.cpp src/cache.cpp src/logger.cpp src/detector.cpp src/server.cpp)
target_link_libraries(dnscore Threads::Threads)

add_executable(telltale-dns src/main.cpp)
target_link_libraries(telltale-dns dnscore)

# unit tests
add_executable(test_parser tests/test_parser.cpp)
target_link_libraries(test_parser dnscore)
add_executable(test_phase2 tests/test_phase2.cpp)
target_link_libraries(test_phase2 dnscore)
add_executable(test_detector tests/test_detector.cpp)
target_link_libraries(test_detector dnscore)

# benchmark tools
add_executable(dns_bench tools/dns_bench.cpp)
target_link_libraries(dns_bench Threads::Threads)
add_executable(fake_upstream tools/fake_upstream.cpp)
