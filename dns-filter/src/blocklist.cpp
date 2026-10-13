#include "blocklist.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <vector>

void Blocklist::add(const std::string& domain) {
    std::string d;
    for (char c : domain) d.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    while (!d.empty() && d.back() == '.') d.pop_back();
    if (!d.empty()) set_.insert(d);
}

long Blocklist::load_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return -1;

    static const char* skip[] = {"localhost", "localhost.localdomain", "local", "broadcasthost",
                                 "ip6-localhost", "ip6-loopback", "0.0.0.0"};
    long added = 0;
    std::string line;
    while (std::getline(in, line)) {
        size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);

        std::istringstream ss(line);
        std::vector<std::string> tok;
        for (std::string t; ss >> t;) tok.push_back(t);
        if (tok.empty()) continue;

        // hosts format: "<ip> <domain>"; plain format: "<domain>"
        std::string domain = (tok.size() >= 2) ? tok[1] : tok[0];

        std::string lower;
        for (char c : domain) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        while (!lower.empty() && lower.back() == '.') lower.pop_back();
        if (lower.empty()) continue;
        if (std::find(std::begin(skip), std::end(skip), lower) != std::end(skip)) continue;

        size_t before = set_.size();
        set_.insert(lower);
        if (set_.size() > before) added++;
    }
    return added;
}

bool Blocklist::is_blocked(const std::string& qname, std::string* matched) const {
    // Test "a.b.evil.com", then "b.evil.com", then "evil.com", then "com".
    size_t pos = 0;
    for (;;) {
        auto it = set_.find(qname.substr(pos));
        if (it != set_.end()) {
            if (matched) *matched = *it;
            return true;
        }
        size_t dot = qname.find('.', pos);
        if (dot == std::string::npos) return false;
        pos = dot + 1;
    }
}
