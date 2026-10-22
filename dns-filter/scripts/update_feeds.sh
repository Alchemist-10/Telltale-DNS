#!/usr/bin/env bash
# Downloads a public threat/ad/malware host list into feeds/ (hosts format).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p feeds
curl -fsSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -o feeds/stevenblack.txt
echo "feeds/stevenblack.txt: $(grep -c '^0\.0\.0\.0 ' feeds/stevenblack.txt) entries"
echo
echo "Run with:  ./telltale-dns --blocklist blocklist.txt --blocklist feeds/stevenblack.txt"
echo "Reload without restart:  kill -HUP \$(pgrep telltale-dns)"
# Other feeds in hosts or plain one-domain-per-line format (for example abuse.ch's URLhaus)
# can be downloaded into feeds/ the same way and passed with another --blocklist flag.
