#!/usr/bin/env bash
# Compare decode_pcap output with tshark (Wireshark CLI) for ASTERIX pcaps.
# Usage: from repo root, ./scripts/compare_wireshark.sh [pcap_dir]
# Requires: decode_pcap (cargo build --bin decode_pcap), tshark (Wireshark).

set -e
cd "$(dirname "$0")/.."
PCAP_DIR="${1:-assets}"
DSL="${DSL:-examples/asterix_family.dsl}"
BIN="target/debug/decode_pcap"
[ ! -x "$BIN" ] && BIN="target/release/decode_pcap"

echo "=== ASTERIX decode_pcap vs tshark ==="
echo "Pcap dir: $PCAP_DIR  DSL: $DSL"
echo ""

for pcap in "$PCAP_DIR"/*.pcap; do
  [ -f "$pcap" ] || continue
  name=$(basename "$pcap")
  echo "--- $name ---"

  # Our decoder (stderr has the summary)
  ours=$("$BIN" "$pcap" "$DSL" 2>&1) || true
  echo "Our decoder:"
  echo "$ours" | sed 's/^/  /'

  # tshark: count packets with ASTERIX and show block summary
  if command -v tshark >/dev/null 2>&1; then
    echo "Tshark (ASTERIX):"
    # One line per packet; each line can have "category" or "cat1,cat2"
    tshark -r "$pcap" -Y "asterix" -T fields -e asterix.category -e asterix.length 2>/dev/null | head -5 | sed 's/^/  /'
    n=$(tshark -r "$pcap" -Y "asterix" 2>/dev/null | wc -l | tr -d ' ')
    echo "  (packets with ASTERIX: $n)"
  else
    echo "  (tshark not found, skip comparison)"
  fi
  echo ""
done

echo "=== Inconsistencies / notes ==="
echo "1. cat_001_002.pcap: First 3 bytes are 00 4e 02 (Category 0, Length 19970). Payload 223 bytes."
echo "   We reject (block would be 19970 bytes > 223). Tshark shows 'Category 000 Length 19970' without validating."
echo "2. cat_034_048.pcap: Block count matches tshark. We decode 340 records (4 CAT034, 336 CAT048), remove 106 (truncated/short records: i034_120 or i048_050 buffer underrun)."
echo "3. asterix.pcap / cat_062_065.pcap: We skip CAT062/CAT065 (not in DSL); tshark may decode if dissector present."
