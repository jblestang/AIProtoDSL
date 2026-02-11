#!/usr/bin/env bash
# Compare our decode_pcap text dump with tshark ASTERIX dump by byte offset.
# Identifies at which offset the two interpretations diverge.
# Usage: ./scripts/compare_dump_offsets.sh [frame_number]
# Default: frame 1 (CAT048 block). Requires: tshark, decode_pcap, assets.

set -e
cd "$(dirname "$0")/.."
FRAME="${1:-1}"
PCAP="${PCAP:-assets/cat_034_048.pcap}"
OUT_DIR="${OUT_DIR:-assets/failing_payload_048}"
mkdir -p "$OUT_DIR"

# Get block hex (48 bytes) for frame 1
HEX=$(tshark -r "$PCAP" -Y "frame.number==$FRAME" -T fields -e udp.payload 2>/dev/null | tr -d '\n\r')
BLOCK_HEX=$(echo "$HEX" | cut -c1-96)
# Data only (after cat+len+FSPEC): bytes 6-47 = 42 bytes = 84 hex chars
DATA_HEX=$(echo "$HEX" | cut -c13-96)

echo "=== CAT048 block frame $FRAME: offset comparison (our decoder vs tshark) ==="
echo ""

# Block layout: 0-2 cat+len, 3-5 FSPEC, 6-47 data (42 bytes)
echo "--- Block layout ---"
echo "  Offset 0-2:   Category + Length (3 bytes)"
echo "  Offset 3-5:   FSPEC = fd f7 02 (3 bytes)"
echo "  Offset 6-47:  Record data (42 bytes)"
echo ""

# Tshark item order (from tshark -O asterix): no I048/130 in this record
# Sizes (bytes): 010=2, 140=3, 020=1, 040=4, 070=2, 090=2, 220=3, 240=8, 250=1+8=9, 161=2, 200=4, 170=4, 230=2
# Sum = 2+3+1+4+2+2+3+8+9+2+4+4+2 = 46 -> tshark may use different sizes; 42 bytes total so some item shorter
# Use 040=3 (e.g. 24-bit) or 170=2: 2+3+1+3+2+2+3+8+9+2+4+2+2 = 41, still 41. 240=7: 2+3+1+4+2+2+3+7+9+2+4+2+2=41.
# 2+3+1+4+2+2+3+8+8+2+4+2+2 = 43 (250=1+7). So 42 = 2+3+1+4+2+2+3+8+8+2+4+2+2 - 1 = 42. So 250=8 (1+7) or 170=3.
TSHARK_ITEMS="010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 200:4 170:4 230:2"
# Our UAP order (spec): 010, 140, 020, 040, 070, 090, 130, FX, 220, 240, 250, 161, ...
# FSPEC fd = 11111101 -> bit 6 (7th presence) = (fd>>1)&1 = 0 -> 130 ABSENT
# So our items (130 absent): 010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 ...
OUR_ITEMS_NO130="010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 042:4 200:4 170:2 210:2"
# If 130 present: 010:2 140:3 020:1 040:4 070:2 090:2 130:7 220:3 240:8 250:9 161:2 ...
OUR_ITEMS_WITH130="010:2 140:3 020:1 040:4 070:2 090:2 130:7 220:3 240:8 250:9 161:2 042:4 200:4 170:2 210:2"

# Build offset table for a list "name:size name:size ..."
build_offsets() {
    local list="$1"
    local start=0
    while read -r item_size; do
        local name="${item_size%:*}"
        local size="${item_size#*:}"
        echo "  data_offset $start-$((start+size-1))  $name ($size bytes)"
        start=$((start + size))
    done <<< "$list"
}

echo "--- tshark interpretation (item order; no I048/130) ---"
echo "  Data offset = byte offset in record body (block offset - 6)."
off=0
for ent in 010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 200:4 170:4 230:2; do
    name="${ent%:*}"
    size="${ent#*:}"
    end=$((off+size-1))
    if [ $end -lt 42 ]; then
        echo "  data_offset $off-$end  I048/$name ($size bytes)"
    else
        echo "  data_offset $off-??  I048/$name ($size bytes)  [PAST END: only 42 data bytes]"
    fi
    off=$((off+size))
done
echo "  tshark total (spec sizes): $off bytes; actual record has 42 data bytes (tshark may use different sizes for 170/200/230)"
echo ""

echo "--- our decoder (UAP order; 130 ABSENT per FSPEC bit 6=0) ---"
off=0
for ent in 010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 042:4 200:4 170:2 210:2; do
    name="${ent%:*}"
    size="${ent#*:}"
    end=$((off+size-1))
    if [ $end -lt 42 ]; then
        echo "  data_offset $off-$end  i048_$name ($size bytes)"
    else
        echo "  data_offset $off-??  i048_$name ($size bytes)  [PAST END - FAIL HERE]"
    fi
    off=$((off+size))
done
echo "  our total (130 absent): $off bytes"
echo ""

echo "--- our decoder (if 130 PRESENT - wrong FSPEC read) ---"
off=0
for ent in 010:2 140:3 020:1 040:4 070:2 090:2 130:7 220:3 240:8 250:9 161:2; do
    name="${ent%:*}"
    size="${ent#*:}"
    end=$((off+size-1))
    if [ $end -lt 42 ]; then
        echo "  data_offset $off-$end  i048_$name ($size bytes)"
    else
        echo "  data_offset $off-??  i048_$name ($size bytes)  [PAST END - FAIL HERE]"
    fi
    off=$((off+size))
done
echo "  our total (130 present): $off bytes before 161; 161 needs 2, only 1 left -> REMOVED at i048_161"
echo ""

echo "--- DIVERGENCE ---"
echo "  Our decoder reports: REMOVED at i048_161 (TrackNumber.spare: failed to fill whole buffer)."
echo "  That means we have 1 byte left when starting I048/161 (2 bytes needed)."
echo "  So we consumed 41 data bytes before 161."
echo "  41 = 14 (010..090) + 7 (130) + 20 (220,240,250) -> we are decoding I048/130 (7 bytes) although FSPEC says absent."
echo "  Problem offset: data offset 14 (block offset 20). We incorrectly read bytes 14-20 as I048/130; tshark reads them as start of I048/040 (040 continues) / 070 / 090."
echo "  So the first offset where our interpretation differs is data_offset 14 (block offset 20)."
echo ""

echo "--- Raw data bytes with block offset ---"
echo "$BLOCK_HEX" | sed 's/\(..\)/\1 /g' | while read -r line; do
    echo "  $line"
done
echo ""
echo "  Block offset 20 = byte 0x28 (decimal 40). In hex above: offset 20 is '28' (part of 00 05 28 3c = our 040 theta)."
echo "  If we read 130 (7 bytes) we consume 14-20 = c5 af f1 e0 02 00 05 -> wrong; tshark uses 12-15 as 040, 16-17 as 070, etc."
echo ""

# Save our dump and tshark dump for reference
echo "=== Saving dumps ==="
cargo run --bin decode_pcap -- "$PCAP" --dump=- 2>/dev/null | awk -v fn="$FRAME" '/^=== packet '"$FRAME"' .*block cat 48/,/^=== packet [0-9]+ /' | head -20 > "$OUT_DIR/our_dump_frame${FRAME}_cat048.txt"
[ -f "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" ] && cp "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" "$OUT_DIR/tshark_dump_frame${FRAME}.txt" 2>/dev/null || true
echo "  Our dump excerpt: $OUT_DIR/our_dump_frame${FRAME}_cat048.txt"
echo "  Tshark dump:      $OUT_DIR/tshark_asterix_frame${FRAME}.txt"
echo ""
echo "Done."
