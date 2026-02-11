#!/usr/bin/env bash
# Byte-by-byte comparison: our decoder vs tshark for CAT048 block (frame 1).
# Run from repo root. Requires: decode_pcap, tshark.

set -e
cd "$(dirname "$0")/.."
PCAP="${1:-assets/cat_034_048.pcap}"
FRAME=1
OUT="assets/failing_payload_048"

echo "=== CAT048 block comparison (frame $FRAME) ==="
echo ""

# Raw block (48 bytes): bytes 0-2 = cat+len, 3-5 = FSPEC, 6-47 = record body
HEX=$(tshark -r "$PCAP" -Y "frame.number==$FRAME" -T fields -e udp.payload 2>/dev/null | tr -d '\n\r')
BLOCK_HEX=$(echo "$HEX" | cut -c1-96)   # 48 bytes = 96 hex chars
echo "Block (48 bytes) hex:"
echo "$BLOCK_HEX" | sed 's/\(........\)/\1 /g'
echo ""
echo "  [0-2]   Category 0x30 (48), Length 0x0030 (48)"
echo "  [3-5]   FSPEC: fd f7 02  (3 bytes, FX=0 in last byte => no 4th FSPEC byte)"
echo "  [6-47]  Record body: 42 bytes"
echo ""

echo "--- tshark item order (from tshark -O asterix) ---"
echo "  One record, 45 bytes total (3 FSPEC + 42 data). Item order:"
echo "  010, 140, 020, 040, 070, 090, 220, 240, 250, 161, 200, 170, 230"
echo "  (no 030, 042, 050, 055, 060, 065, 080, 100, 210 in this record's display)"
echo ""

echo "--- our decoder (EUROCONTROL UAP) ---"
echo "  FSPEC fd f7 02 => bits: byte0 all 7 set, byte1 bits 7,6,5,4,2,1 set, byte2 bit 6 set"
echo "  => 010, 140, 020, 030, 040, 042, 050, 055, 060, 065, 070, 090, 100, 210 (14 items)"
echo "  We consume: 010(2) 140(3) 020(1) 030(5) 040(4) 042(4) 055(2) 060(2) 065(2) 070(2) 090(2) 100(4) 210(2) = 33 data bytes"
echo "  => first record ends at byte 39 (3 FSPEC + 33 data). Bytes 39-47 = 9 bytes treated as second record => REMOVED"
echo ""

echo "--- ROOT CAUSE ---"
echo "  Same FSPEC (fd f7 02) is interpreted with different UAP order:"
echo "  - We use EUROCONTROL order: bit 3 = I048/030 (octets_fx, 5 bytes). We consume 5 bytes for 030."
echo "  - Encoder/tshark use an order where 030 is not at bit 3 (or 040 follows 020). So those 5 bytes are not '030' but part of 040/070/... and the record continues to byte 47."
echo "  So we stop the first record 9 bytes too early and wrongly try to decode bytes 39-47 as a second record."
echo ""

echo "--- Suggested fix ---"
echo "  1. Align Cat048 UAP with the encoder: either use the same order as tshark for this pcap, or"
echo "  2. Skip/consume unknown FSPEC bits (when a set bit has no field in our UAP, skip the item's bytes per spec), or"
echo "  3. Accept that this pcap may be encoded with a non-EUROCONTROL UAP variant."
echo ""

# Side-by-side decode outputs
echo "--- tshark decode (excerpt) ---"
[ -f "$OUT/tshark_asterix_frame${FRAME}.txt" ] && sed -n '/FSPEC/,/B1B/p' "$OUT/tshark_asterix_frame${FRAME}.txt" | head -30
echo ""
echo "--- our decoder (excerpt) ---"
cargo run --bin decode_pcap -- "$PCAP" --dump=- 2>/dev/null | awk -v fn="$FRAME" '/^=== packet 1 /,/^=== packet 2 /' | head -30
