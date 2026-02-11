#!/usr/bin/env bash
# Isolate a failing CAT048 payload from the pcap and compare with tshark ASTERIX decode.
# Usage: ./scripts/isolate_failing_payload_048.sh [pcap] [frame_number]
# Default: assets/cat_034_048.pcap, frame 1 (first packet: CAT048 block len 48, we report 2nd record REMOVED).

set -e
cd "$(dirname "$0")/.."
PCAP="${1:-assets/cat_034_048.pcap}"
FRAME="${2:-1}"
OUT_DIR="${OUT_DIR:-assets/failing_payload_048}"
mkdir -p "$OUT_DIR"

# Frame 1: single CAT048 block at UDP offset 0, length 48. tshark sees 1 record (45 bytes body); we decode 1 record [3-39] then try [39-48] as 2nd → REMOVED.
UDP_OFFSET=0
BLOCK_LEN=48

echo "=== Isolating failing CAT048 payload ==="
echo "Pcap: $PCAP"
echo "Frame: $FRAME"
echo "UDP offset of CAT048 block: $UDP_OFFSET, block length: $BLOCK_LEN"
echo ""

# 1) Full UDP payload (hex) of the frame
PAYLOAD_HEX=$(tshark -r "$PCAP" -Y "frame.number==$FRAME" -T fields -e udp.payload 2>/dev/null | tr -d '\n\r')
if [ -z "$PAYLOAD_HEX" ]; then
  echo "Error: no UDP payload for frame $FRAME"
  exit 1
fi

# Save full payload as hex
echo "$PAYLOAD_HEX" | sed 's/\(..\)/\1 /g' | fold -s -w 48 | sed 's/ $//' > "$OUT_DIR/udp_payload_hex.txt"
echo "Written: $OUT_DIR/udp_payload_hex.txt"

# 2) Raw binary full UDP payload
echo "$PAYLOAD_HEX" | xxd -r -p > "$OUT_DIR/udp_payload.bin"
echo "Written: $OUT_DIR/udp_payload.bin"

# 3) Isolated CAT048 block (48 bytes at offset 0)
BLOCK_HEX=$(echo "$PAYLOAD_HEX" | cut -c$((UDP_OFFSET*2+1))-$(( (UDP_OFFSET+BLOCK_LEN)*2 )))
echo "$BLOCK_HEX" | sed 's/\(..\)/\1 /g' > "$OUT_DIR/cat048_block_hex.txt"
echo "Written: $OUT_DIR/cat048_block_hex.txt"

# 4) Isolated block as raw binary
echo "$BLOCK_HEX" | xxd -r -p > "$OUT_DIR/cat048_block.bin"
echo "Written: $OUT_DIR/cat048_block.bin"

# 5) xxd-style dumps
echo "Full UDP payload (xxd-style):" > "$OUT_DIR/udp_payload_xxd.txt"
echo "$PAYLOAD_HEX" | xxd -r -p | xxd -g1 >> "$OUT_DIR/udp_payload_xxd.txt"
echo "CAT048 block (bytes $UDP_OFFSET-$((UDP_OFFSET+BLOCK_LEN-1))):" > "$OUT_DIR/cat048_block_xxd.txt"
echo "$BLOCK_HEX" | xxd -r -p | xxd -g1 >> "$OUT_DIR/cat048_block_xxd.txt"
echo "Written: $OUT_DIR/udp_payload_xxd.txt, $OUT_DIR/cat048_block_xxd.txt"
echo ""

# 6) tshark full ASTERIX decode for this frame
echo "=== tshark ASTERIX decode (frame $FRAME) ==="
tshark -r "$PCAP" -Y "frame.number==$FRAME" -O asterix 2>/dev/null > "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" || true
if [ -s "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" ]; then
  echo "Written: $OUT_DIR/tshark_asterix_frame${FRAME}.txt"
  echo ""
  echo "--- tshark decode (CAT048) ---"
  sed -n '/ASTERIX packet, Category 048/,$p' "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" | head -80
else
  echo "tshark ASTERIX output empty"
  tshark -r "$PCAP" -Y "frame.number==$FRAME" -V 2>/dev/null > "$OUT_DIR/tshark_verbose_frame${FRAME}.txt" || true
fi
echo ""

# 7) Our decoder's view of the same frame (CAT048 block only)
echo "=== Our decoder (decode_pcap) view ==="
cargo run --bin decode_pcap -- "$PCAP" --dump=- 2>/dev/null | awk -v fn="$FRAME" '
  /^=== packet / { in_packet=0 }
  $0 ~ "packet " fn " " { in_packet=1 }
  in_packet && /block cat 48/ { cat48=1; print; next }
  in_packet && cat48 { print; if (/^=== packet /) exit }
' > "$OUT_DIR/our_decoder_frame${FRAME}_cat048.txt" || true
if [ -s "$OUT_DIR/our_decoder_frame${FRAME}_cat048.txt" ]; then
  echo "Written: $OUT_DIR/our_decoder_frame${FRAME}_cat048.txt"
  cat "$OUT_DIR/our_decoder_frame${FRAME}_cat048.txt"
fi
echo ""

echo "=== CAT048 block summary ==="
echo "Hex (first 24 bytes): $(echo "$BLOCK_HEX" | cut -c1-48)"
echo "  Category = $(echo "$BLOCK_HEX" | cut -c1-2) (48), Length = 0x$(echo "$BLOCK_HEX" | cut -c3-6) = $(printf '%d' 0x$(echo "$BLOCK_HEX" | cut -c3-6))"
echo ""
echo "All outputs in: $OUT_DIR/"
