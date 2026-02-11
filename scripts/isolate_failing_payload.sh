#!/usr/bin/env bash
# Isolate a non-working (CAT034) payload from the pcap, dump it, and compare with tshark ASTERIX decode.
# Usage: ./scripts/isolate_failing_payload.sh [pcap] [frame_number]
# Default: assets/cat_034_048.pcap, frame 3 (first packet with failing CAT034 block in our dump).

set -e
cd "$(dirname "$0")/.."
PCAP="${1:-assets/cat_034_048.pcap}"
FRAME="${2:-3}"
OUT_DIR="${OUT_DIR:-assets/failing_payload}"
mkdir -p "$OUT_DIR"

# Known failing block from our analysis: packet 3, UDP offset 55, CAT034 block len 11
# So the 11-byte block starts at byte 55 of the UDP payload (0-based).
UDP_OFFSET=55
BLOCK_LEN=11

echo "=== Isolating failing payload ==="
echo "Pcap: $PCAP"
echo "Frame: $FRAME"
echo "UDP offset of CAT034 block: $UDP_OFFSET, block length: $BLOCK_LEN"
echo ""

# 1) Full UDP payload (hex) of the frame
PAYLOAD_HEX=$(tshark -r "$PCAP" -Y "frame.number==$FRAME" -T fields -e udp.payload 2>/dev/null | tr -d '\n\r')
if [ -z "$PAYLOAD_HEX" ]; then
  echo "Error: no UDP payload for frame $FRAME"
  exit 1
fi

# Save full payload as hex dump (with newlines every 16 bytes)
echo "$PAYLOAD_HEX" | sed 's/\(..\)/\1 /g' | fold -s -w 48 | sed 's/ $//' > "$OUT_DIR/udp_payload_hex.txt"
echo "Written: $OUT_DIR/udp_payload_hex.txt (full UDP payload, hex)"

# 2) Raw binary full UDP payload
echo "$PAYLOAD_HEX" | xxd -r -p > "$OUT_DIR/udp_payload.bin"
echo "Written: $OUT_DIR/udp_payload.bin (full UDP payload, raw)"

# 3) Isolated failing block (11 bytes at offset 55) — hex
# Offset 55 bytes = 110 hex chars (0-indexed: 0-109 = 55 bytes), so we want chars 110 to 131 (11 bytes = 22 hex chars)
BLOCK_HEX=$(echo "$PAYLOAD_HEX" | cut -c$((UDP_OFFSET*2+1))-$(( (UDP_OFFSET+BLOCK_LEN)*2 )))
echo "$BLOCK_HEX" | sed 's/\(..\)/\1 /g' > "$OUT_DIR/cat034_block_hex.txt"
echo "Written: $OUT_DIR/cat034_block_hex.txt (CAT034 block only, hex)"

# 4) Isolated block as raw binary
echo "$BLOCK_HEX" | xxd -r -p > "$OUT_DIR/cat034_block.bin"
echo "Written: $OUT_DIR/cat034_block.bin (CAT034 block only, raw)"

# 5) xxd-style dump of full payload (byte offsets)
echo "Full UDP payload (xxd-style):" > "$OUT_DIR/udp_payload_xxd.txt"
echo "$PAYLOAD_HEX" | xxd -r -p | xxd -g1 >> "$OUT_DIR/udp_payload_xxd.txt"
echo "Written: $OUT_DIR/udp_payload_xxd.txt"

# 6) xxd of isolated block
echo "CAT034 block (bytes $UDP_OFFSET-$((UDP_OFFSET+BLOCK_LEN-1))):" > "$OUT_DIR/cat034_block_xxd.txt"
echo "$BLOCK_HEX" | xxd -r -p | xxd -g1 >> "$OUT_DIR/cat034_block_xxd.txt"
echo "Written: $OUT_DIR/cat034_block_xxd.txt"
echo ""

# 7) tshark full ASTERIX decode for this frame
echo "=== tshark ASTERIX decode (frame $FRAME) ==="
tshark -r "$PCAP" -Y "frame.number==$FRAME" -O asterix 2>/dev/null > "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" || true
if [ -s "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" ]; then
  echo "Written: $OUT_DIR/tshark_asterix_frame${FRAME}.txt"
  echo ""
  echo "--- tshark decode (CAT034 part) ---"
  sed -n '/ASTERIX packet, Category 034/,$p' "$OUT_DIR/tshark_asterix_frame${FRAME}.txt" | head -25
else
  echo "tshark ASTERIX output empty (dissector may not be available)"
  tshark -r "$PCAP" -Y "frame.number==$FRAME" -V 2>/dev/null > "$OUT_DIR/tshark_verbose_frame${FRAME}.txt" || true
  echo "Fell back to: $OUT_DIR/tshark_verbose_frame${FRAME}.txt"
fi
echo ""

# 8) Our decoder's view of the same frame (from existing dump or one-liner)
echo "=== Our decoder (decode_pcap) view ==="
cargo run --bin decode_pcap -- "$PCAP" --dump=- 2>/dev/null | awk -v fn="$FRAME" '
  /^=== packet / { in_packet=0 }
  $0 ~ "packet " fn " " { in_packet=1 }
  in_packet && /block cat 34/ { cat34=1; print; next }
  in_packet && cat34 { print; if (/^=== packet /) exit }
' > "$OUT_DIR/our_decoder_frame${FRAME}_cat034.txt" || true
if [ -s "$OUT_DIR/our_decoder_frame${FRAME}_cat034.txt" ]; then
  echo "Written: $OUT_DIR/our_decoder_frame${FRAME}_cat034.txt"
  cat "$OUT_DIR/our_decoder_frame${FRAME}_cat034.txt"
fi
echo ""

# 9) Summary: raw bytes of CAT034 block with interpretation
echo "=== CAT034 block raw bytes (frame $FRAME, offset $UDP_OFFSET) ==="
printf "Hex: %s\n" "$BLOCK_HEX"
echo ""
printf "Bytes: "
echo "$BLOCK_HEX" | sed 's/\(..\)/\1 /g'
echo ""
echo "  Byte 0-1:   Category = $(echo "$BLOCK_HEX" | cut -c1-2) (34), Length = 0x$(echo "$BLOCK_HEX" | cut -c3-6) = $(printf '%d' 0x$(echo "$BLOCK_HEX" | cut -c3-6))"
echo "  Byte 3:     FSPEC (first byte of record body)"
echo "  Byte 4-:    Data items per UAP"
echo ""
echo "All outputs in: $OUT_DIR/"
