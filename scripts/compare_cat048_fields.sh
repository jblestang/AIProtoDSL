#!/usr/bin/env bash
# Compare our CAT048 decoder output to Wireshark/tshark field-by-field.
# Uses FSPEC from the block to build our expected layout (I048/130 optional, variable length when present).
# Usage: ./scripts/compare_cat048_fields.sh [frame_number]
# Output: report to stdout and assets/failing_payload_048/field_comparison_report.txt

set -e
cd "$(dirname "$0")/.."
FRAME="${1:-1}"
PCAP="${PCAP:-assets/cat_034_048.pcap}"
OUT_DIR="${OUT_DIR:-assets/failing_payload_048}"
mkdir -p "$OUT_DIR"

# --- 1. Get raw block and FSPEC from UDP payload (first CAT048 block in frame) ---
HEX=$(tshark -r "$PCAP" -Y "frame.number==$FRAME" -T fields -e udp.payload 2>/dev/null | tr -d '\n\r')
BLOCK_LEN=0
FSPEC_HEX=""
FSPEC_BYTES=()
DATA_LEN=0
if [ -n "$HEX" ]; then
  # First 3 bytes: cat (1) + length (2, big-endian)
  LEN_HI=$(echo "$HEX" | cut -c3-4)
  LEN_LO=$(echo "$HEX" | cut -c5-6)
  BLOCK_LEN=$((0x$LEN_HI * 256 + 0x$LEN_LO))
  # FSPEC starts at byte 3 of block (hex offset 6 = chars 7-8)
  pos=6
  while [ $pos -lt $((BLOCK_LEN * 2)) ]; do
    b=$(echo "$HEX" | cut -c$((pos+1))-$((pos+2)))
    FSPEC_HEX="$FSPEC_HEX $b"
    FSPEC_BYTES+=("$b")
    val=$((0x$b))
    [ $((val & 1)) -eq 0 ] && break
    pos=$((pos + 2))
  done
  # Data = rest of block after FSPEC (byte offset 3 + num_fspec_bytes)
  num_fspec=$(( ${#FSPEC_BYTES[@]} ))
  DATA_LEN=$((BLOCK_LEN - 3 - num_fspec))
fi

# FSPEC bit 6 (0-based) = 7th presence bit = I048/130. First byte: bit index 6 => (byte >> 1) & 1
I048_130_PRESENT=0
if [ ${#FSPEC_BYTES[@]} -gt 0 ]; then
  B0=${FSPEC_BYTES[0]}
  first_byte=$((0x$B0))
  I048_130_PRESENT=$(( (first_byte >> 1) & 1 ))
fi

# --- 2. Capture tshark ASTERIX field list (I048/XXX lines only) ---
TSHARK_RAW="$OUT_DIR/tshark_asterix_frame${FRAME}.txt"
tshark -r "$PCAP" -Y "frame.number==$FRAME" -O asterix 2>/dev/null > "$TSHARK_RAW" || true

TSHARK_FIELDS=()
while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*([0-9]{3}),[[:space:]] ]]; then
        TSHARK_FIELDS+=("${BASH_REMATCH[1]}")
    fi
done < "$TSHARK_RAW"

# --- 3. Capture our decoder output ---
OUR_DUMP="$OUT_DIR/our_dump_frame${FRAME}_cat048.txt"
DECODE_OUT=$(mktemp)
cargo run --bin decode_pcap -- "$PCAP" --dump=- 2>/dev/null > "$DECODE_OUT" || true

awk -v fn="$FRAME" '
  /^=== packet [0-9]+ .*block cat 48/ {
    if ($3+0==fn+0) { p=1; print; next }
    else { p=0; next }
  }
  p && /^=== packet [0-9]+ / { p=0; exit }
  p { print }
' "$DECODE_OUT" | head -50 > "$OUR_DUMP"

OUR_REMOVED=$(grep 'REMOVED:' "$OUR_DUMP" 2>/dev/null | sed 's/.*REMOVED: /REMOVED: /' | head -1 || echo "")
OUR_DECODED=$(grep 'DECODED' "$OUR_DUMP" 2>/dev/null | head -1 || echo "")
rm -f "$DECODE_OUT"

# --- 4. Byte sizes: UAP order (010, 140, 020, 040, 070, 090, 130, 220, 240, 250, 161, ...) ---
# 130 is variable (1–8 bytes when present). For layout we use 7 when present for "wrong" path, 0 when absent.
# Frame 1: 010, 140, 020, 040, 070, 090, 220, 240, 250, 161, 200, 170, 230 (no 042)
TSHARK_ORDER="010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2 200:4 170:4 230:2"

# Our order with 130: absent (0 bytes) or present (variable 1–8). Use 4 as typical when present for layout.
OUR_WITHOUT_130="010:2 140:3 020:1 040:4 070:2 090:2 220:3 240:8 250:9 161:2"
OUR_WITH_130_VAR="010:2 140:3 020:1 040:4 070:2 090:2 130:4 220:3 240:8 250:9 161:2"

if [ "$I048_130_PRESENT" -eq 0 ]; then
  OUR_ORDER="$OUR_WITHOUT_130"
  OUR_130_LABEL="(130 absent per FSPEC)"
else
  OUR_ORDER="$OUR_WITH_130_VAR"
  OUR_130_LABEL="(130 present per FSPEC, variable 1–8 bytes)"
fi

# --- 5. Build offset->field for tshark ---
tshark_offset=0
tshark_at_offset=()
for ent in $TSHARK_ORDER; do
    f="${ent%:*}"
    s="${ent#*:}"
    for ((i=0;i<s;i++)); do
        tshark_at_offset[$tshark_offset]=$f
        ((tshark_offset++)) || true
    done
done

# --- 6. Build offset->field for our decoder (expected when we decode correctly) ---
our_offset=0
our_at_offset=()
for ent in $OUR_ORDER; do
    name="${ent%:*}"
    size="${ent#*:}"
    for ((i=0;i<size;i++)); do
        our_at_offset[$our_offset]=$name
        ((our_offset++)) || true
    done
done

# --- 7. Find first offset where field differs ---
FIRST_BAD_OFFSET=-1
FIRST_BAD_TSHARK=""
FIRST_BAD_OUR=""
max_i=$(( tshark_offset < our_offset ? tshark_offset : our_offset ))
[ $max_i -gt $DATA_LEN ] && max_i=$DATA_LEN
for ((i=0; i<max_i; i++)); do
    t="${tshark_at_offset[$i]:-}"
    o="${our_at_offset[$i]:-}"
    if [[ "$t" != "$o" ]]; then
        FIRST_BAD_OFFSET=$i
        FIRST_BAD_TSHARK=$t
        FIRST_BAD_OUR=$o
        break
    fi
done

# --- 8. Report ---
REPORT="$OUT_DIR/field_comparison_report.txt"
{
    echo "=================================================================================="
    echo "CAT048 frame $FRAME: field-by-field comparison — our decoder vs Wireshark (tshark)"
    echo "=================================================================================="
    echo ""
    echo "--- Block ---"
    echo "  Block length: $BLOCK_LEN bytes (from pcap)"
    echo "  FSPEC (hex):$FSPEC_HEX  (${#FSPEC_BYTES[@]} byte(s))"
    echo "  I048/130 present (FSPEC bit 6): $I048_130_PRESENT  $OUR_130_LABEL"
    echo "  Data bytes (after FSPEC): $DATA_LEN"
    echo ""
    echo "--- Wireshark field order (from tshark -O asterix) ---"
    for f in "${TSHARK_FIELDS[@]}"; do
        echo "  I048/$f"
    done
    echo ""
    echo "--- Our decoder (current behaviour) ---"
    if [[ -n "$OUR_REMOVED" ]]; then
        echo "  Status: REMOVED (record not decoded)"
        echo "  Reason: $OUR_REMOVED"
        echo "  Expected (if we decode per FSPEC): 130 $([ "$I048_130_PRESENT" -eq 0 ] && echo "absent" || echo "present (1–8 bytes)")."
    elif [[ -n "$OUR_DECODED" ]]; then
        echo "  Status: DECODED"
        echo "  $OUR_DECODED"
    else
        echo "  Status: (no record line in dump)"
    fi
    echo ""
    echo "--- Consistency (our *expected* layout vs Wireshark) ---"
    if [[ $FIRST_BAD_OFFSET -lt 0 ]]; then
        echo "  All fields consistent with Wireshark up to the end of compared data."
    else
        echo "  First inconsistency at data_offset $FIRST_BAD_OFFSET:"
        echo "    Wireshark decodes here: I048/${FIRST_BAD_TSHARK:-?}"
        echo "    We decode here:         I048/${FIRST_BAD_OUR:-?}"
    fi
    echo ""
    echo "--- Byte layout (data = after FSPEC) ---"
    echo "  Offset  | We (expected) | Wireshark"
    echo "  --------|----------------|----------"
    for ((i=0; i<DATA_LEN && i<60; i++)); do
        o="${our_at_offset[$i]:-.}"
        t="${tshark_at_offset[$i]:-.}"
        eq=""; [[ "$o" == "$t" ]] || eq="  <-- DIFF"
        printf "  %2d      | I048/%-10s | I048/%-6s%s\n" "$i" "$o" "$t" "$eq"
    done
    [ $DATA_LEN -gt 60 ] && echo "  ..."
    echo ""
    echo "--- Files ---"
    echo "  Tshark full dump: $TSHARK_RAW"
    echo "  Our dump:         $OUR_DUMP"
    echo ""
} | tee "$REPORT"

echo "Report written to $REPORT"
