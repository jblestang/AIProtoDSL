# ASTERIX CAT048: Decoder vs tshark Comparison

## Summary

For the CAT048 block in frame 1 of `cat_034_048.pcap` (48 bytes), **tshark decodes one record** (45 bytes = 3 FSPEC + 42 data) while **our decoder decodes one record [3–39]** and then **REMOVED** for bytes [39–48] (“second record” fails with `i048_020: ... IO: failed to fill whole buffer`).

**Root cause:** The same FSPEC bytes (`fd f7 02`) are interpreted with **different UAP (item) order**. We use EUROCONTROL order and read **I048/030** at bit 3 (5 bytes); the encoder/tshark use an order where **040 follows 020**, so those 5 bytes belong to 040/070/… and the single record extends to the end of the block.

---

## Byte layout (frame 1, 48-byte block)

| Offset | Bytes   | Content |
|--------|---------|--------|
| 0–2    | 30 00 30 | Category 48, Length 48 |
| 3–5    | fd f7 02 | FSPEC (3 bytes; FX=0 in byte 5 ⇒ no 4th FSPEC byte) |
| 6–47   | 42 bytes | Record body |

---

## tshark

- **One record**, total length 45 (3 FSPEC + 42 data).
- **Item order in this record:**  
  010 → 140 → 020 → **040** → 070 → 090 → 220 → 240 → 250 → 161 → 200 → 170 → 230.
- No 030, 042, 050, 055, 060, 065, 080, 100, 210 in the decoded list for this record.
- So after 020, tshark reads **040** (and then 070, 090, 220, …), and consumes the full 42 data bytes in one record.

---

## Our decoder (EUROCONTROL UAP)

- FSPEC `fd f7 02` with our UAP:
  - Byte 0: all 7 bits set ⇒ 010, 140, 020, **030**, 040, 042, 050.
  - Byte 1: 6 bits set ⇒ 055, 060, 065, 070, 090, 100.
  - Byte 2: bit 6 set ⇒ 210.
- So we decode **14 items**, including **I048/030** (octets_fx) at bit 3.
- We consume:  
  010(2) + 140(3) + 020(1) + **030(5)** + 040(4) + 042(4) + 055(2) + 060(2) + 065(2) + 070(2) + 090(2) + 100(4) + 210(2) = **33 data bytes**.
- First record therefore ends at byte **39** (3 FSPEC + 33 data).
- Bytes **39–47** (9 bytes) are then treated as a **second record**; decoding fails (e.g. at i048_020) ⇒ **REMOVED**.

---

## Where the error comes from

1. **UAP order**
   - We assume EUROCONTROL order: bit 3 = **I048/030** (Warning/Error or Beam, octets_fx).
   - The encoder (and tshark) use an order where **040** (and then 070, 090, 220, …) follows 020, so **no I048/030 at that FSPEC position**.
2. **Effect**
   - We read **5 bytes as I048/030** (bytes 12–16: `c5 af f1 e0 02`).
   - In tshark’s order those bytes are part of **040 / 070 / …**, so the single record continues and uses all 42 data bytes.
   - We end the first record 9 bytes too early and wrongly try to decode the remaining 9 bytes as a second record.

So the error is **not** a bug in FSPEC LSB/FX or in a single field decoder; it is a **UAP (item order) mismatch** between our decoder and this pcap/tshark.

---

## Options to fix or handle

1. **Match encoder UAP**  
   Use (or configure) a Cat048 UAP that matches the encoder: e.g. 010, 140, 020, 040, 070, 090, 220, 240, 250, 161, 200, 170, 230 (and no 030 at that FSPEC position for this record). That implies a different FSPEC bit → item mapping so we don’t consume 5 bytes as 030.

2. **Skip unknown items**  
   When a set FSPEC bit has no corresponding field in our UAP, skip the correct number of bytes for that data item (per EUROCONTROL CAT048). That keeps record boundaries in sync even if we don’t decode every item.

3. **Document and accept**  
   Keep EUROCONTROL UAP and document that pcaps encoded with another UAP (e.g. tshark/radar variant) can show “second record REMOVED” for blocks that tshark shows as one record.

---

## How to reproduce

```bash
# Isolate the block and decodes
./scripts/isolate_failing_payload_048.sh

# Byte-by-byte comparison and root cause
./scripts/compare_cat048_frame1.sh
```

Files in `assets/failing_payload_048/`:  
`tshark_asterix_frame1.txt`, `our_decoder_frame1_cat048.txt`, `cat048_block_hex.txt`.
