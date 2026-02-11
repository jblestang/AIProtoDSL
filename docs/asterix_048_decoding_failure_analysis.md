# ASTERIX CAT048 decoding failure – analysis vs Wireshark

## Failing case

- **Source:** Frame 1, `assets/cat_034_048.pcap`, single CAT048 block, 48 bytes.
- **Our decoder:** `record bytes [3-48] REMOVED: Validation: field i048_161: Validation: TrackNumber.spare: IO: failed to fill whole buffer`
- **Wireshark/tshark:** Decodes the same block as **one** complete record (45 bytes = 3 FSPEC + 42 data).

## Block layout (hex)

```
Offset  0-2:  30 00 30     Category 48, Length 48
Offset  3-5:  fd f7 02     FSPEC (3 bytes; FX=0 in last byte)
Offset  6-47: 42 bytes     Record body (data)
```

Data bytes (6–47):

```
19 c9 35 6d 4d a0 c5 af f1 e0 02 00 05 28 3c 66 0c 10 c2 36 d4 18 20 01 c0 78 00 31 bc 00 00 40 0d eb 07 b9 58 2e 41 00 20 f5
```

## Wireshark (tshark) decode of this record

tshark decodes **one** record with this item order and no I048/130:

- 010 (2) → 140 (3) → 020 (1) → 040 (4) → 070 (2) → 090 (2)  
- 220 (3) → 240 (8) → 250 (1+8=9) → 161 (2) → 200 (4) → 170 (4) → 230 (2)  
- **Total data:** 2+3+1+4+2+2+3+8+9+2+4+4+2 = **46** (tshark may use slightly different sizes; 040/070/090/170 can differ by spec edition).

Important: **I048/130 (Radar Plot Characteristics) is not present** in tshark’s decode for this record.

## Our decoder (EUROCONTROL UAP)

- **UAP order:** 010, 140, 020, 040, 070, 090, **130**, FX, 220, 240, 250, 161, 042, 200, 170, …
- **FSPEC** `fd f7 02` (binary 11111101 11110111 00000010):
  - Byte 0: bits 7–1 (MSB first) = 1,1,1,1,1,1,**0** → bit 6 = **0** → I048/130 **absent** in the spec (7th bit = 0).
  - So with correct FSPEC reading we should **not** decode 130.

If we **do** decode 130 (7-byte RadarPlotCharacteristics), consumption is:

- 010(2) + 140(3) + 020(1) + 040(4) + 070(2) + 090(2) = **14**
- **130(7) = 7** (only if bit 6 were 1)
- 220(3) + 240(8) + 250(1+8)=9 = **20**  
→ 14 + 7 + 20 = **41** data bytes, then I048/161 needs **2** bytes → only **1** byte left (byte 47) → **failure at TrackNumber**.

So the failure at **i048_161 (TrackNumber.spare)** with “failed to fill whole buffer” means we run out on the **second** byte of TrackNumber, i.e. we have **1 byte left** when starting 161. That implies **41 data bytes consumed** before 161, which matches **130 being decoded (7 bytes)** even though FSPEC bit 6 is 0.

## Root cause (vs Wireshark)

1. **FSPEC bit for I048/130**  
   - In the block, first FSPEC byte is `0xfd` → bit 1 (second LSB of the 7 presence bits) = 0 → **130 must be absent**.  
   - If our decoder still decodes 130, then either:
   - the **FSPEC presence bit order** (which bit maps to 130) is wrong, or  
   - the **optional field order** used when reading FSPEC does not match the UAP (so the wrong bit is used for 130).

2. **Effect**  
   - We consume **7 extra bytes** as I048/130.  
   - We then have only **1 byte** left when we try to read I048/161 (2 bytes) → **TrackNumber.spare: IO: failed to fill whole buffer**.

3. **Wireshark**  
   - Does **not** show I048/130 in this record, consistent with FSPEC bit 6 = 0 and with the above byte count.

## Recommended checks

1. **FSPEC ↔ optional order**  
   - Ensure the **order of optional fields** when decoding (the order we iterate to read presence bits) is **exactly** the UAP order: 0=010, 1=140, 2=020, 3=040, 4=070, 5=090, 6=130, 7=FX, 8=220, …  
   - Verify that **bit_index 6** is used for I048/130 and that we read the **6th presence bit** of the first FSPEC byte (MSB-first: `(byte >> 1) & 1` for 0xfd → 0).

2. **Presence bit formula**  
   - Decode: `(bytes[byte_idx] >> (7 - bit_idx)) & 1` with `bit_idx = bit_index % 7` (0..6).  
   - For the first byte and bit_index 6 this gives `(fd >> 1) & 1 = 0` → 130 absent.  
   - Confirm this is the formula used for the **message** FSPEC when decoding CAT048.

3. **I048/250 (BDS)**  
   - If 250 were over-consumed (e.g. REP or entry size wrong), we could also run out before 161; but the arithmetic above points to **41 bytes consumed before 161**, which fits **130 present (7 bytes)** and not 250 alone.

## How to reproduce

```bash
./scripts/isolate_failing_payload_048.sh
# Compare
tshark -r assets/cat_034_048.pcap -Y "frame.number==1" -O asterix
cargo run --bin decode_pcap -- assets/cat_034_048.pcap --dump=-
```

**Conclusion:** The CAT048 decoding failure at **i048_161 (TrackNumber)** is caused by running out of buffer (1 byte left for a 2-byte field). Compared with Wireshark, the only way to get 41 bytes consumed before 161 is to decode **I048/130** (7 bytes) even though it is **not** present in this record (FSPEC bit 6 = 0). The origin of the failure is therefore **incorrect presence for I048/130** (wrong FSPEC bit or wrong mapping between FSPEC bits and optional fields).
