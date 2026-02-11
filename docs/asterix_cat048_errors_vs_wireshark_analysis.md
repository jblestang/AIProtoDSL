# CAT048 decoding errors — analysis vs Wireshark

This document summarizes the comparison between our decoder and Wireshark (tshark) for CAT048 blocks in `assets/cat_034_048.pcap`, and the root cause of remaining failures.

## Method

- **Script:** `scripts/compare_cat048_fields.sh [frame_number]`
- For each frame we:
  1. Extract the first CAT048 block from the UDP payload and read **FSPEC** (bytes 3+ of the block until LSB=0).
  2. Derive **I048/130 presence** from FSPEC bit 6 (7th presence bit): `(first_fspec_byte >> 1) & 1`.
  3. Build our **expected** byte layout: if 130 absent, layout is 010, 140, 020, 040, 070, 090, 220, 240, 250, 161, …; if 130 present, we insert 130 (variable 1–8 bytes) after 090.
  4. Compare this expected layout with the field order and sizes from **tshark -O asterix**.
  5. Report our decoder status (DECODED or REMOVED + reason).

## Frame 1 (len 48) — failing at I048/161

| Item | Value |
|------|--------|
| Block | 48 bytes, FSPEC `fd f7 02` (3 bytes) |
| I048/130 (FSPEC bit 6) | **0 → absent** |
| Data bytes (after FSPEC) | 42 |
| Wireshark | Decodes one record: 010, 140, 020, 040, 070, 090, **220**, 240, 250, 161, 200, 170, 230 (no I048/130) |
| Our decoder | **REMOVED:** `field i048_161: TrackNumber.spare: IO: failed to fill whole buffer` |

**Consistency:** When we assume **130 absent** (correct per FSPEC), our expected layout matches Wireshark through **data offset 35** (through I048/161). So the *intended* behaviour is aligned with Wireshark.

**Root cause of failure:** Failing at I048/161 with “failed to fill whole buffer” means we run out of data while reading the 2-byte TrackNumber (4-bit spare + 12-bit TRN). So we have **at most 1 byte left** when we start I048/161, i.e. we consumed **41 data bytes** before 161. That implies we are still **decoding I048/130 as 7 bytes** (14 + 7 + 20 = 41) even though FSPEC bit 6 is 0 (130 absent). So the bug is in our decoder: we are not skipping I048/130 when its presence bit is 0 (wrong bit, wrong stack level, or FSPEC not applied correctly for this record).

## Frame 2 (len 48)

Same structure as frame 1: FSPEC has 130 absent; we still report REMOVED at i048_161. Same root cause as frame 1.

## Frame 3 (len 55) — failing at I048/042

| Item | Value |
|------|--------|
| FSPEC | `ff f0` (2 bytes in report; block has more data) — bit 6 = 1 → **130 present** |
| Our decoder | **REMOVED:** `field i048_042: CalculatedPositionCartesian.x: IO: failed to fill whole buffer` |

Here 130 is present. We decode 130 with variable length (1–8 bytes). We then run out of buffer when decoding I048/042. So either we over-consume in 130 (e.g. one extra byte) or the record is simply shorter than the set of optionals implies; comparison with tshark (which shows 130, 220, 240, 250, 161, 042, …) confirms the field order. The failure is a buffer underrun after 161, likely due to 130 length or optional combination.

## Frame 5 (len 185) — first record DECODED

| Item | Value |
|------|--------|
| FSPEC (first record) | 130 absent (bit 6 = 0) |
| Our decoder | **DECODED** first record (bytes [3–20]); only 020 and 140 present (minimal record). |

When 130 is absent and the record has few optionals, we decode successfully. This matches the expectation that with 130 correctly skipped, layout aligns with Wireshark.

## Summary table

| Frame | Block len | FSPEC (130) | Our status | Failure field | Conclusion |
|-------|-----------|-------------|------------|---------------|------------|
| 1 | 48 | absent | REMOVED | i048_161 | We consume 41 bytes → still decode 130 (7 bytes); **decoder bug** |
| 2 | 48 | absent | REMOVED | i048_161 | Same as frame 1 |
| 3 | 55 | present | REMOVED | i048_042 | Buffer underrun after 161; 130 variable length or record length |
| 5 | 185 | absent (1st rec) | DECODED | — | Decode OK when 130 skipped and record is short |

## Recommendations

1. **Frames 1 & 2 (130 absent, fail at 161)**  
   Fix the decoder so that when FSPEC bit 6 is 0 we **do not** decode I048/130. Verify:
   - The presence bit used for the 7th optional (I048/130) is exactly bit 6 of the first FSPEC byte: `(bytes[0] >> 1) & 1`.
   - The presence stack is the message-level FSPEC when we read that bit (no nested struct overwriting it).
   - No other code path consumes 7 bytes for 130 when the optional is absent.

2. **Frame 3 (130 present, fail at 042)**  
   Confirm I048/130 is decoded as **variable-length** (1 FSPEC byte + 0–7 optional subfields). If we over-consume (e.g. fixed 7 bytes when only 1–4 are present), we will run out at 042.

3. **Regression**  
   Re-run `./scripts/compare_cat048_fields.sh 1` after the fix; expected layout (130 absent) should match Wireshark and the decoder should **DECODED** the record (or fail later at 200/170 if the record is truncated).

## How to reproduce

```bash
# Single frame (default: frame 1)
./scripts/compare_cat048_fields.sh 1

# Other frames
./scripts/compare_cat048_fields.sh 2
./scripts/compare_cat048_fields.sh 3
./scripts/compare_cat048_fields.sh 5
```

Report is written to `assets/failing_payload_048/field_comparison_report.txt` (overwritten per run). Tshark and our dumps are under `assets/failing_payload_048/`.

---

## Full pcap run (cat_034_048.pcap)

**Command:** `cargo run --bin decode_pcap -- assets/cat_034_048.pcap --dump=assets/failing_payload_048/full_dump.txt`

**Counts:** 120 blocks (34 CAT034, 86 CAT048), **170 decoded** records, **74 removed**.

### Classification of REMOVED records

| Failure type | Typical byte range | Meaning |
|--------------|--------------------|--------|
| `field fspec: IO: failed to fill whole buffer` | [47-48], [49-50], [55-56], [57-58] | **Trailing bytes**: after decoding one (or more) full record(s), 1–2 bytes remain in the block. Decoder tries to read a next record and fails on FSPEC (needs at least 1 byte). Not a decoder bug — block has leftover bytes. |
| `field i048_161: TrackNumber.spare: IO: failed to fill whole buffer` | [137-185] | **Truncated CAT048 record**: a record in a multi-record block doesn’t have enough bytes for I048/161 (e.g. I048/250 rep count too large and consumes rest). |
| `field i048_010: DataSourceId.sac` / `i048_020` / `i048_140` | [29-30], [38-39], [40-41], [49-50] | **Very short “record”** (1–2 bytes): decoder advanced past a full record and is trying to decode from leftover bytes. |
| `field i034_010: DataSourceId.sic` | [14-16], [24-28] | **Truncated CAT034 record**: block has 2–5 bytes left; not enough for full CAT034 record. |
| `field i034_050: SystemConfig034.fspec` | [14-16] | **Truncated CAT034** at I034/050 (FSPEC of System Configuration). |

### Conclusion (updated after I048/170 FX fix)

- **Root cause of CAT048 “trailing bytes”:** The DSL was **under-consuming** by 1 byte: **I048/170 Track Status** has an FX extension (EUROCONTROL: when the LSB of the first byte is 1, a second octet follows — TrackStatus048Ext). We only decoded the first byte (TrackStatus048) and never the extension, so one byte was left and the decoder then tried to read a next record and failed on FSPEC.
- **Fix:** Model the extension with **`fspec(1, 0)`** (1 presence bit, no blocking): `fspec: fspec(1, 0) -> (0: ext); ext: optional<TrackStatus048Ext>`. Here `n=0` means no FX byte extension—consecutive presence bits only—so the single bit is the LSB of the byte and governs presence of `ext`. Applied to `TrackStatus048`.

- **Obsolete:** The previous alternative a **1-bit presence bitmap** without extension: `fspec(1) -> (0: ext)` plus `ext: optional<...>`. The codec reads one bit (the *next* bit in its LSB-first order) and uses it as presence for the following optional. So `fspec(1)` fits when that single presence bit is the next bit in the stream (e.g. after 7 bits it would be the byte’s **MSB**). For **I048/170** the extension bit is the **LSB** of the same byte, so the “next” bit after the 7 data bits is the MSB, not the LSB. Therefore I048/170 is modeled with **`fx_ext`** (which checks the last decoded byte’s LSB), not `fspec(1)`.
- **Result:** CAT048 **removed** dropped from 64 to **0**. Record bytes for 48-byte blocks are now [3-48] (full block consumed); `i048_170` shows `ext: struct { tre, gho, sup, tcc, ... }` when present.
- The remaining **10 REMOVED** are all **CAT034** (truncated records or multi-record blocks with trailing bytes).
- To **inspect a specific failure**: open `assets/failing_payload_048/full_dump.txt` and search for `REMOVED`; the line above shows the block (packet, cat, len) and the byte range of the removed record.
