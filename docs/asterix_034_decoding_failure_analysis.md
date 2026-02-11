# ASTERIX CAT 034 Decoding Failure Analysis

## Summary

| Metric | Value |
|--------|--------|
| CAT034 blocks in pcap | 34 |
| CAT034 records decoded | 10 |
| CAT034 records removed (failures) | 24 (from 32 failing blocks; 2 blocks decode fully) |

Block sizes seen: **len 11** (majority), **len 16**, **len 28**. Body = len − 3 (transport).

---

## Failure distribution (from dump)

| Failing field | Count | Typical block | Error |
|---------------|-------|----------------|--------|
| **i034_060** (SystemProcessingMode034.fspec) | 10 | len 11 | IO: failed to fill whole buffer |
| **i034_110** | 4 | len 11 | IO: failed to fill whole buffer |
| **i034_090** (CollimationError.rng) | 2 | len 11 | IO: failed to fill whole buffer |
| **i034_120** (Position3D.hgt) | 2 | len 11 | IO: failed to fill whole buffer |
| **i034_100** (PolarWindow.rhoend) | 2 | len 16 | IO: failed to fill whole buffer |
| **i034_050** (SystemConfig034.ssr) | 2 | len 16 (2nd record) | IO: failed to fill whole buffer |
| **fspec** (2nd record in block) | 2 | len 28 | IO: failed to fill whole buffer |

---

## Root causes

### 1. **Short blocks (len 11 → 8 bytes body)**

- Body = 1 FSPEC byte + 7 bytes of data.
- Minimal content that fits: I034/010 (2) + I034/000 (1) + I034/030 (3) + I034/020 (1) = 7 bytes. So at most four items after FSPEC.
- If FSPEC indicates **050** and **060** are present:
  - I034/050 (SystemConfig034): at least 1 byte (FSPEC) + 1 byte (COM when present) = 2 bytes.
  - I034/060 (SystemProcessingMode034): at least 1 byte (FSPEC) + 1 byte (rdpxmt when present) = 2 bytes.
- So 7 + 2 + 2 = 11 bytes would be needed; only 8 are available. Decoder therefore runs out of data when reading **060** (or earlier if 050 is decoded).
- **Conclusion**: For len-11 blocks, the wire either (a) uses a different FSPEC (fewer items) so that 050/060 are not both present, or (b) the block is truncated and we correctly fail when the buffer ends.

### 2. **i034_060 (SystemProcessingMode034.fspec) — most frequent**

- Decoder has just finished I034/050 and tries to read the first byte of I034/060 (the FSPEC byte).
- No bytes left → **SystemProcessingMode034.fspec: IO: failed to fill whole buffer**.
- So in these records the wire has 010, 000, 030, 020, (041 optional), and 050 decoded; then 060 is indicated by FSPEC but the block ends. Consistent with **len-11 blocks being too short** for the FSPEC pattern we decode.

### 3. **i034_110 / i034_090 / i034_120**

- Same 8-byte body: FSPEC indicates later items (110, 090, 120) but buffer ends before their encoding.
- Again consistent with **truncated or minimal blocks** where the decoder is aligned but the record is short.

### 4. **len-16 blocks**

- **i034_100 (PolarWindow.rhoend)**: First record decodes up to 100; PolarWindow is 8 bytes (rhost, rhoend, thetast, thetaend). Failure when the last part of PolarWindow cannot be read → buffer ends mid-struct.
- **i034_050 (SystemConfig034.ssr)**: First record in the block decodes; second record starts, we decode 050 and then try to read optional **ssr** and run out → second record is shorter than implied by FSPEC/050.

### 5. **len-28 blocks**

- First record decodes (bytes 3–26, 23 bytes).
- Second record: only 2 bytes left (27–28). Decoder tries to read FSPEC (variable length) → **field fspec: IO: failed to fill whole buffer**. So the second record is **truncated** (only 2 bytes for the whole record).

---

## Decoded record example (len 28, bytes 3–26)

- FSPEC: `ef 10` (bits 0–5 and 8–10 set → 010, 000, 030, 020, 050, 060, 100, 110).
- 010, 000, 030, 020 present; 041 absent; 050 (SystemConfig034 with COM + MDS), 060 (fspec only, no rdpxmt), 070 absent, 100 (PolarWindow), 110 present, 120/090 absent.
- Decoder and DSL alignment are correct for this record.

---

## Conclusions

1. **DSL/UAP alignment**: When there are enough bytes, CAT034 decodes correctly (e.g. len-28 first record). UAP and I034/050 (fspec+COM/PSR/SSR/MDS) and I034/060 (fspec+rdpxmt) match the wire.
2. **Most failures are buffer underrun**: Decoder fails when the remaining buffer is too short for the next item indicated by FSPEC. No evidence of wrong field order or wrong parsing of 050/060.
3. **Block length vs content**:
   - **len 11**: 8 bytes body is only enough for a minimal record (e.g. 010, 000, 030, 020). Any 050/060 and beyond need more space; running out at 060 (or 090/110/120) is expected if the wire FSPEC sets those bits.
   - **len 16**: Some blocks contain two records; the second can be truncated (050.ssr or 100.rhoend).
   - **len 28**: First record fits; second record has only 2 bytes and fails on FSPEC read.

**Recommendation**: Treat remaining CAT034 failures as **short/truncated blocks** in the pcap. To improve decode rate we could (a) accept partial records (e.g. skip or default optional fields when buffer ends), or (b) verify with the pcap producer that block lengths are correct and complete.
