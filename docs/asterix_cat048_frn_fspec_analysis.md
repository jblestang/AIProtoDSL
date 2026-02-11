# CAT048 FRN / FSPEC Mismatch Analysis

Analysis of the **Field Reference Number (FRN)** and **FSPEC (Field Specification)** mapping between our decoder, Wireshark/tshark, and the EUROCONTROL CAT048 specification.

## 1. Reference: EUROCONTROL CAT048 UAP

From **EUROCONTROL SPEC 0149-4** (Category 048 Monoradar Target Reports), section 5.3.1 *Standard User Application Profile*:

- **UAP order (FRN order):** Data items are transmitted in the order defined by the FRN in the UAP.
- **FSPEC:** One or more octets; each octet carries **7 presence bits** (one per data item in that “extent”) plus one **FX (Field Extension)** bit.
- **FX:** When set to 1, a further FSPEC octet follows.

The **standard UAP** lists the following order (first octet’s 7 items + FX, then second octet, etc.):

| Octet | Bit positions (spec typical) | FRNs (data items) |
|-------|-------------------------------|--------------------|
| 1     | 7 presence + FX               | 010, 140, 020, 040, 070, 090, **130**, FX |
| 2     | 7 presence + FX               | 220, 240, 250, 161, 042, 200, 170, FX |
| 3     | 7 presence + FX               | 210, 030, 080, 100, 110, 120, 230, FX |
| 4     | 7 presence + FX               | 260, 055, 050, 065, 060, SP, RE, FX |

So the **first FSPEC octet** encodes presence for **I048/010, I048/140, I048/020, I048/040, I048/070, I048/090, I048/130** and **FX**.

## 2. FSPEC Octet Bit Layout (Spec vs Implementations)

In ASTERIX Part 1, the FSPEC octet is usually described as:

- **8 bits per octet.**  
- **7 bits** indicate presence of the 7 data items for that extent.  
- **1 bit** is the **FX** (extension): if set, another FSPEC octet follows.

The critical detail is **which physical bit is FX** and **which bits are the 7 presence bits**.

### 2.1 Two common conventions

| Convention | FX bit | 7 presence bits | 7th item (e.g. 130) |
|------------|--------|------------------|----------------------|
| **A: FX in LSB** | Bit 0 (LSB) | Bits 7–1 (MSB first) | Bit 1 → `(byte >> 1) & 1` |
| **B: FX in bit 1** | Bit 1 | Bits 7,6,5,4,3,2,**0** (skip bit 1) | Bit 0 (LSB) → `(byte >> 0) & 1` |

For the **failing block**, first FSPEC byte = **0xFD** = `0b11111101`:

- **Bit 0 (LSB) = 1**  
- **Bit 1 = 0**  
- **Bits 2–7 = 1**

So:

- **Convention A (FX in LSB):**  
  - Presence bits = bits 7–1 → 1,1,1,1,1,1,**0**.  
  - 7th item (130) = bit 1 → `(0xFD >> 1) & 1 = 0` → **130 absent**.

- **Convention B (FX in bit 1):**  
  - Presence bits = 7,6,5,4,3,2,0 (skip bit 1).  
  - 7th item (130) = bit 0 → `(0xFD >> 0) & 1 = 1` → **130 present**.

So:

- If the **spec/Wireshark** use **Convention A**, then for 0xFD we must **not** decode 130.
- If our decoder effectively uses **Convention B** (or maps the 7th presence bit to LSB), we will decode 130 and consume 7 bytes, which matches the observed failure (run out at I048/161).

## 3. Our Decoder

### 3.1 FSPEC read (codec)

- We read FSPEC octets until **`b & 0x01 == 0`** → we treat **bit 0 as FX** (Convention A).
- So we **stop** reading FSPEC when the LSB is 0. That is consistent with **FX in LSB**.

### 3.2 Presence bit used for each optional

- We use **bit_index** 0, 1, 2, … for the **sequence of optional fields** (no explicit “skip FX” in the bit stream).
- Formula: `byte_idx = bit_index / 7`, `bit_idx = bit_index % 7`, then  
  **`bit = (bytes[byte_idx] >> (7 - bit_idx)) & 1`**.

So for the **first octet**:

- bit_index 0 → `(byte >> 7) & 1` → bit 7  
- bit_index 1 → `(byte >> 6) & 1` → bit 6  
- …  
- bit_index 6 → `(byte >> 1) & 1` → bit 1  

So we use **bits 7,6,5,4,3,2,1** for the first 7 optionals. That is **Convention A** (7 presence in 7–1, FX in 0). For 0xFD that gives the **7th optional (130) = bit 1 = 0** → **130 absent**. So with this formula we **should not** decode 130.

### 3.3 Optional field order (DSL)

In `Cat048Record` we have:

- **fspec mapping:**  
  `0: i048_010, 1: i048_140, 2: i048_020, 3: i048_040, 4: i048_070, 5: i048_090, 6: i048_130, 7: FX, 8: i048_220, ...`

So **logical indices 0–6** = 010, 140, 020, 040, 070, 090, 130; index **7** is FX. The codec **does not** skip a bit for “7: FX”: it just iterates over **optional_indices** (all optional fields in order). So we have **28 optionals** and we consume **28 consecutive presence bits** (4 octets × 7 bits). That means we **do not** reserve bit index 7 for “FX” when reading presence; the 8th bit we read is for **i048_220**. So:

- We use **7 bits per octet** for presence (indices 0–6, 8–14, …).
- **FX** is only used in the **FSPEC read loop** (stop when LSB = 0), not as an extra “slot” in the presence stream.

So for the first octet we use bits 7,6,5,4,3,2,1 for 010, 140, 020, 040, 070, 090, 130. For 0xFD that gives 130 = (0xFD>>1)&1 = **0** → 130 absent. So **the intended behaviour** is consistent with the spec and Wireshark. If we still decode 130 in practice, the bug is likely:

- **Nested struct (I048/130)** overwriting or not restoring **ctx.presence**, so that after decoding 130 we use wrong presence for the next optionals, or  
- **Order / count of optionals** not matching the UAP (e.g. an extra “FX” optional consuming a bit), or  
- **First-byte value** in the block not actually 0xFD in the code path that fails.

## 4. Wireshark / tshark

- For the same block, tshark decodes **one** record and **does not** show **I048/130**.
- So Wireshark treats the **7th item of the first FSPEC octet as absent** for 0xFD.
- That is consistent with **Convention A**: 7 presence bits in 7–1, FX in 0; 7th item = bit 1 = 0.

So: **Wireshark and spec (Convention A) agree**: for 0xFD, I048/130 is absent.

## 5. Summary Table (First FSPEC Octet)

| Source        | FX bit | 7 presence bits | 7th FRN (130) for 0xFD |
|---------------|--------|------------------|--------------------------|
| **Spec (typical)** | LSB (0) | 7–1 MSB first    | Bit 1 → 0 → **absent**   |
| **Wireshark**  | LSB (0) | 7–1              | **absent** (no I048/130) |
| **Our code (formula)** | LSB (0) | 7–1 (`(7 - bit_idx)`) | Bit 1 → 0 → **absent**   |
| **Our observed behaviour** | —      | —                | **Present** (we consume 7 bytes) → **mismatch** |

So the **FRN/FSPEC mismatch** is:

- **Spec and Wireshark:** First octet 0xFD → 7th FRN (I048/130) **absent** (bit 1 = 0).
- **Our decoder (intended):** Same mapping → 130 **absent**.
- **Our decoder (observed):** We **do** decode 130 and consume 7 bytes → **first inconsistency at I048/130** (data offset 14); Wireshark decodes I048/220 there.

## 6. Recommended Next Steps

1. **Confirm in code** that for CAT048 we use exactly **7 presence bits per FSPEC octet** and that **no** optional slot is consumed for “FX” (FX only controls the FSPEC read loop).
2. **Confirm** that when we decode an optional **struct** (e.g. I048/130 = RadarPlotCharacteristics), we **save/restore** `ctx.presence` so the parent FSPEC is not overwritten (already done in `decode_struct`).
3. **Trace** the first CAT048 record: log the first FSPEC byte and the value of the presence bit used for I048/130; verify it is 0 for 0xFD.
4. **If** the spec for this category explicitly places **FX in bit 1** (Convention B), then we must change our presence formula for CAT048 so that the 7 presence bits are read from positions **[7,6,5,4,3,2,0]** (skip bit 1). Then 0xFD would yield 130 = bit 0 = 1 → present, and we would then be **wrong** relative to Wireshark; so the more likely fix is to **align with Convention A** (FX in LSB, 7th item = bit 1) and fix any bug that causes us to decode 130 when that bit is 0.

**Observed failure:** We fail at I048/161 with 1 byte left → 41 data bytes consumed before 161 = 14 (010..090) + 7 (130) + 20 (220,240,250). So we *are* decoding 130 despite the formula giving 0 for bit index 6. The bug is therefore likely: (a) optional order / count not matching the UAP (e.g. an extra optional consuming a bit so 130 gets a different bit), or (b) presence state corrupted when decoding nested struct I048/130 (e.g. before save/restore was added), or (c) a different code path for CAT048. Tracing the actual bit_index and presence bytes when deciding 130 is needed.

## 7. References

- EUROCONTROL SPEC 0149-4 (Category 048 Monoradar Target Reports), section 5.3.1 (UAP) and Part 1 (FSPEC).
- `examples/asterix_family.dsl`: `Cat048Record` fspec mapping.
- `src/codec.rs`: FSPEC read (`b & 0x01 == 0`), presence formula `(bytes[byte_idx] >> (7 - bit_idx)) & 1`.
- `assets/failing_payload_048/field_comparison_report.txt`: first inconsistency at data offset 14 (we decode I048/130, Wireshark I048/220).
