# I048/130 Radar Plot Characteristics — verification against the standard

This document verifies that our definition and decoding of **I048/130 (Radar Plot Characteristics)** match the EUROCONTROL ASTERIX specification.

## 1. Standard (EUROCONTROL SPEC Part 4, Category 048)

- **Reference:** EUROCONTROL Standard SUR.ET1.ST05.2000-STD-04-01, Part 4 (Category 048 – Transmission of Monoradar Target Reports), section **5.2.16 Data Item I048/130, Radar Plot Characteristics**.
- **Definition:** Radar plot characteristics (e.g. plot quality, smoothing) for the target report.
- **Format:** Variable-length. The item comprises:
  1. **FSPEC octet(s):** One or more octets, same convention as the main record: **7 presence bits per octet** (bits 7–1, MSB first), **FX (Field Extension) in bit 0 (LSB)**. FSPEC continues until an octet with LSB = 0 is read.
  2. **Optional subfields:** For each bit set in the FSPEC (in bit order 7, 6, 5, 4, 3, 2, 1 — no slot for FX when decoding optionals), the corresponding subfield is present and encoded as defined.

- **Subfields (typical in the spec):** Each is one octet when present. Names and types align with:
  - **SRL** – 1 octet  
  - **SRR** – 1 octet  
  - **SAM** – 1 octet (signed)  
  - **PRL** – 1 octet  
  - **PAM** – 1 octet (signed)  
  - **RPD** – 1 octet (signed)  
  - **APD** – 1 octet (signed)  

- **UAP position:** In the standard User Application Profile, I048/130 is the **7th data item** in the first FSPEC octet (after 010, 140, 020, 040, 070, 090). So the **7th presence bit** (bit 1 in the octet, i.e. `(byte >> 1) & 1`) indicates presence/absence of the whole I048/130 item.

## 2. Our DSL (encoding)

**Message (Cat048Record):**

- FSPEC mapping: `0: i048_010, 1: i048_140, 2: i048_020, 3: i048_040, 4: i048_070, 5: i048_090, 6: i048_130, 7: FX, …`
- So **I048/130** is the **7th optional** → it uses the **7th presence bit** of the first FSPEC octet (bit index 6 in our 0-based order).

**Struct RadarPlotCharacteristics (I048/130 content):**

```text
struct RadarPlotCharacteristics {
  fspec: fspec -> (0: srl, 1: srr, 2: sam, 3: prl, 4: pam, 5: rpd, 6: apd, 7: FX);
  srl: optional<u8> [0..255];
  srr: optional<u8> [0..255];
  sam: optional<i8> [-128..127];
  prl: optional<u8> [0..255];
  pam: optional<i8> [-128..127];
  rpd: optional<i8> [-128..127];
  apd: optional<i8> [-128..127];
}
```

- **FSPEC first:** Matches the spec (variable-length FSPEC, then optional subfields).
- **FX in LSB:** Mapping includes `7: FX`; the parser treats FX as extension only (not a data field), so we use **7 presence bits per octet** (bits 7–1) for the seven subfields.
- **Subfield order and size:** SRL, SRR, SAM, PRL, PAM, RPD, APD — each **1 octet** (u8 or i8). Matches the standard.

## 3. Our codec (decoding)

**FSPEC read (message and struct):**

- We read octets until `b & 0x01 == 0` → **FX in LSB (bit 0)**. Matches the spec.

**Presence bit for each optional:**

- Formula: `byte_idx = bit_index / 7`, `bit_idx = bit_index % 7`, then  
  `bit = (bytes[byte_idx] >> (7 - bit_idx)) & 1`.
- So we use **bits 7, 6, 5, 4, 3, 2, 1** of each FSPEC octet (no bit 0 for optionals). Matches **7 presence bits per octet, FX in LSB**.

**Message-level (I048/130 present or absent):**

- I048/130 is the 7th optional (bit_index 6).
- For the first FSPEC byte: `bit = (bytes[0] >> (7 - 6)) & 1 = (bytes[0] >> 1) & 1`.
- Example: first byte **0xFD** → bit = 0 → **I048/130 absent**. This matches the spec and Wireshark (no I048/130 in the record).

**Struct-level (RadarPlotCharacteristics when I048/130 is present):**

1. We decode the **fspec** field: read octets until LSB = 0; push `PresenceState::Fspec { bytes, bit_index: 0 }`.
2. We decode the **seven optionals** in struct order (srl, srr, sam, prl, pam, rpd, apd); each uses the next presence bit (bit_index 0..6 for the first FSPEC byte).
3. We **do not** consume a presence bit for FX; the parser has dropped the `7: FX` entry from the logical mapping, so we only have 7 bits for 7 optionals.
4. Each present subfield is one octet (u8 or i8). Total length = **1 FSPEC octet + 0..7 octets** (variable 1–8 octets). Matches the spec.

## 4. Summary checklist

| Requirement | Our implementation | Status |
|-------------|--------------------|--------|
| I048/130 is 7th item in first FSPEC octet (UAP) | Cat048Record: bit index 6 → `(byte >> 1) & 1` | ✓ |
| FX in LSB of FSPEC octets | Read until `b & 0x01 == 0` | ✓ |
| 7 presence bits per FSPEC octet (bits 7–1) | `(bytes[byte_idx] >> (7 - bit_idx)) & 1`, bit_idx 0..6 | ✓ |
| I048/130 content: FSPEC first, then optionals | Struct: first field `fspec`, then 7× optional | ✓ |
| Subfields SRL, SRR, SAM, PRL, PAM, RPD, APD, 1 octet each | optional\<u8\> or optional\<i8\>, 7 fields | ✓ |
| No “8th” optional slot for FX when decoding | Parser removes FX from mapping; we decode 7 optionals only | ✓ |

## 5. Conclusion

- **I048/130 is decoded as expected by the standard:**  
  - At **message level**, presence is given by the 7th presence bit of the first FSPEC octet (bit 1 = `(byte >> 1) & 1`).  
  - When **present**, the content is **variable-length**: one or more FSPEC octets (FX in LSB), then 0–7 one-octet subfields (SRL, SRR, SAM, PRL, PAM, RPD, APD) according to the subfield FSPEC.

- The **remaining decoding failure** (e.g. frame 1: REMOVED at i048_161) is **not** due to a wrong I048/130 encoding definition or wrong struct layout. It is due to the decoder still **consuming 7 bytes for I048/130 when the message-level FSPEC bit is 0** (130 absent). The fix is to ensure the **message-level** presence for the 7th optional (I048/130) is taken from the correct FSPEC bit and stack level so that we **skip** I048/130 when that bit is 0.
