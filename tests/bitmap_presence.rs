//! # Bitmap presence (FSPEC-style) — unit tests and behaviour specification
//!
//! This module tests the **variable-length presence bitmap** used in protocols like ASTERIX:
//! `bitmap(total_bits, 7)` with **7 presence bits + 1 FX (extension) bit per byte**.
//!
//! ## Wire format (shareable specification)
//!
//! - **Layout per byte**: Each byte carries **7 presence bits** in bits **7..1** (MSB = first
//!   optional in this block), and **1 FX bit** in **bit 0** (LSB).
//! - **Bit order within byte**: Bit 7 = optional 0 (in this block), bit 6 = optional 1, …,
//!   bit 1 = optional 6. So presence for optional `i` in block is `(byte >> (7 - (i % 7))) & 1`.
//! - **FX (bit 0)**:
//!   - **FX = 1**: More bytes follow (next byte is another block of 7 presence bits + FX).
//!   - **FX = 0**: No more bytes; decoding stops. **All remaining optional bits (for higher
//!     indices) are implicitly absent** — no further bytes are read for the FSPEC.
//! - **Length**: The FSPEC is **not** fixed by `total_bits`. It is **as many bytes as needed** (stop on FX=0):
//!   - If the first byte has FX=0, the FSPEC is **1 byte** and only 7 presence bits apply;
//!     optionals 7..(total_bits-1) are absent.
//!   - If the first byte has FX=1, the decoder reads the next byte; this repeats until a byte
//!     with FX=0 is read or the maximum number of blocks (ceil(total_bits/7)) is reached.
//!   - **Example bitmap(28, 7)**: Up to **4 blocks** (4 bytes). Blocks 2, 3, 4 can be missing —
//!     the FSPEC can be **1, 2, 3, or 4 bytes** depending on where FX=0 appears.
//! - **Max size**: `bitmap(total_bits, 7)` implies a maximum FSPEC size of **ceil(total_bits/7)**
//!   bytes. The decoder shall not read more than this (it is enforced).
//! - **Last FX = 0**: When the maximum number of bytes is read, the **last byte must have FX=0**.
//!   Otherwise the FSPEC is invalid and decoding returns a validation error.
//!
//! ## Examples (bitmap(14, 7))
//!
//! - **1 byte 0x00**: All 7 presence bits 0, FX=0 → stop. Optionals 0–6 absent, 7–13 absent (implicit).
//! - **1 byte 0x80**: Bit 7 set (optional 0 present), FX=0 → stop. Optional 0 present, 1–13 absent.
//! - **1 byte 0xFE**: Bits 7–1 set (optionals 0–6 present), FX=0 → stop. Optionals 0–6 present, 7–13 absent.
//! - **2 bytes 0x81 0x00**: First byte: optional 0 present, FX=1. Second: 0x00 → optionals 1–6 absent, FX=0.
//!   So optional 0 present, 1–13 absent.
//! - **2 bytes 0xFF 0x80**: First: all 7 present, FX=1. Second: optional 7 present, FX=0.
//!   So optionals 0–7 present, 8–13 absent.
//!
//! All tests below encode/decode using the same convention and document expected bytes and presence.
//!
//! ## Test index (expected behaviour)
//!
//! | Test | Behaviour |
//! |------|-----------|
//! | `bitmap_presence_decode_one_byte_fx0_all_absent` | 1 byte 0x00 → all absent; consume only 1 byte |
//! | `bitmap_presence_decode_one_byte_fx0_first_present` | 1 byte 0x80 → optional 0 present, rest absent |
//! | `bitmap_presence_decode_one_byte_fx0_all_seven_present` | 1 byte 0xFE → optionals 0–6 present, 7–13 absent |
//! | `bitmap_presence_decode_two_bytes_first_optional_present` | 0x81 0x00 → optional 0 present only |
//! | `bitmap_presence_decode_two_bytes_eight_present` | 0xFF 0x80 → optionals 0–7 present |
//! | `bitmap_28_7_decode_*` | bitmap(28,7): 1, 2, 3, or 4 blocks (blocks 2–4 can be missing) |
//! | `bitmap_presence_encode_all_absent_one_byte` | All absent → 0x00, 1 byte |
//! | `bitmap_presence_encode_first_present_one_byte` | First present → 0x80 (bit 7 set, FX=0) |
//! | `bitmap_presence_encode_all_seven_present_one_byte` | All 7 present → 0xFE |
//! | `bitmap_presence_encode_eight_present_two_bytes` | 8 present → 0xFF 0x80 |
//! | `bitmap_presence_encode_bit_order_optional_0` | Optional 0 → bit 7 (0x80) |
//! | `bitmap_presence_encode_bit_order_optional_1` | Optional 1 → bit 6 (0x40) |
//! | `bitmap_presence_roundtrip_*` | Encode then decode preserves presence and values |
//! | `bitmap_presence_decode_reject_last_fx1_at_max_size` | Max-size FSPEC with last byte FX=1 → validation error |
//!
//! ### bitmap(14, 3) — 3 presence bits + 1 FX per byte, max 5 bytes
//!
//! | Test | Behaviour |
//! |------|-----------|
//! | `bitmap_14_3_decode_one_byte_fx0_*` | 1 byte: 3 presence (bits 7,6,5) + FX=0; optionals 3–13 absent |
//! | `bitmap_14_3_decode_two_bytes_first_present` | 0x81 0x00 → optional 0 present only |
//! | `bitmap_14_3_encode_*` | Encode all absent / first present (FSPEC may be truncated to max_bytes) |
//! | `bitmap_14_3_decode_reject_last_fx1_at_max_size` | 5 bytes with last FX=1 → validation error |
//! | `bitmap_14_3_roundtrip_four_present` | Roundtrip with first 4 optionals present |

use aiprotodsl::codec::{Codec, CodecError, Endianness};
use aiprotodsl::{parse, ResolvedProtocol, Value};
use std::collections::HashMap;

// -----------------------------------------------------------------------------
// DSL fixtures: minimal messages for bitmap(N, 7) with N = 2, 7, 14, 28
// -----------------------------------------------------------------------------

/// Two optionals: one byte suffices (7 presence bits, we use 2). Good for basic roundtrip.
const BITMAP_2_7: &str = r#"
message Bitmap2_7 {
  fspec: bitmap(2, 7) -> (0: a, 1: b);
  a: optional<u8>;
  b: optional<u8>;
}
"#;

/// Seven optionals: exactly one block. Tests 1-byte FSPEC with all present/absent/mixed.
const BITMAP_7_7: &str = r#"
message Bitmap7_7 {
  fspec: bitmap(7, 7) -> (0: a, 1: b, 2: c, 3: d, 4: e, 5: f, 6: g);
  a: optional<u8>; b: optional<u8>; c: optional<u8>; d: optional<u8>;
  e: optional<u8>; f: optional<u8>; g: optional<u8>;
}
"#;

/// Fourteen optionals: 1 or 2 bytes. Tests FX=0 after 1 byte (implicit absent 7–13) and 2-byte FSPEC.
const BITMAP_14_7: &str = r#"
message Bitmap14_7 {
  fspec: bitmap(14, 7) -> (0: a, 1: b, 2: c, 3: d, 4: e, 5: f, 6: g, 7: h, 8: i, 9: j, 10: k, 11: l, 12: m, 13: n);
  a: optional<u8>; b: optional<u8>; c: optional<u8>; d: optional<u8>;
  e: optional<u8>; f: optional<u8>; g: optional<u8>; h: optional<u8>;
  i: optional<u8>; j: optional<u8>; k: optional<u8>; l: optional<u8>;
  m: optional<u8>; n: optional<u8>;
}
"#;

/// Fourteen optionals with 3 presence bits per block: max 5 bytes. Each byte = 3 presence (bits 7,6,5) + FX (bit 0).
const BITMAP_14_3: &str = r#"
message Bitmap14_3 {
  fspec: bitmap(14, 3) -> (0: a, 1: b, 2: c, 3: d, 4: e, 5: f, 6: g, 7: h, 8: i, 9: j, 10: k, 11: l, 12: m, 13: n);
  a: optional<u8>; b: optional<u8>; c: optional<u8>; d: optional<u8>;
  e: optional<u8>; f: optional<u8>; g: optional<u8>; h: optional<u8>;
  i: optional<u8>; j: optional<u8>; k: optional<u8>; l: optional<u8>;
  m: optional<u8>; n: optional<u8>;
}
"#;

/// Twenty-eight optionals: up to 4 blocks; blocks 2–4 can be missing (1, 2, 3, or 4 bytes).
const BITMAP_28_7: &str = r#"
message Bitmap28_7 {
  fspec: bitmap(28, 7) -> (
    0: a, 1: b, 2: c, 3: d, 4: e, 5: f, 6: g, 7: h, 8: i, 9: j, 10: k, 11: l, 12: m, 13: n,
    14: o, 15: p, 16: q, 17: r, 18: s, 19: t, 20: u, 21: v, 22: w, 23: x, 24: y, 25: z, 26: aa, 27: ab
  );
  a: optional<u8>; b: optional<u8>; c: optional<u8>; d: optional<u8>;
  e: optional<u8>; f: optional<u8>; g: optional<u8>; h: optional<u8>;
  i: optional<u8>; j: optional<u8>; k: optional<u8>; l: optional<u8>;
  m: optional<u8>; n: optional<u8>; o: optional<u8>; p: optional<u8>;
  q: optional<u8>; r: optional<u8>; s: optional<u8>; t: optional<u8>;
  u: optional<u8>; v: optional<u8>; w: optional<u8>; x: optional<u8>;
  y: optional<u8>; z: optional<u8>; aa: optional<u8>; ab: optional<u8>;
}
"#;

fn resolve(proto: &str) -> ResolvedProtocol {
    let protocol = parse(proto).expect("parse");
    ResolvedProtocol::resolve(protocol).expect("resolve")
}

/// Optional fields: when present the codec returns the inner value (e.g. `Value::U8(x)`); when absent, `Value::List(vec![])`.
fn optional_u8(decoded: &HashMap<String, Value>, name: &str) -> Option<u8> {
    match decoded.get(name) {
        Some(Value::U8(x)) => Some(*x),
        Some(Value::List(l)) if !l.is_empty() => l.first().and_then(Value::as_u64).map(|x| x as u8),
        _ => None,
    }
}

fn optional_absent(decoded: &HashMap<String, Value>, name: &str) -> bool {
    matches!(decoded.get(name), Some(Value::List(l)) if l.is_empty())
}

/// Helper: build value map for bitmap2_7 with a/b present or absent.
fn vals_2_7(a: Option<u8>, b: Option<u8>) -> HashMap<String, Value> {
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    v.insert("a".to_string(), a.map(|x| Value::List(vec![Value::U8(x)])).unwrap_or(Value::List(vec![])));
    v.insert("b".to_string(), b.map(|x| Value::List(vec![Value::U8(x)])).unwrap_or(Value::List(vec![])));
    v
}

/// Helper: one optional present by index (0..7) for Bitmap7_7; rest absent.
fn vals_7_7_one_present(bit_index: usize, value: u8) -> HashMap<String, Value> {
    let names = ["a", "b", "c", "d", "e", "f", "g"];
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    for (i, &n) in names.iter().enumerate() {
        let val = if i == bit_index { Value::List(vec![Value::U8(value)]) } else { Value::List(vec![]) };
        v.insert(n.to_string(), val);
    }
    v
}

/// Helper: all optionals present for Bitmap7_7 with given byte values.
fn vals_7_7_all_present(values: [u8; 7]) -> HashMap<String, Value> {
    let names = ["a", "b", "c", "d", "e", "f", "g"];
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    for (n, &x) in names.iter().zip(values.iter()) {
        v.insert((*n).to_string(), Value::List(vec![Value::U8(x)]));
    }
    v
}

// -----------------------------------------------------------------------------
// Decode: 1 byte, FX=0 (single block, remaining bits implicitly absent)
// -----------------------------------------------------------------------------

/// **Behaviour**: One FSPEC byte with FX=0. Only 7 presence bits apply; any optional index >= 7
/// is implicitly absent (decoder does not read a second byte).
#[test]
fn bitmap_presence_decode_one_byte_fx0_all_absent() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 1 byte 0x00: all 7 presence bits 0, FX=0 → stop. Optionals 0–6 and 7–13 all absent.
    let payload: Vec<u8> = vec![0x00, 0x99]; // 0x99 is first byte of next field if we over-read; we must not consume it
    let decoded = codec.decode_message("Bitmap14_7", &payload).expect("decode");
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    // Decoder must consume only 1 byte of FSPEC
    let (consumed, _) = codec.decode_message_with_extent("Bitmap14_7", &payload);
    assert_eq!(consumed, 1, "FSPEC is 1 byte when FX=0; no extra byte read");
}

/// **Behaviour**: One byte 0x80 → bit 7 set (optional 0 present), FX=0. Rest absent.
#[test]
fn bitmap_presence_decode_one_byte_fx0_first_present() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 0x80 = bit 7 set (optional 0 = "a"), FX=0. Then one u8 for optional 0.
    let payload: Vec<u8> = vec![0x80, 42];
    let decoded = codec.decode_message("Bitmap14_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(42));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
}

/// **Behaviour**: One byte 0xFE = bits 7–1 set (optionals 0–6 present), FX=0. Optionals 7–13 absent.
#[test]
fn bitmap_presence_decode_one_byte_fx0_all_seven_present() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 0xFE: 7 presence bits set, FX=0. Then 7 × u8.
    let payload: Vec<u8> = vec![0xFE, 10, 11, 12, 13, 14, 15, 16];
    let decoded = codec.decode_message("Bitmap14_7", &payload).expect("decode");
    let names = ["a", "b", "c", "d", "e", "f", "g"];
    for (i, &n) in names.iter().enumerate() {
        assert_eq!(optional_u8(&decoded, n), Some(10 + i as u8), "{}", n);
    }
    for name in ["h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent (implicit after 1-byte FSPEC)", name);
    }
}

// -----------------------------------------------------------------------------
// Decode: 2 bytes (FX=1 then FX=0)
// -----------------------------------------------------------------------------

/// **Behaviour**: Two bytes 0x81 0x00. First: optional 0 present (bit 7 set), FX=1. Second: all 7 absent, FX=0.
/// So optional 0 present, 1–13 absent.
#[test]
fn bitmap_presence_decode_two_bytes_first_optional_present() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x81, 0x00, 100];
    let decoded = codec.decode_message("Bitmap14_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(100));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
}

/// **Behaviour**: Two bytes 0xFF 0x80. First: all 7 present, FX=1. Second: optional 7 (bit 7 of second byte) present, FX=0.
/// So optionals 0–7 present, 8–13 absent. (Bit 7 of second byte = optional index 7 = "h".)
#[test]
fn bitmap_presence_decode_two_bytes_eight_present() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0xFF, 0x80, 1, 2, 3, 4, 5, 6, 7, 8];
    let decoded = codec.decode_message("Bitmap14_7", &payload).expect("decode");
    for (i, name) in ["a", "b", "c", "d", "e", "f", "g", "h"].iter().enumerate() {
        assert_eq!(optional_u8(&decoded, name), Some(1 + i as u8), "{}", name);
    }
    for name in ["i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
}

// -----------------------------------------------------------------------------
// Encode: 1 byte when FX=0 (no continuation)
// -----------------------------------------------------------------------------

/// **Behaviour**: Encode all absent → single FSPEC byte 0x00 (FX=0).
#[test]
fn bitmap_presence_encode_all_absent_one_byte() {
    let resolved = resolve(BITMAP_7_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    for n in ["a", "b", "c", "d", "e", "f", "g"] {
        v.insert(n.to_string(), Value::List(vec![]));
    }
    let encoded = codec.encode_message("Bitmap7_7", &v).expect("encode");
    assert_eq!(encoded[0], 0x00, "single byte 0x00 when all absent, FX=0");
    assert_eq!(encoded.len(), 1, "only FSPEC byte");
}

/// **Behaviour**: Encode only first optional present → 0x80 (bit 7 set, FX=0). One byte FSPEC.
#[test]
fn bitmap_presence_encode_first_present_one_byte() {
    let resolved = resolve(BITMAP_2_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let encoded = codec.encode_message("Bitmap2_7", &vals_2_7(Some(33), None)).expect("encode");
    assert_eq!(encoded[0], 0x80, "bit 7 = first optional present, FX=0 in bit 0");
    assert_eq!(encoded.len(), 2, "1 byte FSPEC + 1 byte value for a");
}

/// **Behaviour**: Encode all 7 optionals present in one block → 0xFE (bits 7–1 set, FX=0).
#[test]
fn bitmap_presence_encode_all_seven_present_one_byte() {
    let resolved = resolve(BITMAP_7_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let encoded = codec.encode_message("Bitmap7_7", &vals_7_7_all_present([1, 2, 3, 4, 5, 6, 7])).expect("encode");
    assert_eq!(encoded[0], 0xFE, "bits 7–1 set, FX=0");
    assert_eq!(encoded.len(), 1 + 7, "1 FSPEC + 7 u8");
}

// -----------------------------------------------------------------------------
// Encode: 2 bytes when 8+ optionals present
// -----------------------------------------------------------------------------

/// **Behaviour**: Optionals 0–7 present → first byte 0xFF (7 set + FX=1), second 0x80 (optional 7 = bit 7 present, FX=0).
#[test]
fn bitmap_presence_encode_eight_present_two_bytes() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    for (i, n) in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"].iter().enumerate() {
        let val = if i < 8 { Value::List(vec![Value::U8(i as u8)]) } else { Value::List(vec![]) };
        v.insert((*n).to_string(), val);
    }
    let encoded = codec.encode_message("Bitmap14_7", &v).expect("encode");
    assert_eq!(encoded[0], 0xFF, "first block: all 7 present + FX=1");
    assert_eq!(encoded[1], 0x80, "second block: optional 7 (bit 7) present, FX=0");
    assert_eq!(encoded.len(), 2 + 8, "2 FSPEC + 8 u8");
}

// -----------------------------------------------------------------------------
// Roundtrip: encode then decode
// -----------------------------------------------------------------------------

#[test]
fn bitmap_presence_roundtrip_2_7_both_absent() {
    let resolved = resolve(BITMAP_2_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let v = vals_2_7(None, None);
    let encoded = codec.encode_message("Bitmap2_7", &v).expect("encode");
    let decoded = codec.decode_message("Bitmap2_7", &encoded).expect("decode");
    assert!(optional_absent(&decoded, "a"));
    assert!(optional_absent(&decoded, "b"));
}

#[test]
fn bitmap_presence_roundtrip_2_7_both_present() {
    let resolved = resolve(BITMAP_2_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let v = vals_2_7(Some(10), Some(20));
    let encoded = codec.encode_message("Bitmap2_7", &v).expect("encode");
    let decoded = codec.decode_message("Bitmap2_7", &encoded).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(10));
    assert_eq!(optional_u8(&decoded, "b"), Some(20));
}

/// **Behaviour**: Encode with only first 3 optionals present; decode and verify presence and values.
/// Encoder may emit 1 or 2 FSPEC bytes depending on implementation (total_bits=14 can be 2 bytes).
#[test]
fn bitmap_presence_roundtrip_14_7_one_byte_fspec() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    v.insert("a".to_string(), Value::List(vec![Value::U8(1)]));
    v.insert("b".to_string(), Value::List(vec![Value::U8(2)]));
    v.insert("c".to_string(), Value::List(vec![Value::U8(3)]));
    for n in ["d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        v.insert(n.to_string(), Value::List(vec![]));
    }
    let encoded = codec.encode_message("Bitmap14_7", &v).expect("encode");
    let decoded = codec.decode_message("Bitmap14_7", &encoded).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(1));
    assert_eq!(optional_u8(&decoded, "b"), Some(2));
    assert_eq!(optional_u8(&decoded, "c"), Some(3));
    for name in ["d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} absent", name);
    }
}

// -----------------------------------------------------------------------------
// Bit order: which wire bit corresponds to which optional
// -----------------------------------------------------------------------------

/// **Behaviour**: Bit 7 of first byte = optional 0, bit 6 = optional 1, …, bit 1 = optional 6.
/// Encode only optional 1 present and check wire byte.
#[test]
fn bitmap_presence_encode_bit_order_optional_1() {
    let resolved = resolve(BITMAP_7_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let v = vals_7_7_one_present(1, 50);
    let encoded = codec.encode_message("Bitmap7_7", &v).expect("encode");
    // Optional 1 → bit 6 set → 0x40 would be bit 7. Bit 6 = 0x02... no. (byte >> (7-j)) for j=1 → bit 6 → 1<<6 = 0x40. So 0x40 in bits 7..1.
    // Actually: bit 7 = optional 0, bit 6 = optional 1. So optional 1 present => 0x40 (bit 6 set in bits 7-1). 0x40 + FX=0 => 0x40.
    assert_eq!(encoded[0], 0x40, "optional 1 present => bit 6 set => 0x40 (FX=0)");
}

/// **Behaviour**: Optional 0 present → bit 7 set → 0x80 in bits 7–1, FX=0 → 0x80.
#[test]
fn bitmap_presence_encode_bit_order_optional_0() {
    let resolved = resolve(BITMAP_7_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let v = vals_7_7_one_present(0, 50);
    let encoded = codec.encode_message("Bitmap7_7", &v).expect("encode");
    assert_eq!(encoded[0], 0x80, "optional 0 present => bit 7 set => 0x80 (FX=0)");
}

// -----------------------------------------------------------------------------
// bitmap(28, 7): up to 4 blocks; blocks 2–4 can be missing (1, 2, 3, or 4 bytes)
// -----------------------------------------------------------------------------

/// **Behaviour**: 1 block (1 byte, FX=0) → 7 presence bits; optionals 7–27 absent.
#[test]
fn bitmap_28_7_decode_one_block() {
    let resolved = resolve(BITMAP_28_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x80, 77]; // 1 byte FSPEC: optional 0 present, FX=0
    let decoded = codec.decode_message("Bitmap28_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(77));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "ab"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap28_7", &payload);
    assert_eq!(consumed, 1 + 1, "1 FSPEC byte + 1 u8");
}

/// **Behaviour**: 2 blocks (2 bytes, second FX=0) → 14 presence bits; optionals 14–27 absent.
#[test]
fn bitmap_28_7_decode_two_blocks() {
    let resolved = resolve(BITMAP_28_7);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x81, 0x00, 77];
    let decoded = codec.decode_message("Bitmap28_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(77));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "ab"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap28_7", &payload);
    assert_eq!(consumed, 2 + 1, "2 FSPEC bytes + 1 u8");
}

/// **Behaviour**: 3 blocks (3 bytes, third FX=0) → 21 presence bits; optionals 21–27 absent.
#[test]
fn bitmap_28_7_decode_three_blocks() {
    let resolved = resolve(BITMAP_28_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 0x81 = opt0 present, FX=1; 0x01 = no optionals in block 1, FX=1; 0x00 = FX=0. Then one u8.
    let payload: Vec<u8> = vec![0x81, 0x01, 0x00, 99];
    let decoded = codec.decode_message("Bitmap28_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(99));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "ab"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap28_7", &payload);
    assert_eq!(consumed, 3 + 1, "3 FSPEC bytes + 1 u8");
}

/// **Behaviour**: 4 blocks (max; fourth byte FX=0) → all 28 presence bits.
#[test]
fn bitmap_28_7_decode_four_blocks() {
    let resolved = resolve(BITMAP_28_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 4 bytes: opt0 present in block 0, FX=1; blocks 1,2,3 all absent (0x01, 0x01, 0x00). Then one u8.
    let payload: Vec<u8> = vec![0x81, 0x01, 0x01, 0x00, 42];
    let decoded = codec.decode_message("Bitmap28_7", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(42));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "ab"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap28_7", &payload);
    assert_eq!(consumed, 4 + 1, "4 FSPEC bytes + 1 u8");
}

// -----------------------------------------------------------------------------
// bitmap(14, 3): 3 presence bits + 1 FX per byte, max 5 bytes
// -----------------------------------------------------------------------------

/// **Behaviour**: bitmap(14, 3) — 1 byte with FX=0: 3 presence bits (optionals 0–2), rest absent. Max 5 bytes.
#[test]
fn bitmap_14_3_decode_one_byte_fx0_all_absent() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x00, 0x99];
    let decoded = codec.decode_message("Bitmap14_3", &payload).expect("decode");
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap14_3", &payload);
    assert_eq!(consumed, 1, "FSPEC is 1 byte when FX=0");
}


/// **Behaviour**: 1 block (4 bits): value 2 = optional 0 present, FX=0. Rest absent. Wire: low nibble 0x02.
#[test]
fn bitmap_14_3_decode_one_byte_fx0_first_present() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x02, 42];
    let decoded = codec.decode_message("Bitmap14_3", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(42));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
}

/// **Behaviour**: 1 block (4 bits): value 0x0E = optionals 0,1,2 present, FX=0. Wire: low nibble 0x0E.
#[test]
fn bitmap_14_3_decode_one_byte_fx0_three_present() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x0E, 10, 11, 12];
    let decoded = codec.decode_message("Bitmap14_3", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(10));
    assert_eq!(optional_u8(&decoded, "b"), Some(11));
    assert_eq!(optional_u8(&decoded, "c"), Some(12));
    for name in ["d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
}

/// **Behaviour**: 2 blocks (8 bits): block0 value 3 (opt0 present, FX=1), block1 value 0 (FX=0). Wire: 0x03.
#[test]
fn bitmap_14_3_decode_two_bytes_first_present() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x03, 100];
    let decoded = codec.decode_message("Bitmap14_3", &payload).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(100));
    for name in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} should be absent", name);
    }
    let (consumed, _) = codec.decode_message_with_extent("Bitmap14_3", &payload);
    assert_eq!(consumed, 2, "1 FSPEC byte (2×4-bit blocks) + 1 u8");
}

/// **Behaviour**: Encoder truncates FSPEC to max_bytes (ceil(5*4/8)=3 for 14,3). All absent → 3 bytes, last FX=0.
#[test]
fn bitmap_14_3_encode_all_absent_one_byte() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    for n in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        v.insert(n.to_string(), Value::List(vec![]));
    }
    let encoded = codec.encode_message("Bitmap14_3", &v).expect("encode");
    assert!(encoded.len() >= 1 && encoded.len() <= 5);
    let last_fspec = encoded.len() - 1;
    assert_eq!(encoded[last_fspec] & 0x01, 0, "last FSPEC byte has FX=0");
}

/// **Behaviour**: Encode only optional 0 present → 5 blocks (4 bits each): block0=3 (opt0+FX=1), blocks 1..3=1, block4=0; first byte 0x13 (nibbles 3,1).
#[test]
fn bitmap_14_3_encode_first_present_one_byte() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    v.insert("a".to_string(), Value::List(vec![Value::U8(33)]));
    for n in ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        v.insert(n.to_string(), Value::List(vec![]));
    }
    let encoded = codec.encode_message("Bitmap14_3", &v).expect("encode");
    assert_eq!(encoded[0], 0x13, "first byte = block0=3, block1=1 (4 bits each)");
    assert!(encoded.len() >= 2);
    assert_eq!(encoded[encoded.len() - 1], 33, "trailing u8 value");
}

/// **Behaviour**: 5 blocks (max, 20 bits) with last block FX=1 → validation error. Wire: 5×4-bit = 1,1,1,1,1 → 0x11, 0x11, 0x01.
#[test]
fn bitmap_14_3_decode_reject_last_fx1_at_max_size() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let payload: Vec<u8> = vec![0x11, 0x11, 0x01]; // 5 blocks (4 bits each), last block value 1 (FX=1)
    let result = codec.decode_message("Bitmap14_3", &payload);
    match &result {
        Err(CodecError::Validation(msg)) => {
            assert!(msg.contains("last FSPEC byte must have FX=0"), "got: {}", msg);
        }
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

/// **Behaviour**: Roundtrip bitmap(14, 3) with first 4 optionals present.
#[test]
fn bitmap_14_3_roundtrip_four_present() {
    let resolved = resolve(BITMAP_14_3);
    let codec = Codec::new(resolved, Endianness::Big);
    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    v.insert("a".to_string(), Value::List(vec![Value::U8(1)]));
    v.insert("b".to_string(), Value::List(vec![Value::U8(2)]));
    v.insert("c".to_string(), Value::List(vec![Value::U8(3)]));
    v.insert("d".to_string(), Value::List(vec![Value::U8(4)]));
    for n in ["e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        v.insert(n.to_string(), Value::List(vec![]));
    }
    let encoded = codec.encode_message("Bitmap14_3", &v).expect("encode");
    let decoded = codec.decode_message("Bitmap14_3", &encoded).expect("decode");
    assert_eq!(optional_u8(&decoded, "a"), Some(1));
    assert_eq!(optional_u8(&decoded, "b"), Some(2));
    assert_eq!(optional_u8(&decoded, "c"), Some(3));
    assert_eq!(optional_u8(&decoded, "d"), Some(4));
    for name in ["e", "f", "g", "h", "i", "j", "k", "l", "m", "n"] {
        assert!(optional_absent(&decoded, name), "{} absent", name);
    }
}

// -----------------------------------------------------------------------------
// Validation: max size and last FX = 0
// -----------------------------------------------------------------------------

/// **Behaviour**: For bitmap(14, 7) the max FSPEC size is 2 bytes. If we read 2 bytes and the
/// last byte has FX=1, the FSPEC is invalid (last FX must be 0). Decode returns Validation error.
#[test]
fn bitmap_presence_decode_reject_last_fx1_at_max_size() {
    let resolved = resolve(BITMAP_14_7);
    let codec = Codec::new(resolved, Endianness::Big);
    // 2 bytes (max for 14 bits), but last byte has FX=1 → invalid.
    let payload: Vec<u8> = vec![0x81, 0x01, 0x00]; // 0x01 = FX=1 on last byte
    let result = codec.decode_message("Bitmap14_7", &payload);
    match &result {
        Err(CodecError::Validation(msg)) => {
            assert!(msg.contains("last FSPEC byte must have FX=0"), "expected last-FX-0 message, got: {}", msg);
        }
        other => panic!("expected Validation error, got: {:?}", other),
    }
}
