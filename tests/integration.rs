//! Integration tests: parse DSL, encode/decode, validation, frame, and walk-only (no decode/encode).

use aiprotodsl::codec::{Codec, Endianness};
use aiprotodsl::frame;
use aiprotodsl::walk::{message_extent, validate_message_in_place, zero_padding_reserved_in_place, remove_message_in_place, Endianness as WalkEndianness};
use aiprotodsl::{parse, AbstractType, ResolvedProtocol, TypeSpec, Value};
use std::collections::HashMap;

const SIMPLE_PROTO: &str = r#"
message Simple {
  id: u8;
  len: u16;
  data: list<u8>;
}
"#;

const WITH_TRANSPORT: &str = r#"
transport {
  magic: magic("PACK");
  version: u8 = 1;
  length: u32;
  reserved: reserved(2);
}

message Packet {
  type: u8 [0..255];
  count: u16;
  items: list<u8>;
}
"#;

const WITH_CONSTRAINTS: &str = r#"
message Bounded {
  kind: u8 [0..10];
  value: u32 [0..1000];
}
"#;

#[test]
fn test_parse_simple_protocol() {
    let protocol = parse(SIMPLE_PROTO).expect("parse");
    assert!(protocol.transport.is_none());
    assert_eq!(protocol.messages.len(), 1);
    assert_eq!(protocol.messages[0].name, "Simple");
    assert_eq!(protocol.messages[0].fields.len(), 3);
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    assert!(resolved.get_message("Simple").is_some());
}

#[test]
fn test_parse_with_transport() {
    let protocol = parse(WITH_TRANSPORT).expect("parse");
    let transport = protocol.transport.as_ref().expect("transport");
    assert_eq!(transport.fields.len(), 4);
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    assert!(resolved.get_message("Packet").is_some());
}

#[test]
fn test_encode_decode_simple() {
    let protocol = parse(SIMPLE_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Little);

    let mut values = HashMap::new();
    values.insert("id".to_string(), Value::U8(42));
    values.insert("len".to_string(), Value::U16(3));
    values.insert(
        "data".to_string(),
        Value::List(vec![Value::U8(1), Value::U8(2), Value::U8(3)]),
    );

    let encoded = codec.encode_message("Simple", &values).expect("encode");
    assert!(encoded.len() >= 3 + 2 + 1 + 4); // id + len + count(u32 for list) + 3 bytes

    let decoded = codec.decode_message("Simple", &encoded).expect("decode");
    assert_eq!(decoded.get("id").and_then(Value::as_u64), Some(42));
    assert_eq!(decoded.get("len").and_then(Value::as_u64), Some(3));
}

#[test]
fn test_validation_constraint() {
    let protocol = parse(WITH_CONSTRAINTS).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Little);

    let mut values = HashMap::new();
    values.insert("kind".to_string(), Value::U8(5));
    values.insert("value".to_string(), Value::U32(500));
    let encoded = codec.encode_message("Bounded", &values).expect("encode");
    let decoded = codec.decode_message("Bounded", &encoded).expect("decode");
    assert_eq!(decoded.get("kind").and_then(Value::as_u64), Some(5));

    // Decode invalid data (kind = 20 out of range) - should fail validation but still consume bytes
    let mut bad = encoded.clone();
    if bad.len() >= 1 {
        bad[0] = 20;
    }
    let (consumed, result) = codec.decode_message_with_extent("Bounded", &bad);
    assert!(consumed > 0);
    assert!(result.is_err());
}

#[test]
fn test_validation_constraint_multiple_intervals() {
    // Range can be a concatenation of intervals; value valid if in any interval
    let src = r#"
message MultiRange {
  code: u8 [0..2, 10..15, 100..100];
}
"#;
    let protocol = parse(src).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Little);

    for (val, valid) in [(0u8, true), (2, true), (5, false), (10, true), (15, true), (20, false), (100, true)] {
        let mut values = HashMap::new();
        values.insert("code".to_string(), Value::U8(val));
        let encoded = codec.encode_message("MultiRange", &values).expect("encode");
        let result = codec.decode_message("MultiRange", &encoded);
        if valid {
            let decoded = result.expect("decode");
            assert_eq!(decoded.get("code").and_then(Value::as_u64), Some(val as u64));
        } else {
            assert!(result.is_err(), "value {} should fail validation", val);
        }
    }
}

#[test]
fn test_frame_decode_multiple_messages() {
    let protocol = parse(SIMPLE_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Little);

    let mut v1 = HashMap::new();
    v1.insert("id".to_string(), Value::U8(1));
    v1.insert("len".to_string(), Value::U16(0));
    v1.insert("data".to_string(), Value::List(vec![]));
    let mut v2 = HashMap::new();
    v2.insert("id".to_string(), Value::U8(2));
    v2.insert("len".to_string(), Value::U16(0));
    v2.insert("data".to_string(), Value::List(vec![]));

    let b1 = codec.encode_message("Simple", &v1).expect("encode");
    let b2 = codec.encode_message("Simple", &v2).expect("encode");
    let frame_bytes: Vec<u8> = b1.into_iter().chain(b2.into_iter()).collect();

    let result = frame::decode_frame(&codec, "Simple", &frame_bytes, None).expect("frame decode");
    assert_eq!(result.messages.len(), 2);
    assert_eq!(result.removed.len(), 0);
}

#[test]
fn test_padding_reserved_zeroed_on_encode() {
    let src = r#"
transport {
  padding: padding(2);
  value: u16;
}
message M { x: u8; }
"#;
    let protocol = parse(src).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Big);

    let mut tv = HashMap::new();
    tv.insert("value".to_string(), Value::U16(0x1234));
    let encoded = codec.encode_transport(&tv).expect("encode");
    assert_eq!(encoded.len(), 2 + 2);
    assert_eq!(encoded[0], 0);
    assert_eq!(encoded[1], 0);
    assert_eq!(encoded[2], 0x12);
    assert_eq!(encoded[3], 0x34);
}

// --- Walk-only tests (no full decode/encode) ---

#[test]
fn test_walk_message_extent_and_validate() {
    let protocol = parse(SIMPLE_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Little);
    let endianness = WalkEndianness::from(Endianness::Little);

    let mut v = HashMap::new();
    v.insert("id".to_string(), Value::U8(10));
    v.insert("len".to_string(), Value::U16(2));
    v.insert("data".to_string(), Value::List(vec![Value::U8(0xaa), Value::U8(0xbb)]));
    let encoded = codec.encode_message("Simple", &v).expect("encode");

    let extent = message_extent(&encoded, 0, &resolved, endianness, "Simple").expect("extent");
    assert_eq!(extent, encoded.len());

    validate_message_in_place(&encoded, 0, &resolved, endianness, "Simple").expect("valid");

    let protocol_bounded = parse(WITH_CONSTRAINTS).expect("parse");
    let resolved_bounded = ResolvedProtocol::resolve(protocol_bounded).expect("resolve");
    let codec_bounded = Codec::new(resolved_bounded.clone(), Endianness::Little);
    let mut vb = HashMap::new();
    vb.insert("kind".to_string(), Value::U8(5));
    vb.insert("value".to_string(), Value::U32(500));
    let encoded_bounded = codec_bounded.encode_message("Bounded", &vb).expect("encode");
    validate_message_in_place(&encoded_bounded, 0, &resolved_bounded, endianness, "Bounded").expect("valid");

    let mut invalid = encoded_bounded.clone();
    invalid[0] = 20;
    let ok = validate_message_in_place(&invalid, 0, &resolved_bounded, endianness, "Bounded");
    assert!(ok.is_err());
}

#[test]
fn test_walk_zero_padding_reserved_in_place() {
    let src = r#"
message WithReserved {
  a: u8;
  reserved: reserved(2);
  b: u16;
}
"#;
    let protocol = parse(src).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Little);
    let endianness = WalkEndianness::from(Endianness::Little);

    let mut v = HashMap::new();
    v.insert("a".to_string(), Value::U8(1));
    v.insert("b".to_string(), Value::U16(0x1234));
    let mut buf = codec.encode_message("WithReserved", &v).expect("encode");
    buf[1] = 0xff;
    buf[2] = 0xff;

    zero_padding_reserved_in_place(&mut buf, 0, &resolved, endianness, "WithReserved").expect("zero");
    assert_eq!(buf[1], 0);
    assert_eq!(buf[2], 0);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[3], 0x34);
    assert_eq!(buf[4], 0x12);
}

#[test]
fn test_walk_remove_message_in_place() {
    let protocol = parse(SIMPLE_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Little);
    let endianness = WalkEndianness::from(Endianness::Little);

    let mut v1 = HashMap::new();
    v1.insert("id".to_string(), Value::U8(1));
    v1.insert("len".to_string(), Value::U16(0));
    v1.insert("data".to_string(), Value::List(vec![]));
    let mut v2 = HashMap::new();
    v2.insert("id".to_string(), Value::U8(2));
    v2.insert("len".to_string(), Value::U16(0));
    v2.insert("data".to_string(), Value::List(vec![]));

    let b1 = codec.encode_message("Simple", &v1).expect("encode");
    let b2 = codec.encode_message("Simple", &v2).expect("encode");
    let mut frame_bytes: Vec<u8> = b1.into_iter().chain(b2.into_iter()).collect();
    let orig_len = frame_bytes.len();

    let extent1 = message_extent(&frame_bytes, 0, &resolved, endianness, "Simple").expect("extent");
    let new_len = remove_message_in_place(&mut frame_bytes, 0, extent1);
    frame_bytes.truncate(new_len);

    assert_eq!(frame_bytes.len(), orig_len - extent1);
    let extent2 = message_extent(&frame_bytes, 0, &resolved, endianness, "Simple").expect("extent");
    assert_eq!(extent2, frame_bytes.len());
    validate_message_in_place(&frame_bytes, 0, &resolved, endianness, "Simple").expect("valid");
}

// --- Presence bits (ASN.1-style bitmap) ---

const PRESENCE_BITS_PROTO: &str = r#"
message WithPresence {
  flags: presence_bits(1);
  a: optional<u8>;
  b: optional<u16>;
}
"#;

#[test]
fn test_presence_bits_encode_decode() {
    let protocol = parse(PRESENCE_BITS_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Little);

    // Both optionals present: bitmap = 0b11 = 3, then a, then b
    let mut v = HashMap::new();
    v.insert("flags".to_string(), Value::U64(3));
    v.insert("a".to_string(), Value::List(vec![Value::U8(10)]));
    v.insert("b".to_string(), Value::List(vec![Value::U16(0x1234)]));
    let encoded = codec.encode_message("WithPresence", &v).expect("encode");
    assert_eq!(encoded.len(), 1 + 1 + 2); // 1 byte bitmap + u8 + u16
    assert_eq!(encoded[0], 3);
    assert_eq!(encoded[1], 10);
    assert_eq!(encoded[2], 0x34);
    assert_eq!(encoded[3], 0x12);

    let decoded = codec.decode_message("WithPresence", &encoded).expect("decode");
    assert_eq!(decoded.get("flags").and_then(Value::as_u64), Some(3));
    assert_eq!(decoded.get("a"), Some(&Value::U8(10)));
    assert_eq!(decoded.get("b"), Some(&Value::U16(0x1234)));

    // Only first optional present: bitmap = 0b01 = 1, then a only
    let mut v2 = HashMap::new();
    v2.insert("a".to_string(), Value::List(vec![Value::U8(42)]));
    v2.insert("b".to_string(), Value::List(vec![]));
    let encoded2 = codec.encode_message("WithPresence", &v2).expect("encode");
    assert_eq!(encoded2.len(), 1 + 1); // 1 byte bitmap + u8
    assert_eq!(encoded2[0], 1);
    assert_eq!(encoded2[1], 42);

    let decoded2 = codec.decode_message("WithPresence", &encoded2).expect("decode");
    assert_eq!(decoded2.get("flags").and_then(Value::as_u64), Some(1));
    assert_eq!(decoded2.get("a"), Some(&Value::U8(42)));
    assert_eq!(decoded2.get("b"), Some(&Value::List(vec![])));
}

// --- Fspec (ASTERIX-style variable-length FSPEC) ---

const FSPEC_PROTO: &str = r#"
message FspecRecord {
  fspec: fspec;
  a: optional<u8>;
  b: optional<u16>;
}
"#;

#[test]
fn test_fspec_encode_decode() {
    let protocol = parse(FSPEC_PROTO).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Little);

    let mut v = HashMap::new();
    v.insert("fspec".to_string(), Value::Bytes(vec![]));
    v.insert("a".to_string(), Value::List(vec![Value::U8(10)]));
    v.insert("b".to_string(), Value::List(vec![Value::U16(0x1234)]));
    let encoded = codec.encode_message("FspecRecord", &v).expect("encode");
    assert!(encoded.len() >= 2);
    let first_byte = encoded[0];
    assert_eq!(first_byte & 0x7f, 3);
    let decoded = codec.decode_message("FspecRecord", &encoded).expect("decode");
    assert_eq!(decoded.get("a"), Some(&Value::U8(10)));
    assert_eq!(decoded.get("b"), Some(&Value::U16(0x1234)));
}

#[test]
fn test_asterix_family_parse() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/asterix_family.dsl");
    let src = std::fs::read_to_string(&path).expect("read asterix_family.dsl");
    let protocol = parse(&src).expect("parse asterix family");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    assert!(resolved.get_message("Cat001Record").is_some());
    assert!(resolved.get_message("Cat048Record").is_some());
    assert!(resolved.get_message("Cat034Record").is_some());
    assert!(resolved.get_message("Cat240Record").is_some());
    assert!(resolved.get_struct("DataSourceId").is_some());

    // Payload: which messages can follow transport and how to select from category
    let after = resolved.messages_after_transport();
    assert_eq!(after.len(), 5);
    assert!(after.contains(&"Cat001Record".to_string()));
    assert!(after.contains(&"Cat048Record".to_string()));

    let mut transport_values = HashMap::new();
    transport_values.insert("category".to_string(), Value::U8(48));
    transport_values.insert("length".to_string(), Value::U16(10));
    assert_eq!(resolved.message_for_transport_values(&transport_values), Some("Cat048Record"));
    transport_values.insert("category".to_string(), Value::U8(1));
    assert_eq!(resolved.message_for_transport_values(&transport_values), Some("Cat001Record"));
    transport_values.insert("category".to_string(), Value::U8(34));
    assert_eq!(resolved.message_for_transport_values(&transport_values), Some("Cat034Record"));

    assert!(resolved.payload_repeated(), "ASTERIX payload is a list of records per data block (list<...> in selector)");

    // Abstract data model: type definitions (ASN.1-like)
    assert!(resolved.get_type_def("DataSourceId").is_some(), "type DataSourceId");
    assert!(resolved.get_type_def("Cat048Record").is_some(), "type Cat048Record");
    assert!(resolved.get_type_def("Cat002Record").is_some(), "type Cat002Record");
    let td = resolved.get_type_def("DataSourceId").unwrap();
    assert_eq!(td.fields.len(), 2);
    assert_eq!(td.fields[0].name, "sac");
    assert!(!td.fields[0].optional);
    assert!(matches!(td.fields[0].abstract_type, AbstractType::Integer));
    let td048 = resolved.get_type_def("Cat048Record").unwrap();
    assert!(td048.fields.len() > 10, "Cat048Record type should have many fields");
    assert_eq!(td048.fields[0].name, "i048_010");
    assert!(td048.fields[0].optional, "i048_010 should be optional in abstract type");
    assert!(matches!(td048.fields[0].abstract_type, AbstractType::TypeRef(ref s) if s == "DataSourceId"));

    // payload_is_list_for_transport: category=48 -> list<Cat048Record>
    assert!(resolved.payload_is_list_for_transport(&transport_values));

    // Cat002: verify full UAP fields are parsed
    assert!(resolved.get_message("Cat002Record").is_some());
    let cat002 = resolved.get_message("Cat002Record").unwrap();
    // Cat002 has 11 optional fields (010, 000, 020, 030, 041, 050, 060, 070, 100, 090, 080)
    let cat002_optionals: Vec<&str> = cat002.fields.iter()
        .filter(|f| matches!(f.type_spec, TypeSpec::Optional(_)))
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(cat002_optionals.len(), 11);
    assert_eq!(cat002_optionals[0], "i002_010");
    assert_eq!(cat002_optionals[1], "i002_000");
    assert_eq!(cat002_optionals[7], "i002_070");
    assert_eq!(cat002_optionals[10], "i002_080");

    // Cat002 FSPEC mapping with FX bits
    let fspec002 = resolved.fspec_mapping_message("Cat002Record").expect("Cat002Record has fspec");
    assert_eq!(fspec002.optional_fields.len(), 11);
    assert_eq!(fspec002.field_for_bit(0), Some("i002_010"));
    assert_eq!(fspec002.field_for_bit(7), Some("i002_070")); // logical 7 (physical 8, after FX at 7)

    // FSPEC mapping: explicit link between fspec field and the optional fields it governs
    let fspec = resolved.fspec_mapping_message("Cat048Record").expect("Cat048Record has fspec");
    assert_eq!(fspec.fspec_field, "fspec");
    assert!(fspec.optional_fields.len() > 10);
    assert_eq!(fspec.optional_fields[0], "i048_010");
    assert_eq!(fspec.optional_fields[1], "i048_020");
    assert!(fspec.optional_fields.contains(&"i048_161".to_string()));
    // Explicit bit position -> field mapping (FX bits filtered, logical indices)
    assert_eq!(fspec.bit_to_field[0], (0, "i048_010".to_string()));
    assert_eq!(fspec.bit_to_field[1], (1, "i048_020".to_string()));
    assert_eq!(fspec.field_for_bit(0), Some("i048_010"));
    assert_eq!(fspec.bit_for_field("i048_161"), Some(17));
}
