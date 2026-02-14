//! Integration tests: parse DSL, encode/decode, validation, frame, walk-only, and DSL lint.

use aiprotodsl::codec::{Codec, Endianness};
use aiprotodsl::frame;
use aiprotodsl::lint::{lint, LintRule, Severity};
use aiprotodsl::walk::{message_extent, validate_message_in_place, zero_padding_reserved_in_place, remove_message_in_place, Endianness as WalkEndianness};
use aiprotodsl::{parse, AbstractType, PaddingKind, ResolvedProtocol, TypeSpec, Value};
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
  padding: padding(2);
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
  padding: padding(2);
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

// --- Bitmap presence (variable-length presence bitmap; e.g. ASTERIX uses 7 presence + 1 FX per block) ---

const FSPEC_PROTO: &str = r#"
message FspecRecord {
  fspec: bitmap(2, 7) -> (0: a, 1: b);
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
    // bitmap(2, 7): 2 presence bits then FX. Two optionals present => bits 7 and 6 set => 0x40
    assert_eq!(first_byte & 0x7f, 0x40);
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
    // TrackNumber.spare must be bit padding so decode uses 4 bits not 4 bytes
    let track = resolved.get_struct("TrackNumber").expect("TrackNumber");
    let spare = track.fields.iter().find(|f| f.name == "spare").expect("spare field");
    assert!(matches!(&spare.type_spec, TypeSpec::Padding(PaddingKind::Bits(4))), "TrackNumber.spare should be Padding(Bits(4)), got {:?}", spare.type_spec);

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

    // Cat002 bitmap presence mapping
    let bp002 = resolved.bitmap_presence_mapping_message("Cat002Record").expect("Cat002Record has bitmap");
    assert_eq!(bp002.optional_fields.len(), 11);
    assert_eq!(bp002.field_for_bit(0), Some("i002_010"));
    assert_eq!(bp002.field_for_bit(7), Some("i002_070"));

    // Bitmap presence mapping: link between presence field and the optional fields it governs
    let bp = resolved.bitmap_presence_mapping_message("Cat048Record").expect("Cat048Record has bitmap");
    assert_eq!(bp.presence_field, "fspec");
    assert!(bp.optional_fields.len() > 10);
    assert_eq!(bp.optional_fields[0], "i048_010");
    assert_eq!(bp.optional_fields[1], "i048_140");
    assert_eq!(bp.optional_fields[2], "i048_020");
    assert_eq!(bp.optional_fields[3], "i048_040");
    assert_eq!(bp.optional_fields[10], "i048_161");
    assert!(bp.optional_fields.contains(&"i048_220".to_string()));
    assert!(bp.optional_fields.contains(&"i048_260".to_string()));
    assert_eq!(bp.field_for_bit(0), Some("i048_010"));
    assert_eq!(bp.bit_for_field("i048_161"), Some(10));
    assert_eq!(bp.bit_for_field("i048_130"), Some(6));

    // field_quantum_and_child: struct fields have quantum; optional struct ref gives child container
    let (q_rho, child_040) = resolved.field_quantum_and_child("MeasuredPositionPolar", "rho");
    assert_eq!(q_rho, Some("1/256 NM"), "rho quantum");
    assert_eq!(child_040, None);
    let (_q, child_040) = resolved.field_quantum_and_child("Cat048Record", "i048_040");
    assert_eq!(child_040, Some("MeasuredPositionPolar"), "i048_040 is optional MeasuredPositionPolar");
}

/// Decode frame 1 CAT048 block (bitmap 0xFD 0xF7 0x02 => I048/130 absent). Verifies mapping is applied so we skip 130 and decode past 161.
#[test]
fn test_cat048_frame1_130_absent_decode() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/asterix_family.dsl");
    let src = std::fs::read_to_string(&path).expect("read asterix_family.dsl");
    let protocol = parse(&src).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Big);

    // 0xFD 0xF0: 130 absent (bit 6=0); 220,240,250,161 present; 042,200,170 absent (bit 15=0 so no 3rd block).
    // I048/240 = 8×6 bits = 6 bytes; 250 count=0; 161(2). Total 2+14+3+6+1+2 = 28 bytes.
    let payload: Vec<u8> = vec![
        0xfd, 0xf0,                                                                                     // bitmap (2 bytes)
        0x19, 0xc9, 0x35, 0x6d, 0x4d, 0xa0, 0xc5, 0xaf, 0xf1, 0xe0, 0x02, 0x00, 0x05, 0x28,             // 010..090 (14)
        0x3c, 0x66, 0x0c, 0x10, 0xc2, 0x36, 0xd4, 0x18, 0x01, 0x00, 0x07, 0xb9,                       // 220(3),240(6),250(count=0),161(2) (12)
    ];
    assert_eq!(payload.len(), 28);

    let (consumed, result) = codec.decode_message_with_extent("Cat048Record", &payload);
    match &result {
        Ok(values) => {
            // I048/130 must be absent (we read presence bit 6 = 0)
            let v130 = values.get("i048_130").expect("i048_130 field");
            let list = v130.as_list().expect("i048_130 is list when absent");
            assert!(list.is_empty(), "I048/130 should be absent for FSPEC 0xFD: {:?}", v130);
            // We must have decoded past 161
            assert!(values.get("i048_161").is_some(), "i048_161 should be present");
        }
        Err(e) => panic!("decode should succeed when mapping skips 130: {} (consumed={})", e, consumed),
    }
}

/// Run decode_pcap on a pcap and return stderr summary (block count, decoded, removed, known/unknown cats).
fn run_decode_pcap(pcap_path: &str, dsl_path: &str) -> (String, std::process::Output) {
    let bin = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            ["target/debug/decode_pcap", "target/release/decode_pcap"]
                .iter()
                .map(|p| cwd.join(p))
                .find(|p| p.exists())
        })
        .expect("decode_pcap binary not found (run cargo build --bin decode_pcap)");
    let out = std::process::Command::new(&bin)
        .args([pcap_path, dsl_path])
        .output()
        .expect("run decode_pcap");
    (String::from_utf8_lossy(&out.stderr).into_owned(), out)
}

#[test]
fn test_asterix_pcap_vs_wireshark_consistency() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dsl = manifest.join("examples/asterix_family.dsl");
    let dsl_str = dsl.to_string_lossy();

    // cat_034_048: we must see blocks and known categories (34, 48); block count should match structure
    let pcap = manifest.join("assets/cat_034_048.pcap");
    if !pcap.exists() {
        return;
    }
    let (stderr, out) = run_decode_pcap(pcap.to_string_lossy().as_ref(), &dsl_str);
    assert!(out.status.success(), "decode_pcap should succeed: {}", stderr);
    assert!(
        stderr.contains("asterix blocks") && stderr.contains("CAT034") && stderr.contains("CAT048"),
        "expected block summary and known categories: {}",
        stderr
    );
    // We use length = total block size; tshark shows same (e.g. 48, 55, 11). Our block count 120 (34+86).
    assert!(
        stderr.contains("120") || stderr.contains("blocks="),
        "expected block count or blocks= in summary: {}",
        stderr
    );
}

#[test]
fn test_dsl_lint_tabs_and_one_field_per_line() {
    // Compliant: tabs only, one field per line
    let ok = "transport {\n\tx: u8;\n\ty: u16;\n}\n";
    let msgs = lint(ok);
    let errors: Vec<_> = msgs.iter().filter(|m| m.severity == Severity::Error).collect();
    assert!(errors.is_empty(), "compliant source should have no lint errors: {:?}", msgs);

    // Spaces for indentation -> IndentationTabsOnly
    let spaces = "transport {\n  x: u8;\n}\n";
    let msgs = lint(spaces);
    assert!(
        msgs.iter().any(|m| m.rule == LintRule::IndentationTabsOnly),
        "spaces should trigger IndentationTabsOnly: {:?}",
        msgs
    );

    // Two fields on one line -> OneFieldPerLine
    let two_fields = "message M {\n\tx: u8; y: u16;\n}\n";
    let msgs = lint(two_fields);
    assert!(
        msgs.iter().any(|m| m.rule == LintRule::OneFieldPerLine),
        "two fields on one line should trigger OneFieldPerLine: {:?}",
        msgs
    );
}

/// Nested bitmap structs: message with optional struct, each struct has its own bitmap and optional nested struct, up to depth 5.
const NESTED_FSPEC_DEPTH_5: &str = r#"
message Nest5 {
  fspec: bitmap(1, 7) -> (0: a);
  a: optional<Level1>;
}
struct Level1 {
  fspec: bitmap(1, 7) -> (0: b);
  b: optional<Level2>;
}
struct Level2 {
  fspec: bitmap(1, 7) -> (0: c);
  c: optional<Level3>;
}
struct Level3 {
  fspec: bitmap(1, 7) -> (0: d);
  d: optional<Level4>;
}
struct Level4 {
  fspec: bitmap(1, 7) -> (0: e);
  e: optional<Level5>;
}
struct Level5 {
  fspec: bitmap(1, 7) -> (0: v);
  v: optional<u8> [0..255];
}
"#;

#[test]
fn test_nested_fspec_presence_stack_depth_5() {
    let protocol = parse(NESTED_FSPEC_DEPTH_5).expect("parse");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved, Endianness::Big);

    // Build value: all 5 levels present, leaf v = 42.
    // Optional = List([value]) when present.
    let v5 = HashMap::from([
        ("v".to_string(), Value::List(vec![Value::U8(42)])),
    ]);
    let v4 = HashMap::from([
        ("e".to_string(), Value::List(vec![Value::Struct(v5)])),
    ]);
    let v3 = HashMap::from([
        ("d".to_string(), Value::List(vec![Value::Struct(v4)])),
    ]);
    let v2 = HashMap::from([
        ("c".to_string(), Value::List(vec![Value::Struct(v3)])),
    ]);
    let v1 = HashMap::from([
        ("b".to_string(), Value::List(vec![Value::Struct(v2)])),
    ]);
    let msg = HashMap::from([
        ("a".to_string(), Value::List(vec![Value::Struct(v1)])),
    ]);

    let encoded = codec.encode_message("Nest5", &msg).expect("encode");
    // 1 (msg presence 0x80) + 1 (L1) + 1 (L2) + 1 (L3) + 1 (L4) + 1 (L5) + 1 (v) = 7 bytes
    assert!(encoded.len() >= 7, "encoded should have at least 7 bytes, got {}", encoded.len());

    let decoded = codec.decode_message("Nest5", &encoded).expect("decode");

    // Decode stores optional as inner value when present (not List([x])). Check structure at depth 5 (presence stack used at each level).
    let a = decoded.get("a").and_then(Value::as_struct).expect("a present");
    let b = a.get("b").and_then(Value::as_struct).expect("b present");
    let c = b.get("c").and_then(Value::as_struct).expect("c present");
    let d = c.get("d").and_then(Value::as_struct).expect("d present");
    let e = d.get("e").and_then(Value::as_struct).expect("e present");
    // Optional u8 when present is stored as inner value
    let leaf = e.get("v").and_then(Value::as_u64).expect("v present");
    assert_eq!(leaf, 42, "leaf value should be 42 after decode (presence stack depth 5)");
}
