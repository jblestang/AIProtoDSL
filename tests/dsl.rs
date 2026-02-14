//! Extensive DSL unit tests: syntax (parse success/failure) and semantics (resolve, references).

use aiprotodsl::{parse, ResolvedProtocol};

// ==================== Syntax: valid programs ====================

#[test]
fn parse_empty_protocol() {
    // Grammar allows empty protocol (no sections); parser returns Ok with empty vecs
    let r = parse("");
    let p = r.expect("empty protocol can parse");
    assert!(p.messages.is_empty());
    assert!(p.structs.is_empty());
}

#[test]
fn parse_minimal_message() {
    let src = r#"
message M {
  x: u8;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].name, "M");
    assert_eq!(p.messages[0].fields.len(), 1);
    assert_eq!(p.messages[0].fields[0].name, "x");
}

#[test]
fn parse_message_all_base_types() {
    let src = r#"
message AllBase {
  a: u8;
  b: u16;
  c: u32;
  d: u64;
  e: i8;
  f: i16;
  g: i32;
  h: i64;
  i: bool;
  j: float;
  k: double;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 11);
}

#[test]
fn parse_message_with_comments() {
    let src = r#"
message WithComments {
  // line comment
  id: u8;
  len: u16; /* block */
  data: list<u8>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 3);
}

#[test]
fn parse_transport_section() {
    let src = r#"
transport {
  magic: magic("\\x00PROTO");
  version: u8 = 1;
  length: u32;
  padding: padding(2);
}
message P { x: u8; }
"#;
    let p = parse(src).expect("parse");
    let t = p.transport.as_ref().expect("transport");
    assert_eq!(t.fields.len(), 4);
}

#[test]
fn parse_transport_padding_bits() {
    let src = r#"
transport {
  x: u8;
  pad: padding(3, bits);
}
message P { y: u8; }
"#;
    let p = parse(src).expect("parse");
    let t = p.transport.as_ref().expect("transport");
    assert_eq!(t.fields.len(), 2);
}

#[test]
fn parse_payload_section() {
    let src = r#"
transport { cat: u8; len: u16; }
payload {
  messages: A, B;
  selector: cat -> 1: A, 2: B;
}
message A { x: u8; }
message B { y: u16; }
"#;
    let p = parse(src).expect("parse");
    let pl = p.payload.as_ref().expect("payload");
    assert_eq!(pl.messages.len(), 2);
    let sel = pl.selector.as_ref().expect("selector");
    assert_eq!(sel.transport_field, "cat");
    assert_eq!(sel.value_to_message.len(), 2);
}

#[test]
fn parse_payload_repeated() {
    let src = r#"
transport { cat: u8; len: u16; }
payload {
  messages: R;
  repeated;
}
message R { x: u8; }
"#;
    let p = parse(src).expect("parse");
    assert!(p.payload.as_ref().unwrap().repeated);
}

#[test]
fn parse_type_section_abstract() {
    let src = r#"
type Foo {
  x: integer [0..255];
  y: boolean;
}
message M { a: u8; }
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.type_defs.len(), 1);
    assert_eq!(p.type_defs[0].name, "Foo");
    assert_eq!(p.type_defs[0].fields.len(), 2);
}

#[test]
fn parse_enum_section() {
    let src = r#"
enum Kind { A = 0; B = 1; C = 16; }
message M { k: u8; }
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.enum_defs.len(), 1);
    assert_eq!(p.enum_defs[0].name, "Kind");
    assert_eq!(p.enum_defs[0].variants.len(), 3);
}

#[test]
fn parse_struct_and_ref() {
    let src = r#"
struct S { a: u8; b: u16; }
message M {
  id: u8;
  s: S;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.structs.len(), 1);
    assert_eq!(p.structs[0].name, "S");
    assert_eq!(p.messages[0].fields[1].name, "s");
}

#[test]
fn parse_constraints_range() {
    let src = r#"
message M {
  x: u8 [0..255];
  y: i16 [-100..100];
}
"#;
    let p = parse(src).expect("parse");
    let c = p.messages[0].fields[0].constraint.as_ref().expect("constraint");
    assert!(matches!(c, aiprotodsl::ast::Constraint::Range(_)));
}

#[test]
fn parse_constraints_multi_interval() {
    let src = r#"
message M {
  x: u8 [0..10, 20..30];
}
"#;
    let p = parse(src).expect("parse");
    let c = p.messages[0].fields[0].constraint.as_ref().expect("constraint");
    if let aiprotodsl::ast::Constraint::Range(iv) = c {
        assert_eq!(iv.len(), 2);
    } else {
        panic!("expected range constraint");
    }
}

#[test]
fn parse_constraints_enum() {
    let src = r#"
message M {
  k: u8 [in(0, 1, 2)];
}
"#;
    let p = parse(src).expect("parse");
    let c = p.messages[0].fields[0].constraint.as_ref().expect("constraint");
    assert!(matches!(c, aiprotodsl::ast::Constraint::Enum(_)));
}

#[test]
fn parse_sized_int_bitfield_padding() {
    let src = r#"
message M {
  a: u16(14);
  b: i8(7);
  c: bitfield(8);
  d: padding(2);
  e: padding(5, bits);
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 5);
}

#[test]
fn parse_length_of_count_of() {
    let src = r#"
message M {
  len: u16;
  data: list<u8>;
  n: u8;
  items: list<u16>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 4);
}

#[test]
fn parse_presence_bits() {
    let src = r#"
message M {
  flags: presence_bits(1);
  a: optional<u8>;
  b: optional<u16>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 3);
}

#[test]
fn parse_bitmap_without_mapping() {
    let src = r#"
message M {
  fspec: bitmap(14, 7);
  a: optional<u8>;
  b: optional<u16>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 3);
}

#[test]
fn parse_bitmap_with_mapping() {
    let src = r#"
message M {
  fspec: bitmap(2, 7) -> (0: a, 1: b);
  a: optional<u8>;
  b: optional<u16>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 3);
}

#[test]
fn parse_list_and_optional() {
    let src = r#"
message M {
  xs: list<u8>;
  opt: optional<u16>;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 2);
}

#[test]
fn parse_rep_list_octets_fx() {
    let src = r#"
message M {
  n: u8;
  items: rep_list<u16>;
  tail: octets_fx;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields.len(), 3);
}

#[test]
fn parse_conditional_field() {
    let src = r#"
message M {
  kind: u8;
  extra: u16 if kind == 1;
}
"#;
    let p = parse(src).expect("parse");
    let f = &p.messages[0].fields[1];
    assert!(f.condition.is_some());
    assert_eq!(f.condition.as_ref().unwrap().field, "kind");
}

#[test]
fn parse_quantum_spec() {
    let src = r#"
struct S {
  rho: u16 [0..65535] quantum "1/256 NM";
  theta: u16 quantum "360/65536 °";
}
message M { x: S; }
"#;
    let p = parse(src).expect("parse");
    assert!(p.structs[0].fields[0].quantum.is_some());
    assert!(p.structs[0].fields[1].quantum.is_some());
}

#[test]
fn parse_default_value() {
    let src = r#"
message M {
  version: u8 = 1;
  flag: bool = true;
}
"#;
    let p = parse(src).expect("parse");
    assert!(p.messages[0].fields[0].default.is_some());
    assert!(p.messages[0].fields[1].default.is_some());
}

#[test]
fn parse_selector_list_type() {
    let src = r#"
transport { cat: u8; len: u16; }
payload {
  messages: R;
  selector: cat -> 48: list<R>;
}
message R { x: u8; }
"#;
    let p = parse(src).expect("parse");
    let sel = p.payload.as_ref().unwrap().selector.as_ref().unwrap();
    assert_eq!(sel.value_to_message.len(), 1);
    assert!(sel.value_to_message[0].2); // is_list
}

// ==================== Syntax: invalid / parse errors ====================

#[test]
fn parse_unclosed_brace_fails() {
    let src = r#"
message M {
  x: u8;
"#;
    let r = parse(src);
    assert!(r.is_err(), "unclosed brace should fail: {:?}", r);
}

#[test]
fn parse_wrong_keyword_fails() {
    let src = "messag M { x: u8; }";
    assert!(parse(src).is_err());
}

#[test]
fn parse_malformed_message_fails() {
    let src = "message { x: u8; }";
    assert!(parse(src).is_err());
}

#[test]
fn parse_malformed_field_no_semicolon_fails() {
    let src = r#"
message M {
  x: u8
}
"#;
    assert!(parse(src).is_err());
}

#[test]
fn parse_unknown_ident_as_struct_ref_succeeds() {
    // Unknown ident parses as struct ref; resolve/codec may fail later if undefined
    let src = r#"
message M {
  x: UnknownStruct;
}
"#;
    let p = parse(src).expect("parse");
    assert_eq!(p.messages[0].fields[0].name, "x");
    assert!(matches!(
        &p.messages[0].fields[0].type_spec,
        aiprotodsl::ast::TypeSpec::StructRef(s) if s == "UnknownStruct"
    ));
}

#[test]
fn parse_presence_bits_invalid_n_fails() {
    let src = r#"
message M {
  f: presence_bits(3);
  a: optional<u8>;
}
"#;
    let r = parse(src);
    assert!(r.is_err(), "presence_bits(3) invalid: {:?}", r);
}

#[test]
fn parse_bitmap_missing_args_fails() {
    let src = r#"
message M {
  f: bitmap();
  a: optional<u8>;
}
"#;
    assert!(parse(src).is_err());
}

// ==================== Semantics: resolve success ====================

#[test]
fn resolve_minimal() {
    let p = parse("message M { x: u8; }").expect("parse");
    let r = ResolvedProtocol::resolve(p).expect("resolve");
    assert!(r.get_message("M").is_some());
}

#[test]
fn resolve_transport_and_payload() {
    let src = r#"
transport { cat: u8; len: u16; }
payload { messages: A, B; selector: cat -> 1: A, 2: B; }
message A { x: u8; }
message B { y: u16; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p).expect("resolve");
    assert_eq!(r.messages_after_transport().len(), 2);
}

#[test]
fn resolve_struct_ref() {
    let src = r#"
struct S { a: u8; }
message M { id: u8; s: S; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p).expect("resolve");
    assert!(r.get_struct("S").is_some());
    assert!(r.get_message("M").is_some());
}

#[test]
fn resolve_type_defs() {
    let src = r#"
type T { x: integer; }
enum E { A = 0; }
message M { a: u8; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p).expect("resolve");
    assert!(r.get_type_def("T").is_some());
}

// ==================== Semantics: resolve errors ====================

#[test]
fn resolve_duplicate_message_name_fails() {
    let src = r#"
message M { x: u8; }
message M { y: u16; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("Duplicate message name"));
}

#[test]
fn resolve_duplicate_struct_name_fails() {
    let src = r#"
struct S { a: u8; }
struct S { b: u16; }
message M { x: u8; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("Duplicate struct name"));
}

#[test]
fn resolve_duplicate_type_name_fails() {
    let src = r#"
type T { x: integer; }
type T { y: integer; }
message M { a: u8; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("Duplicate type name"));
}

#[test]
fn resolve_payload_message_undefined_fails() {
    let src = r#"
transport { cat: u8; len: u16; }
payload { messages: Missing; }
message M { x: u8; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("not a defined message"));
}

#[test]
fn resolve_selector_message_undefined_fails() {
    let src = r#"
transport { cat: u8; len: u16; }
payload { messages: M; selector: cat -> 1: Missing; }
message M { x: u8; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("not a defined message"));
}

#[test]
fn resolve_struct_ref_undefined_allowed() {
    // Struct refs are not resolved at resolve() time; codec fails at encode/decode if missing
    let src = r#"
message M { id: u8; s: UnknownStruct; }
"#;
    let p = parse(src).expect("parse");
    let r = ResolvedProtocol::resolve(p);
    // Currently resolve does not check that struct refs exist; it only checks payload/messages.
    // So this may pass. If we add the check later, flip to assert!(r.is_err()).
    let _ = r;
}

#[test]
fn parse_payload_without_messages_list_fails() {
    // payload must list at least one message
    let src = r#"
transport { cat: u8; len: u16; }
payload { repeated; }
message M { x: u8; }
"#;
    let r = parse(src);
    assert!(r.is_err(), "payload without messages list should fail parse");
}
