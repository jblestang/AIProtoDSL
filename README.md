# AIProtoDSL

A **DSL (Domain Specific Language)** for defining binary protocol encodings, with a **codec** (encoder/decoder), **validation**, and **frame handling** in Rust. The grammar is implemented with [PEST](https://pest.rs/).

## Structure

The protocol is organized in three layers:

1. **Transport** — Optional frame/header (magic bytes, version, length, padding).
2. **Messages** — Named message types with fields (the main payload).
3. **Structs** — Reusable compound types referenced by messages or other structs.

## DSL Syntax

### Transport

```text
transport {
  magic: magic("\\x00PROTO");
  version: u8 = 1;
  length: u32;
  padding: padding(2);
}
```

### Messages and structs

```text
message Packet {
  type: u8 [0..255];
  payload_len: u16;
  payload: list<u8>;
}

struct Header {
  id: u32;
  flags: bitfield(8);
}
```

**Comments:** `//` line comments and `/* */` block comments are allowed anywhere (included after a field). Use e.g. `// content not verifiable (full range)` for fields whose range constraint covers the full type range.

### Field types

| Type | Description |
|------|-------------|
| `u8`, `u16`, `u32`, `u64` | Unsigned integers |
| `i8`, `i16`, `i32`, `i64` | Signed integers |
| `bool`, `float`, `double` | Primitives |
| `padding(n)` / `padding_bits(n)` | Padding: `n` bytes or `n` bits (zeroed on encode) |
| `bitfield(n)` | `n` bits (bit mask / flags) |
| `u8(n)` … `i64(n)` | Integer in `n` bits (e.g. `u16(14)`, `i16(10)`); use when the value is an integer, not a bit mask |
| `length_of(field)` | Value is length of another field |
| `count_of(field)` | Value is count of another field |
| `presence_bits(n)` | Bitmap: `n` bytes (1, 2, or 4); following optional fields use bits 0, 1, 2, … |
| `bitmap(...)` | Bitmap (e.g. variable-length until FX=0; 7 presence bits per byte); following optionals use bitmap bits |
| `list<T>` | Count-prefixed list (count as u32, then elements) |
| `optional<T>` | Presence byte; or after a bitmap, bit in bitmap (no byte) |
| `T[n]` | Array (fixed length or `n` from another field) |
| Struct name | Reference to a defined `struct` |

### Constraints

- **Range:** one interval `[min..max]` (e.g. `[0..255]`) or concatenation of intervals `[min1..max1, min2..max2, ...]` (value valid if in any interval)
- **Enum:** `[in(0, 1, 2)]`

### Conditional fields

- `if field_name == value` — field is only present when the given field equals the value.

### Bitmap (presence for optionals)

Use `presence_bits(n)` with `n` = 1, 2, or 4 bytes, or `bitmap(...)` for variable-length. The next **consecutive** optional fields (until a non-optional field) use bits 0, 1, 2, … of that bitmap instead of a per-field presence byte. Bit set = field present. Example:

```text
message WithPresence {
  flags: presence_bits(1);
  a: optional<u8>;
  b: optional<u16>;
}
```

Encoded as: 1 byte bitmap (bit 0 = `a` present, bit 1 = `b` present), then (if present) `a`, then (if present) `b`. Saves one byte per optional when using the bitmap.

### Payload (messages after transport)

Declare which message types can follow the transport and how to select the message type from a transport field:

```text
transport {
  category: u8;
  length: u16;
}
payload {
  messages: Cat001Record, Cat048Record, Cat034Record;
  selector: category -> 1: Cat001Record, 48: Cat048Record, 34: Cat034Record;
}
```

- **`messages`** — list of message type names that can appear after the transport.
- **`selector`** — optional: transport field name and value→message mapping. At decode time, decode the transport, then use `ResolvedProtocol::message_for_transport_values(transport_values)` to get the message name; use `messages_after_transport()` to get the allowed set.
- **`repeated`** — optional: when present, the payload is a **list of records** (zero or more messages of the selected type per data block). Use for protocols like ASTERIX where each data block (category + length) contains multiple records of the same category.

### ASTERIX and family example

Use `bitmap(...)` for ASTERIX-style records: variable-length bitmap bytes (e.g. 7 presence bits per byte, bit 7 = FX extension). The next consecutive optional fields use bits 0, 1, 2, … from the bitmap. **Mapping:** after resolve, use `ResolvedProtocol::bitmap_presence_mapping_message(name)` (or `bitmap_presence_mapping_struct(name)`) to get the optional field list and bit→field mapping. See **`examples/asterix_family.dsl`** for a model of the ASTERIX CAT 001, 002, 034, 048, and 240 family (data block = category + length; **payload is a list of records** per block, with `repeated;` and selector mapping `category` to record type).

## Codec

- **Endianness:** Configurable (big/little) for multi-byte types.
- **Validation:** Range and enum constraints are checked on decode; invalid messages can be reported and skipped in frame mode.
- **Padding:** Padding and padding_bits are always written as zero on encode.

## Zero-copy walk (no decode/encode)

For performance-sensitive paths you can **walk the binary in place** without decoding or encoding:

- **Message extent** — `message_extent(data, start, resolved, endianness, message_name)` returns the byte length of one message by walking the structure (no allocation).
- **Validate in place** — `validate_message_in_place(...)` checks constraints (range/enum) with minimal reads; no `Value` allocation.
- **Zero padding in place** — `zero_padding_reserved_in_place(buffer, ...)` writes 0 for all padding and padding_bits fields in the message.
- **Remove message in place** — `remove_message_in_place(buffer, start, len)` shifts bytes so the message at `[start..start+len]` is removed; returns the new length (caller should truncate the buffer). Use `write_u32_in_place` to update a frame length or count field after removal.

Use the **walk** API when you need to sanitize buffers (zero padding), skip or drop invalid messages without decoding, or compute message boundaries for framing — without the cost of full decode/encode.

## Frame handling

A binary frame can contain **one or more messages**. The frame API:

- Decodes the frame and returns a list of **decoded messages** and a list of **removed** (non-compliant but decodable) messages.
- When a message fails validation, it is still consumed (byte extent is known), so decoding can continue.
- Re-encoding only compliant messages (and updating length/count in the frame) is supported via `encode_frame_with_compliant_only`.

## Usage

```rust
use aiprotodsl::{parse, ResolvedProtocol, Codec, Endianness, Value};
use aiprotodsl::frame;
use std::collections::HashMap;

let src = r#"
message Simple {
  id: u8;
  len: u16;
  data: list<u8>;
}
"#;

let protocol = parse(src).expect("parse");
let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
let codec = Codec::new(resolved, Endianness::Little);

let mut values = HashMap::new();
values.insert("id".to_string(), Value::U8(42));
values.insert("len".to_string(), Value::U16(3));
values.insert("data".to_string(), Value::List(vec![
    Value::U8(1), Value::U8(2), Value::U8(3),
]));

let bytes = codec.encode_message("Simple", &values).expect("encode");
let decoded = codec.decode_message("Simple", &bytes).expect("decode");

// Frame with multiple messages
let result = frame::decode_frame(&codec, "Simple", &frame_bytes, None).expect("frame");
```

## Tests

```bash
cargo test
```

## License

MIT OR Apache-2.0
