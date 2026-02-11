//! # AIProtoDSL — Protocol Encoding DSL and Codec
//!
//! A DSL for defining binary protocol formats (transport headers, messages, structs)
//! with a PEST grammar, plus a Rust codec for encoding/decoding, validation,
//! and frame handling (multiple messages, removal of non-compliant messages).
//!
//! ## DSL structure
//!
//! - **Transport**: optional frame/header (magic, version, length, padding, reserved)
//! - **Payload**: optional; which messages can follow the transport and how to select message type from a transport field (`messages`, `selector`)
//! - **Messages**: named message types with fields
//! - **Structs**: reusable compound types
//!
//! ## Field types
//!
//! - Base: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `bool`, `float`, `double`
//! - `padding(n)`, `reserved(n)`, `bitfield(n)` (encoder zeroes padding/reserved)
//! - Sized int: `u8(n)` … `i64(n)` for integers in n bits (e.g. `u16(14)`, `i16(10)`)
//! - `length_of(field)`, `count_of(field)` for length/count fields
//! - Struct references, `list<T>`, `optional<T>`, `T[n]` (fixed or count-based)
//! - Constraints: `[min..max]` or concatenation `[min1..max1, min2..max2, ...]`, `[in(a, b, c)]`
//!
//! ## Example DSL
//!
//! ```text
//! transport {
//!   magic: magic("\\x00PROTO");
//!   version: u8 = 1;
//!   length: u32;
//!   padding: padding(2);
//! }
//!
//! message Packet {
//!   type: u8 [0..255];
//!   payload_len: u16;
//!   payload: list<u8>;
//! }
//! ```
//!
//! ## Usage
//!
//! See the [README](https://github.com/yourusername/AIProtoDSL) and the `tests/integration.rs` for full examples.

pub mod ast;
pub mod codec;
pub mod frame;
pub mod lint;
pub mod parser;
pub mod value;
pub mod walk;

pub use ast::{AbstractType, FspecMapping, Protocol, ResolvedProtocol, TypeDefSection, TypeSpec};
pub use codec::{Codec, CodecError, Endianness};
pub use frame::{decode_frame, FrameDecodeResult};
pub use parser::parse;
pub use value::Value;
pub use lint::{lint, LintMessage, LintRule, Severity};
pub use walk::{
    message_extent, validate_message_in_place, zero_padding_reserved_in_place,
    remove_message_in_place, write_u32_in_place,
    BinaryWalker, BinaryWalkerMut,
    Endianness as WalkEndianness,
};
