//! # AIProtoDSL — Protocol Encoding DSL and Codec
//!
//! A DSL for defining binary protocol formats (transport headers, messages, structs)
//! with a PEST grammar, plus a Rust codec for encoding/decoding, validation,
//! and frame handling (multiple messages, removal of non-compliant messages).
//!
//! ## DSL structure
//!
//! - **Transport**: optional frame/header (magic, version, length, padding, reserved)
//! - **Messages**: named message types with fields
//! - **Structs**: reusable compound types
//!
//! ## Field types
//!
//! - Base: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `bool`, `float`, `double`
//! - `padding(n)`, `reserved(n)`, `bitfield(n)` (encoder zeroes padding/reserved)
//! - `length_of(field)`, `count_of(field)` for length/count fields
//! - Struct references, `list<T>`, `optional<T>`, `T[n]` (fixed or count-based)
//! - Constraints: `[min..max]`, `[in(a, b, c)]`
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
pub mod parser;
pub mod value;
pub mod walk;

pub use ast::{Protocol, ResolvedProtocol};
pub use codec::{Codec, CodecError, Endianness};
pub use frame::{decode_frame, FrameDecodeResult};
pub use parser::parse;
pub use value::Value;
pub use walk::{
    message_extent, validate_message_in_place, zero_padding_reserved_in_place,
    remove_message_in_place, write_u32_in_place,
    BinaryWalker, BinaryWalkerMut,
    Endianness as WalkEndianness,
};
