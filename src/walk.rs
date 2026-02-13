//! Zero-copy walk over binary data using the message structure.
//!
//! This module provides **structure-only** traversal of binary payloads: it advances a byte
//! position by following the protocol’s message/struct layout without allocating decoded
//! values. Use it when you need extent (byte length), validation (constraints), or in-place
//! edits (zero padding, remove message) without full decode/encode.
//!
//! ## Design
//!
//! - **No decode:** The walker does not build [`Value`](crate::value::Value) trees. It only
//!   reads the minimum bytes required to skip fields (e.g. length/count, presence bits) and
//!   to validate constrained fields.
//! - **Zero-copy:** Data is never copied for decoding; the walker holds a slice and a `pos`.
//! - **Same layout as codec:** Walk follows the same DSL types (structs, optionals, lists,
//!   bitmap presence, etc.) as the main [codec](crate::codec), so extent and validation
//!   match what decode would consume.
//!
//! ## When to use walk vs codec
//!
//! | Use case | Prefer |
//! |----------|--------|
//! | Get byte length of one message | [`message_extent`] |
//! | Check constraints without decoding | [`validate_message_in_place`] |
//! | Zero padding/reserved in a buffer | [`zero_padding_reserved_in_place`] |
//! | Remove a message and shift bytes | [`remove_message_in_place`] + [`write_u32_in_place`] |
//! | Full decode for inspection/display | [codec](crate::codec) |
//!
//! ## Presence and context
//!
//! Optional fields are driven by **presence** state: either a fixed bitmap
//! ([`presence_bits`](crate::ast::TypeSpec::PresenceBits)), or a
//! [bitmap_presence](crate::ast::TypeSpec::BitmapPresence) (FSPEC-style). The walker reads
//! presence bits/bytes when it hits a presence field, then uses that state for subsequent
//! `optional<T>` fields. Numeric values (e.g. from `length_of` / `count_of`) and the current
//! presence state are kept internally for conditional and repeated fields.
//!
//! ## Public API summary
//!
//! - **Extent:** [`message_extent`] — returns number of bytes one message occupies.
//! - **Validation:** [`validate_message_in_place`] — checks constraints in place.
//! - **In-place edits:** [`zero_padding_reserved_in_place`], [`remove_message_in_place`],
//!   [`write_u32_in_place`].
//! - **Low-level:** [`BinaryWalker`] / [`BinaryWalkerMut`] for custom loops (e.g. skip
//!   message, then [`BinaryWalker::position`]).
//!
//! ## Performance and profiling
//!
//! Walk is designed to be fast (no allocation, minimal reads). On typical ASTERIX-style
//! payloads (many optionals and nested structs), measured hotspots are:
//!
//! - **Optional** — reading presence and conditionally skipping the optional’s inner type.
//! - **StructRef** — resolving the struct and recursing over its fields.
//! - **RepList** — reading the repetition count and looping over elements.
//!
//! Enable the **`walk_profile`** feature and use [`reset_walk_profile`] / [`get_walk_profile`]
//! to get a per–type-spec breakdown (label → nanoseconds). Run the `walk_pcap` benchmark
//! with `--features walk_profile` to print a hotspot summary after the run.
//!
//! ## Example
//!
//! ```ignore
//! use aiprotodsl::{message_extent, ResolvedProtocol, WalkEndianness};
//!
//! let resolved: ResolvedProtocol = /* ... */;
//! let body: &[u8] = /* record bytes */;
//! let n = message_extent(body, 0, &resolved, WalkEndianness::Big, "Cat048Record")?;
//! // n = number of bytes consumed by one Cat048Record
//! ```

use crate::ast::*;
use crate::codec::CodecError;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::collections::HashMap;

#[cfg(feature = "walk_profile")]
use std::cell::RefCell;
#[cfg(feature = "walk_profile")]
use std::time::Instant;

/// Byte order for multi-byte fields (e.g. u16, u32, length_of, count_of).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Endianness {
    Big,
    Little,
}

/// Presence state for optional fields: fixed bitmap (presence_bits) or bitmap presence (bitmap_presence).
#[derive(Default)]
enum WalkPresence {
    #[default]
    None,
    Bitmap(u64, usize),
    /// presence_per_block: 0 = consecutive presence bits (8 per byte); k>0 = k presence + 1 FX per block.
    BitmapPresence(Vec<u8>, usize, u32),
    /// Consecutive bits (8 per byte): hot path for ASTERIX FSPEC; no division/modulo per optional.
    BitmapPresenceConsecutive(Vec<u8>, usize, u8),
}

/// Context for walk: stores numeric field values and optional presence state.
#[derive(Default)]
struct WalkContext {
    values: HashMap<String, u64>,
    presence: WalkPresence,
}

/// Read-only walker: advances over binary data by following the message/struct layout.
///
/// Use [`BinaryWalker::skip_message`] to consume one message and get the byte count, or
/// [`BinaryWalker::validate_message`] to check constraints. Position is tracked in
/// [`BinaryWalker::position`]; [`BinaryWalker::remaining`] gives the slice from the
/// current position to the end. No decoded values are allocated.
pub struct BinaryWalker<'a> {
    data: &'a [u8],
    pos: usize,
    resolved: &'a ResolvedProtocol,
    endianness: Endianness,
    ctx: WalkContext,
}

/// Mutable walker: same as [`BinaryWalker`] but operates on `&mut [u8]`.
///
/// Used for in-place edits: [`zero_padding_reserved_message`](BinaryWalkerMut::zero_padding_reserved_message)
/// zeros all `padding` and `reserved` fields in one message. Skip/validate behaviour matches
/// [`BinaryWalker`].
pub struct BinaryWalkerMut<'a> {
    data: &'a mut [u8],
    pos: usize,
    resolved: &'a ResolvedProtocol,
    endianness: Endianness,
    ctx: WalkContext,
}

fn base_type_size(bt: &BaseType) -> usize {
    match bt {
        BaseType::U8 | BaseType::I8 | BaseType::Bool => 1,
        BaseType::U16 | BaseType::I16 => 2,
        BaseType::U32 | BaseType::I32 | BaseType::Float => 4,
        BaseType::U64 | BaseType::I64 | BaseType::Double => 8,
    }
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, CodecError> {
    if *pos >= data.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u32_slice(data: &[u8], pos: usize, endianness: Endianness) -> Result<u32, CodecError> {
    if pos + 4 > data.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    let v = match endianness {
        Endianness::Big => BigEndian::read_u32(&data[pos..]),
        Endianness::Little => LittleEndian::read_u32(&data[pos..]),
    };
    Ok(v)
}

fn read_bitmap_n(data: &[u8], pos: &mut usize, endianness: Endianness, n: u64) -> Result<u64, CodecError> {
    let len = match n {
        1 => 1,
        2 => 2,
        4 => 4,
        _ => return Err(CodecError::Validation("presence_bits(n): n must be 1, 2, or 4".to_string())),
    };
    if *pos + len > data.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    let v = match len {
        1 => data[*pos] as u64,
        2 => match endianness {
            Endianness::Big => BigEndian::read_u16(&data[*pos..]) as u64,
            Endianness::Little => LittleEndian::read_u16(&data[*pos..]) as u64,
        },
        4 => match endianness {
            Endianness::Big => BigEndian::read_u32(&data[*pos..]) as u64,
            Endianness::Little => LittleEndian::read_u32(&data[*pos..]) as u64,
        },
        _ => 0,
    };
    *pos += len;
    Ok(v)
}

fn read_i64_slice(data: &[u8], pos: &mut usize, spec: &TypeSpec, endianness: Endianness) -> Result<i64, CodecError> {
    match spec {
        TypeSpec::Bitfield(n) => {
            let size = ((*n + 7) / 8) as usize;
            let raw = read_bytes_to_u64(data, pos, size, endianness)?;
            *pos += size;
            return Ok(raw as i64);
        }
        TypeSpec::SizedInt(bt, n) => {
            let size = ((*n + 7) / 8) as usize;
            let mask = if *n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
            let raw = read_bytes_to_u64(data, pos, size, endianness)? & mask;
            *pos += size;
            let signed = matches!(bt, BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64);
            let val = if signed && *n > 0 {
                let sign_bit = 1i64 << (*n as i64 - 1);
                if (raw as i64) >= sign_bit {
                    (raw as i64) - (1i64 << *n as i64)
                } else {
                    raw as i64
                }
            } else {
                raw as i64
            };
            return Ok(val);
        }
        _ => {}
    }
    let (size, signed) = match spec {
        TypeSpec::Base(bt) => (base_type_size(bt), matches!(bt, BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64)),
        _ => return Err(CodecError::Validation("not a numeric type".to_string())),
    };
    if *pos + size > data.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    let n = match (size, endianness) {
        (1, _) => data[*pos] as i64,
        (2, Endianness::Big) => BigEndian::read_i16(&data[*pos..]) as i64,
        (2, Endianness::Little) => LittleEndian::read_i16(&data[*pos..]) as i64,
        (4, Endianness::Big) => BigEndian::read_i32(&data[*pos..]) as i64,
        (4, Endianness::Little) => LittleEndian::read_i32(&data[*pos..]) as i64,
        (8, Endianness::Big) => BigEndian::read_i64(&data[*pos..]),
        (8, Endianness::Little) => LittleEndian::read_i64(&data[*pos..]),
        _ => return Err(CodecError::Validation("unsupported size".to_string())),
    };
    *pos += size;
    Ok(if signed { n } else { n as u64 as i64 })
}

fn read_bytes_to_u64(data: &[u8], pos: &mut usize, len: usize, endianness: Endianness) -> Result<u64, CodecError> {
    if *pos + len > data.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    let v = match (len, endianness) {
        (1, _) => data[*pos] as u64,
        (2, Endianness::Big) => BigEndian::read_u16(&data[*pos..]) as u64,
        (2, Endianness::Little) => LittleEndian::read_u16(&data[*pos..]) as u64,
        (4, Endianness::Big) => BigEndian::read_u32(&data[*pos..]) as u64,
        (4, Endianness::Little) => LittleEndian::read_u32(&data[*pos..]) as u64,
        (8, Endianness::Big) => BigEndian::read_u64(&data[*pos..]),
        (8, Endianness::Little) => LittleEndian::read_u64(&data[*pos..]),
        _ => {
            let mut b = [0u8; 8];
            let start = 8 - len;
            b[start..].copy_from_slice(&data[*pos..*pos + len]);
            match endianness {
                Endianness::Big => BigEndian::read_u64(&b),
                Endianness::Little => LittleEndian::read_u64(&b),
            }
        }
    };
    Ok(v)
}

/// Slow path (validation): range check or enum check. Used from validate_field_and_skip.
fn validate_constraint_raw(value_i64: i64, c: &Constraint) -> Result<(), CodecError> {
    match c {
        Constraint::Range(intervals) => {
            let in_any = intervals.iter().any(|(min, max)| value_i64 >= *min && value_i64 <= *max);
            if !in_any {
                return Err(CodecError::Validation(format!(
                    "value {} not in any interval {:?}",
                    value_i64,
                    intervals
                )));
            }
        }
        Constraint::Enum(allowed) => {
            let ok = allowed.iter().any(|l| l.as_i64() == Some(value_i64));
            if !ok {
                return Err(CodecError::Validation("value not in allowed enum".to_string()));
            }
        }
    }
    Ok(())
}

impl WalkContext {
    fn get(&self, k: &str) -> Option<u64> {
        self.values.get(k).copied()
    }
    fn set(&mut self, k: String, v: u64) {
        self.values.insert(k, v);
    }
}

impl<'a> BinaryWalker<'a> {
    pub fn new(data: &'a [u8], resolved: &'a ResolvedProtocol, endianness: Endianness) -> Self {
        BinaryWalker { data, pos: 0, resolved, endianness, ctx: WalkContext::default() }
    }

    pub fn at(data: &'a [u8], start: usize, resolved: &'a ResolvedProtocol, endianness: Endianness) -> Self {
        BinaryWalker { data, pos: start, resolved, endianness, ctx: WalkContext::default() }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    /// Skip one message by structure; returns number of bytes skipped. No allocation.
    pub fn skip_message(&mut self, message_name: &str) -> Result<usize, CodecError> {
        let start = self.pos;
        let msg = self.resolved.get_message(message_name).ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        self.skip_message_fields(msg.fields.as_slice())?;
        Ok(self.pos - start)
    }

    /// Validate current message in place (read only constrained fields, check ranges). No allocation.
    /// Fields whose constraint saturates the type range (flag set on each [`MessageField`](crate::ast::MessageField) at resolve) are skipped without range check.
    pub fn validate_message(&mut self, message_name: &str) -> Result<(), CodecError> {
        let msg = self.resolved.get_message(message_name).ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        self.validate_and_skip_message_fields(msg.fields.as_slice())?;
        Ok(())
    }

    fn skip_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            self.skip_type_spec(&f.type_spec, Some(&f.name))?;
        }
        Ok(())
    }

    /// Validation: for each field we skip (saturating or no constraint) or run range check.
    /// Saturating flag is set on each [`MessageField`](crate::ast::MessageField) at resolve.
    fn validate_and_skip_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields.iter() {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            if f.saturating || f.constraint.is_none() {
                self.skip_type_spec(&f.type_spec, Some(&f.name))?;
            } else {
                self.validate_field_and_skip(f)?;
            }
        }
        Ok(())
    }

    /// Range-check slow path: read field value from buffer then validate interval/enum.
    /// Called only for message-level fields that have a constraint and are not saturating (see [`MessageField::saturating`](crate::ast::MessageField)).
    fn validate_field_and_skip(&mut self, f: &MessageField) -> Result<(), CodecError> {
        #[cfg(feature = "walk_profile")]
        let _g = ProfileGuard::new("ValidateField");
        let value_i64 = read_i64_slice(self.data, &mut self.pos, &f.type_spec, self.endianness)?;
        if let Some(ref c) = f.constraint {
            validate_constraint_raw(value_i64, c)?;
        }
        if matches!(f.type_spec, TypeSpec::LengthOf(_) | TypeSpec::CountOf(_)) {
            self.ctx.set(f.name.clone(), value_i64 as u64);
        }
        Ok(())
    }

    /// **Slow path** (run with `--features walk_profile` and see bench walk_validate_pcap hotspot):
    /// **Optional** (~48%), **StructRef** (~34%), **RepList** (~10%); then BitfieldSizedInt, Base.
    /// For walk+validate, **ValidateField** (range/enum check) is a small fraction when most fields are saturating.
    fn skip_type_spec(&mut self, spec: &TypeSpec, field_name: Option<&str>) -> Result<(), CodecError> {
        match spec {
            TypeSpec::Base(bt) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("Base");
                let n = base_type_size(bt);
                if self.pos + n > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.pos += n;
            }
            TypeSpec::Padding(n) | TypeSpec::Reserved(n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("PaddingReserved");
                self.pos += *n as usize;
            }
            TypeSpec::Bitfield(n) | TypeSpec::SizedInt(_, n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("BitfieldSizedInt");
                self.pos += ((*n + 7) / 8) as usize;
            }
            TypeSpec::LengthOf(_) | TypeSpec::CountOf(_) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("LengthOfCountOf");
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                if let Some(name) = field_name {
                    let v = read_u32_slice(self.data, self.pos, self.endianness)?;
                    self.ctx.set(name.to_string(), v as u64);
                }
                self.pos += 4;
            }
            TypeSpec::PresenceBits(n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("PresenceBits");
                let bitmap = read_bitmap_n(self.data, &mut self.pos, self.endianness, *n)?;
                self.ctx.presence = WalkPresence::Bitmap(bitmap, 0);
            }
            TypeSpec::BitmapPresence { total_bits, presence_per_block, .. } => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("BitmapPresence");
                let max_encoded_bits = if *presence_per_block == 0 { *total_bits } else { ((*total_bits + presence_per_block - 1) / presence_per_block) * (presence_per_block + 1) };
                let max_bytes = ((max_encoded_bits + 7) / 8) as usize;
                let mut bytes = Vec::new();
                if *presence_per_block == 0 {
                    if self.pos + max_bytes > self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    bytes.extend_from_slice(&self.data[self.pos..self.pos + max_bytes]);
                    self.pos += max_bytes;
                } else {
                    let max_blocks = (*total_bits + presence_per_block - 1) / presence_per_block;
                    for _ in 0..max_blocks {
                        if self.pos >= self.data.len() {
                            return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                        }
                        let b = self.data[self.pos];
                        self.pos += 1;
                        bytes.push(b);
                        if b & 0x01 == 0 || bytes.len() >= max_bytes {
                            break;
                        }
                    }
                }
                self.ctx.presence = if *presence_per_block == 0 {
                    WalkPresence::BitmapPresenceConsecutive(bytes, 0, 0)
                } else {
                    WalkPresence::BitmapPresence(bytes, 0, *presence_per_block)
                };
            }
            TypeSpec::PaddingBits(n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("PaddingBits");
                let byte_len = ((*n + 7) / 8) as usize;
                if self.pos + byte_len > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.pos += byte_len;
            }
            TypeSpec::StructRef(name) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("StructRef");
                let s = self.resolved.get_struct(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                self.skip_struct_fields(s.fields.as_slice())?;
            }
            TypeSpec::Array(elem, len) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("Array");
                let n = match len {
                    ArrayLen::Constant(k) => *k,
                    ArrayLen::FieldRef(field) => self.ctx.get(field).ok_or_else(|| CodecError::UnknownField(field.clone()))?,
                };
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::List(elem) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("List");
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = read_u32_slice(self.data, self.pos, self.endianness)?;
                self.pos += 4;
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::RepList(elem) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("RepList");
                if self.pos + 1 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = self.data[self.pos] as u32;
                self.pos += 1;
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::OctetsFx => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("OctetsFx");
                while self.pos < self.data.len() {
                    let b = self.data[self.pos];
                    self.pos += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
            }
            TypeSpec::Optional(elem) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("Optional");
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::BitmapPresenceConsecutive(bytes, byte_idx, bit_offset) => {
                        let present = *byte_idx < bytes.len() && ((bytes[*byte_idx] >> (7 - *bit_offset)) & 1) != 0;
                        if *bit_offset == 7 {
                            *byte_idx += 1;
                            *bit_offset = 0;
                        } else {
                            *bit_offset += 1;
                        }
                        present
                    }
                    WalkPresence::BitmapPresence(bytes, i, presence_per_block) => {
                        let bits_per_block = *presence_per_block as usize;
                        let byte_idx = *i / bits_per_block;
                        let bit_idx = *i % bits_per_block;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> (7 - bit_idx)) & 1 } else { 0 };
                        bit != 0
                    }
                    WalkPresence::None => read_u8(self.data, &mut self.pos)? != 0,
                };
                if present {
                    self.skip_type_spec(elem, None)?;
                }
            }
        }
        Ok(())
    }

    fn skip_struct_fields(&mut self, fields: &[StructField]) -> Result<(), CodecError> {
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            self.skip_type_spec(&f.type_spec, Some(&f.name))?;
        }
        Ok(())
    }
}

impl<'a> BinaryWalkerMut<'a> {
    pub fn new(data: &'a mut [u8], resolved: &'a ResolvedProtocol, endianness: Endianness) -> Self {
        BinaryWalkerMut { data, pos: 0, resolved, endianness, ctx: WalkContext::default() }
    }

    pub fn at(data: &'a mut [u8], start: usize, resolved: &'a ResolvedProtocol, endianness: Endianness) -> Self {
        BinaryWalkerMut { data, pos: start, resolved, endianness, ctx: WalkContext::default() }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    /// Zero all padding and reserved fields in one message, in place. No other allocation.
    pub fn zero_padding_reserved_message(&mut self, message_name: &str) -> Result<(), CodecError> {
        let msg = self.resolved.get_message(message_name).ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        self.zero_padding_reserved_message_fields(msg.fields.as_slice())?;
        Ok(())
    }

    /// One-pass validate and zero: for each field, validate constrained non-saturating fields and zero padding/reserved; returns bytes consumed.
    pub fn validate_and_zero_message(&mut self, message_name: &str) -> Result<usize, CodecError> {
        let start = self.pos;
        let msg = self.resolved.get_message(message_name).ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        self.validate_and_zero_message_fields(msg.fields.as_slice())?;
        Ok(self.pos - start)
    }

    fn validate_and_zero_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields.iter() {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            if f.saturating || f.constraint.is_none() {
                self.zero_or_skip_type_spec(&f.type_spec, Some(&f.name))?;
            } else {
                self.validate_field_and_skip(f)?;
            }
        }
        Ok(())
    }

    fn validate_field_and_skip(&mut self, f: &MessageField) -> Result<(), CodecError> {
        let value_i64 = read_i64_slice(self.data, &mut self.pos, &f.type_spec, self.endianness)?;
        if let Some(ref c) = f.constraint {
            validate_constraint_raw(value_i64, c)?;
        }
        if matches!(f.type_spec, TypeSpec::LengthOf(_) | TypeSpec::CountOf(_)) {
            self.ctx.set(f.name.clone(), value_i64 as u64);
        }
        Ok(())
    }

    /// Skip one message (same as BinaryWalker).
    pub fn skip_message(&mut self, message_name: &str) -> Result<usize, CodecError> {
        let start = self.pos;
        let msg = self.resolved.get_message(message_name).ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        self.skip_message_fields(msg.fields.as_slice())?;
        Ok(self.pos - start)
    }

    fn zero_padding_reserved_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            self.zero_or_skip_type_spec(&f.type_spec, Some(&f.name))?;
        }
        Ok(())
    }

    fn zero_or_skip_type_spec(&mut self, spec: &TypeSpec, field_name: Option<&str>) -> Result<(), CodecError> {
        match spec {
            TypeSpec::Padding(n) | TypeSpec::Reserved(n) => {
                let n = *n as usize;
                if self.pos + n > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.data[self.pos..self.pos + n].fill(0);
                self.pos += n;
            }
            TypeSpec::Base(_) | TypeSpec::Bitfield(_) | TypeSpec::SizedInt(_, _) => {
                self.skip_type_spec(spec, None)?;
            }
            TypeSpec::LengthOf(_) | TypeSpec::CountOf(_) => {
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                if let Some(name) = field_name {
                    let v = read_u32_slice(self.data, self.pos, self.endianness)?;
                    self.ctx.set(name.to_string(), v as u64);
                }
                self.pos += 4;
            }
            TypeSpec::PresenceBits(n) => {
                let bitmap = read_bitmap_n(self.data, &mut self.pos, self.endianness, *n)?;
                self.ctx.presence = WalkPresence::Bitmap(bitmap, 0);
            }
            TypeSpec::BitmapPresence { total_bits, presence_per_block, .. } => {
                let max_encoded_bits = if *presence_per_block == 0 { *total_bits } else { ((*total_bits + presence_per_block - 1) / presence_per_block) * (presence_per_block + 1) };
                let max_bytes = ((max_encoded_bits + 7) / 8) as usize;
                let mut bytes = Vec::new();
                if *presence_per_block == 0 {
                    if self.pos + max_bytes > self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    bytes.extend_from_slice(&self.data[self.pos..self.pos + max_bytes]);
                    self.pos += max_bytes;
                } else {
                    let max_blocks = (*total_bits + presence_per_block - 1) / presence_per_block;
                    for _ in 0..max_blocks {
                        if self.pos >= self.data.len() {
                            return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                        }
                        let b = self.data[self.pos];
                        self.pos += 1;
                        bytes.push(b);
                        if b & 0x01 == 0 || bytes.len() >= max_bytes {
                            break;
                        }
                    }
                }
                self.ctx.presence = if *presence_per_block == 0 {
                    WalkPresence::BitmapPresenceConsecutive(bytes, 0, 0)
                } else {
                    WalkPresence::BitmapPresence(bytes, 0, *presence_per_block)
                };
            }
            TypeSpec::PaddingBits(n) => {
                let byte_len = ((*n + 7) / 8) as usize;
                if self.pos + byte_len > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.data[self.pos..self.pos + byte_len].fill(0);
                self.pos += byte_len;
            }
            TypeSpec::StructRef(name) => {
                let s = self.resolved.get_struct(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                for f in &s.fields {
                    if let Some(ref cond) = f.condition {
                        let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                        let expected = cond.value.as_i64();
                        if cond_val != expected {
                            continue;
                        }
                    }
                    self.zero_or_skip_type_spec(&f.type_spec, Some(&f.name))?;
                }
            }
            TypeSpec::Array(elem, len) => {
                let n = match len {
                    ArrayLen::Constant(k) => *k,
                    ArrayLen::FieldRef(field) => self.ctx.get(field).ok_or_else(|| CodecError::UnknownField(field.clone()))?,
                };
                for _ in 0..n {
                    self.zero_or_skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::List(elem) => {
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = read_u32_slice(self.data, self.pos, self.endianness)?;
                self.pos += 4;
                for _ in 0..n {
                    self.zero_or_skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::RepList(elem) => {
                if self.pos + 1 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = self.data[self.pos] as usize;
                self.pos += 1;
                for _ in 0..n {
                    self.zero_or_skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::OctetsFx => {
                while self.pos < self.data.len() {
                    let b = self.data[self.pos];
                    self.pos += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
            }
            TypeSpec::Optional(elem) => {
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::BitmapPresenceConsecutive(bytes, byte_idx, bit_offset) => {
                        let present = *byte_idx < bytes.len() && ((bytes[*byte_idx] >> (7 - *bit_offset)) & 1) != 0;
                        if *bit_offset == 7 {
                            *byte_idx += 1;
                            *bit_offset = 0;
                        } else {
                            *bit_offset += 1;
                        }
                        present
                    }
                    WalkPresence::BitmapPresence(bytes, i, presence_per_block) => {
                        let bits_per_block = *presence_per_block as usize;
                        let byte_idx = *i / bits_per_block;
                        let bit_idx = *i % bits_per_block;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> (7 - bit_idx)) & 1 } else { 0 };
                        bit != 0
                    }
                    WalkPresence::None => read_u8(self.data, &mut self.pos)? != 0,
                };
                if present {
                    self.zero_or_skip_type_spec(elem, None)?;
                }
            }
        }
        Ok(())
    }

    fn skip_type_spec(&mut self, spec: &TypeSpec, field_name: Option<&str>) -> Result<(), CodecError> {
        match spec {
            TypeSpec::Base(bt) => {
                let n = base_type_size(bt);
                if self.pos + n > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.pos += n;
            }
            TypeSpec::Padding(n) | TypeSpec::Reserved(n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("PaddingReserved");
                self.pos += *n as usize;
            }
            TypeSpec::Bitfield(n) | TypeSpec::SizedInt(_, n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("BitfieldSizedInt");
                self.pos += ((*n + 7) / 8) as usize;
            }
            TypeSpec::LengthOf(_) | TypeSpec::CountOf(_) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("LengthOfCountOf");
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                if let Some(name) = field_name {
                    let v = read_u32_slice(self.data, self.pos, self.endianness)?;
                    self.ctx.set(name.to_string(), v as u64);
                }
                self.pos += 4;
            }
            TypeSpec::PresenceBits(n) => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("PresenceBits");
                let bitmap = read_bitmap_n(self.data, &mut self.pos, self.endianness, *n)?;
                self.ctx.presence = WalkPresence::Bitmap(bitmap, 0);
            }
            TypeSpec::BitmapPresence { total_bits, presence_per_block, .. } => {
                #[cfg(feature = "walk_profile")]
                let _g = ProfileGuard::new("BitmapPresence");
                let max_encoded_bits = if *presence_per_block == 0 { *total_bits } else { ((*total_bits + presence_per_block - 1) / presence_per_block) * (presence_per_block + 1) };
                let max_bytes = ((max_encoded_bits + 7) / 8) as usize;
                let mut bytes = Vec::new();
                if *presence_per_block == 0 {
                    if self.pos + max_bytes > self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    bytes.extend_from_slice(&self.data[self.pos..self.pos + max_bytes]);
                    self.pos += max_bytes;
                } else {
                    let max_blocks = (*total_bits + presence_per_block - 1) / presence_per_block;
                    for _ in 0..max_blocks {
                        if self.pos >= self.data.len() {
                            return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                        }
                        let b = self.data[self.pos];
                        self.pos += 1;
                        bytes.push(b);
                        if b & 0x01 == 0 || bytes.len() >= max_bytes {
                            break;
                        }
                    }
                }
                self.ctx.presence = if *presence_per_block == 0 {
                    WalkPresence::BitmapPresenceConsecutive(bytes, 0, 0)
                } else {
                    WalkPresence::BitmapPresence(bytes, 0, *presence_per_block)
                };
            }
            TypeSpec::PaddingBits(n) => {
                let byte_len = ((*n + 7) / 8) as usize;
                if self.pos + byte_len > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.pos += byte_len;
            }
            TypeSpec::StructRef(name) => {
                let s = self.resolved.get_struct(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                for f in &s.fields {
                    if let Some(ref cond) = f.condition {
                        let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                        let expected = cond.value.as_i64();
                        if cond_val != expected {
                            continue;
                        }
                    }
                    self.skip_type_spec(&f.type_spec, Some(&f.name))?;
                }
            }
            TypeSpec::Array(elem, len) => {
                let n = match len {
                    ArrayLen::Constant(k) => *k,
                    ArrayLen::FieldRef(field) => self.ctx.get(field).ok_or_else(|| CodecError::UnknownField(field.clone()))?,
                };
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::List(elem) => {
                if self.pos + 4 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = read_u32_slice(self.data, self.pos, self.endianness)?;
                self.pos += 4;
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::RepList(elem) => {
                if self.pos + 1 > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                let n = self.data[self.pos] as u32;
                self.pos += 1;
                for _ in 0..n {
                    self.skip_type_spec(elem, None)?;
                }
            }
            TypeSpec::OctetsFx => {
                while self.pos < self.data.len() {
                    let b = self.data[self.pos];
                    self.pos += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
            }
            TypeSpec::Optional(elem) => {
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::BitmapPresenceConsecutive(bytes, byte_idx, bit_offset) => {
                        let present = *byte_idx < bytes.len() && ((bytes[*byte_idx] >> (7 - *bit_offset)) & 1) != 0;
                        if *bit_offset == 7 {
                            *byte_idx += 1;
                            *bit_offset = 0;
                        } else {
                            *bit_offset += 1;
                        }
                        present
                    }
                    WalkPresence::BitmapPresence(bytes, i, presence_per_block) => {
                        let bits_per_block = *presence_per_block as usize;
                        let byte_idx = *i / bits_per_block;
                        let bit_idx = *i % bits_per_block;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> (7 - bit_idx)) & 1 } else { 0 };
                        bit != 0
                    }
                    WalkPresence::None => read_u8(self.data, &mut self.pos)? != 0,
                };
                if present {
                    self.skip_type_spec(elem, None)?;
                }
            }
        }
        Ok(())
    }

    fn skip_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            self.skip_type_spec(&f.type_spec, Some(&f.name))?;
        }
        Ok(())
    }
}

// --- Standalone in-place operations (no decode/encode) ---

/// Returns the byte extent of one message by walking the structure.
///
/// Advances from `start` through the whole message (including all optionals present
/// according to presence bits) and returns the number of bytes consumed. No allocation.
/// Use this to know how long one record is before decoding or to split a frame into
/// messages.
pub fn message_extent(
    data: &[u8],
    start: usize,
    resolved: &ResolvedProtocol,
    endianness: Endianness,
    message_name: &str,
) -> Result<usize, CodecError> {
    let mut w = BinaryWalker::at(data, start, resolved, endianness);
    w.skip_message(message_name)
}

/// Validates a message in place by reading only constrained fields and checking ranges/enums.
///
/// Walks the message from `start` and verifies every field that has a `[min..max]` or
/// `[in(...)]` constraint. No allocation; fails with [`CodecError`](crate::codec::CodecError)
/// if any constraint is violated or the buffer is too short.
/// Fields with [`MessageField::saturating`](crate::ast::MessageField) set (at resolve) skip the range check.
pub fn validate_message_in_place(
    data: &[u8],
    start: usize,
    resolved: &ResolvedProtocol,
    endianness: Endianness,
    message_name: &str,
) -> Result<(), CodecError> {
    let mut w = BinaryWalker::at(data, start, resolved, endianness);
    w.validate_message(message_name)
}

/// Zeros all `padding` and `reserved` fields in the given message range, in place.
///
/// Walks the message from `start` and sets every padding/reserved byte to 0. Useful before
/// re-encoding or to sanitise a buffer. No allocation.
pub fn zero_padding_reserved_in_place(
    data: &mut [u8],
    start: usize,
    resolved: &ResolvedProtocol,
    endianness: Endianness,
    message_name: &str,
) -> Result<(), CodecError> {
    let mut w = BinaryWalkerMut::at(data, start, resolved, endianness);
    w.zero_padding_reserved_message(message_name)
}

/// One-pass validate and zeroize: walks the message from `start`, validates constrained fields and zeros padding/reserved; returns bytes consumed.
pub fn validate_and_zero_message_in_place(
    data: &mut [u8],
    start: usize,
    resolved: &ResolvedProtocol,
    endianness: Endianness,
    message_name: &str,
) -> Result<usize, CodecError> {
    let mut w = BinaryWalkerMut::at(data, start, resolved, endianness);
    w.validate_and_zero_message(message_name)
}

/// Removes a message from the frame by shifting bytes.
///
/// The range `buffer[start..start+len]` is the message to remove. Bytes after
/// `start+len` are shifted left to `start`. Returns the new length of the buffer
/// (`original_len - len`). The caller is responsible for updating any length/count
/// fields (e.g. with [`write_u32_in_place`]) so the frame remains valid.
pub fn remove_message_in_place(buffer: &mut [u8], start: usize, len: usize) -> usize {
    let end = start + len;
    if end > buffer.len() {
        return buffer.len();
    }
    let rest = buffer.len() - end;
    if rest > 0 {
        buffer.copy_within(end..buffer.len(), start);
    }
    buffer.len() - len
}

/// Writes a `u32` at the given offset (4 bytes) with the given endianness.
///
/// Typical use: after [`remove_message_in_place`], update a length or count field
/// in the frame header so the remaining buffer describes the new size.
pub fn write_u32_in_place(buffer: &mut [u8], offset: usize, value: u32, endianness: Endianness) -> Result<(), CodecError> {
    if offset + 4 > buffer.len() {
        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    match endianness {
        Endianness::Big => BigEndian::write_u32(&mut buffer[offset..], value),
        Endianness::Little => LittleEndian::write_u32(&mut buffer[offset..], value),
    }
    Ok(())
}

// --- Walk profiling (feature "walk_profile") ---
//
// When the crate is built with `walk_profile`, each skip_type_spec branch records its
// cumulative time. Use reset_walk_profile() before a run and get_walk_profile() after
// to get a label -> nanoseconds map. Labels are the TypeSpec variant names (e.g.
// "Optional", "StructRef", "RepList"). Run the walk_pcap benchmark with
// `--features walk_profile` to print a hotspot summary to stderr.

#[cfg(feature = "walk_profile")]
#[derive(Default)]
struct WalkProfileStats {
    ns_per_label: HashMap<String, u64>,
}

#[cfg(feature = "walk_profile")]
thread_local!(static WALK_PROFILE: RefCell<WalkProfileStats> = RefCell::new(WalkProfileStats::default()));

#[cfg(feature = "walk_profile")]
fn record_walk_profile(label: &'static str, d: std::time::Duration) {
    WALK_PROFILE.with(|p| {
        let mut st = p.borrow_mut();
        *st.ns_per_label.entry(label.to_string()).or_insert(0) += d.as_nanos() as u64;
    });
}

/// Resets accumulated walk profile stats.
///
/// Call before a walk run when the `walk_profile` feature is enabled; then call
/// [`get_walk_profile`] after the run to get the per–type-spec timing breakdown.
#[cfg(feature = "walk_profile")]
pub fn reset_walk_profile() {
    WALK_PROFILE.with(|p| *p.borrow_mut() = WalkProfileStats::default());
}

/// Returns accumulated walk profile: label → total nanoseconds.
///
/// Labels correspond to TypeSpec variants (e.g. `"Optional"`, `"StructRef"`, `"RepList"`).
/// Empty when the `walk_profile` feature is not enabled.
#[cfg(feature = "walk_profile")]
pub fn get_walk_profile() -> HashMap<String, u64> {
    WALK_PROFILE.with(|p| p.borrow().ns_per_label.clone())
}

#[cfg(feature = "walk_profile")]
struct ProfileGuard {
    label: &'static str,
    start: Instant,
}

#[cfg(feature = "walk_profile")]
impl ProfileGuard {
    fn new(label: &'static str) -> Self {
        Self { label, start: Instant::now() }
    }
}

#[cfg(feature = "walk_profile")]
impl Drop for ProfileGuard {
    fn drop(&mut self) {
        record_walk_profile(self.label, self.start.elapsed());
    }
}

#[cfg(not(feature = "walk_profile"))]
/// No-op when the `walk_profile` feature is not enabled.
pub fn reset_walk_profile() {}

#[cfg(not(feature = "walk_profile"))]
/// Returns an empty map when the `walk_profile` feature is not enabled.
pub fn get_walk_profile() -> HashMap<String, u64> {
    HashMap::new()
}

/// Converts codec endianness to walk endianness for use with [`message_extent`] and related APIs.
impl From<crate::codec::Endianness> for Endianness {
    fn from(e: crate::codec::Endianness) -> Self {
        match e {
            crate::codec::Endianness::Big => Endianness::Big,
            crate::codec::Endianness::Little => Endianness::Little,
        }
    }
}
