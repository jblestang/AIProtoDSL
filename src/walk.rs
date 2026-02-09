//! Zero-copy walk over binary data using the message structure.
//!
//! No decode/encode: walk structure to get extent, validate constraints (minimal reads),
//! zero padding/reserved in place, and remove messages by shifting bytes + updating length/count.

use crate::ast::*;
use crate::codec::CodecError;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Endianness {
    Big,
    Little,
}

/// Presence state for optional fields: fixed bitmap (presence_bits) or variable-length FSPEC (fspec).
#[derive(Default)]
enum WalkPresence {
    #[default]
    None,
    Bitmap(u64, usize),
    Fspec(Vec<u8>, usize),
}

/// Context for walk: stores numeric field values and optional presence state.
#[derive(Default)]
struct WalkContext {
    values: HashMap<String, u64>,
    presence: WalkPresence,
}

/// Read-only walker: skip fields/messages and validate without allocating decoded values.
pub struct BinaryWalker<'a> {
    data: &'a [u8],
    pos: usize,
    resolved: &'a ResolvedProtocol,
    endianness: Endianness,
    ctx: WalkContext,
}

/// Mutable walker: same as BinaryWalker plus zero padding/reserved in place.
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

    fn validate_and_skip_message_fields(&mut self, fields: &[MessageField]) -> Result<(), CodecError> {
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = self.ctx.get(cond.field.as_str()).map(|u| u as i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            if f.constraint.is_some() {
                self.validate_field_and_skip(f)?;
            } else {
                self.skip_type_spec(&f.type_spec, Some(&f.name))?;
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

    fn skip_type_spec(&mut self, spec: &TypeSpec, field_name: Option<&str>) -> Result<(), CodecError> {
        match spec {
            TypeSpec::Base(bt) => {
                let n = base_type_size(bt);
                if self.pos + n > self.data.len() {
                    return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                }
                self.pos += n;
            }
            TypeSpec::Padding(n) | TypeSpec::Reserved(n) => self.pos += *n as usize,
            TypeSpec::Bitfield(n) | TypeSpec::SizedInt(_, n) => self.pos += ((*n + 7) / 8) as usize,
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
            TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => {
                let mut bytes = Vec::new();
                loop {
                    if self.pos >= self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    let b = self.data[self.pos];
                    self.pos += 1;
                    bytes.push(b);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                self.ctx.presence = WalkPresence::Fspec(bytes, 0);
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
                self.skip_struct_fields(s.fields.as_slice())?;
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
            TypeSpec::Optional(elem) => {
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::Fspec(bytes, i) => {
                        let byte_idx = *i / 7;
                        let bit_idx = *i % 7;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> bit_idx) & 1 } else { 0 };
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
            TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => {
                let mut bytes = Vec::new();
                loop {
                    if self.pos >= self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    let b = self.data[self.pos];
                    self.pos += 1;
                    bytes.push(b);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                self.ctx.presence = WalkPresence::Fspec(bytes, 0);
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
            TypeSpec::Optional(elem) => {
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::Fspec(bytes, i) => {
                        let byte_idx = *i / 7;
                        let bit_idx = *i % 7;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> bit_idx) & 1 } else { 0 };
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
            TypeSpec::Padding(n) | TypeSpec::Reserved(n) => self.pos += *n as usize,
            TypeSpec::Bitfield(n) | TypeSpec::SizedInt(_, n) => self.pos += ((*n + 7) / 8) as usize,
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
            TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => {
                let mut bytes = Vec::new();
                loop {
                    if self.pos >= self.data.len() {
                        return Err(CodecError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
                    }
                    let b = self.data[self.pos];
                    self.pos += 1;
                    bytes.push(b);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                self.ctx.presence = WalkPresence::Fspec(bytes, 0);
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
            TypeSpec::Optional(elem) => {
                let present = match &mut self.ctx.presence {
                    WalkPresence::Bitmap(bitmap, i) => {
                        let bit = (*bitmap >> *i) & 1;
                        *i += 1;
                        bit != 0
                    }
                    WalkPresence::Fspec(bytes, i) => {
                        let byte_idx = *i / 7;
                        let bit_idx = *i % 7;
                        *i += 1;
                        let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> bit_idx) & 1 } else { 0 };
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

/// Return the byte extent of one message by walking the structure. No allocation.
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

/// Validate a message in place (read only constrained fields). No allocation.
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

/// Zero all padding and reserved fields in the given message range, in place. No allocation.
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

/// Remove a message from the frame by shifting bytes. Caller must update length/count fields separately.
/// `buffer[start..start+len]` is the message to remove; bytes after `start+len` are shifted to `start`.
/// Returns the new length of the buffer (original_len - len).
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

/// Write a u32 at the given offset (4 bytes) with the given endianness. Use to update length/count after removing a message.
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

/// Convert codec::Endianness to walk::Endianness so walk can be used with Codec's resolved + endianness.
impl From<crate::codec::Endianness> for Endianness {
    fn from(e: crate::codec::Endianness) -> Self {
        match e {
            crate::codec::Endianness::Big => Endianness::Big,
            crate::codec::Endianness::Little => Endianness::Little,
        }
    }
}
