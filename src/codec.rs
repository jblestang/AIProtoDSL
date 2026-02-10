//! Encode/decode binary packets from protocol definitions.
//!
//! Handles base types (with configurable endianness), padding/reserved (zeroed on encode),
//! length_of/count_of, structs, lists, and validation.

use crate::ast::*;
use crate::value::Value;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Endianness {
    Big,
    Little,
}

#[derive(Debug)]
pub struct Codec {
    pub endianness: Endianness,
    resolved: ResolvedProtocol,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Validation: {0}")]
    Validation(String),
    #[error("Unknown struct: {0}")]
    UnknownStruct(String),
    #[error("Unknown field: {0}")]
    UnknownField(String),
    #[error("Length/count mismatch: {0}")]
    LengthMismatch(String),
}

impl Codec {
    pub fn new(resolved: ResolvedProtocol, endianness: Endianness) -> Self {
        Codec { endianness, resolved }
    }

    /// Decode a single message by name from the given bytes.
    pub fn decode_message(
        &self,
        message_name: &str,
        bytes: &[u8],
    ) -> Result<HashMap<String, Value>, CodecError> {
        self.decode_message_with_extent(message_name, bytes)
            .1
    }

    /// Decode a single message and return (bytes_consumed, result). Used by frame decoder to skip non-compliant messages.
    /// Decodes the full message first (to get byte extent), then validates; so on validation error we still return correct consumed.
    pub fn decode_message_with_extent(
        &self,
        message_name: &str,
        bytes: &[u8],
    ) -> (usize, Result<HashMap<String, Value>, CodecError>) {
        let msg = match self.resolved.get_message(message_name) {
            Some(m) => m,
            None => return (0, Err(CodecError::UnknownStruct(message_name.to_string()))),
        };
        let mut cursor = Cursor::new(bytes);
        let mut ctx = DecodeContext::default();
        let values = match self.decode_message_fields_no_validate(&mut cursor, msg.fields.as_slice(), &mut ctx) {
            Ok(v) => v,
            Err(e) => return (cursor.position() as usize, Err(e)),
        };
        let consumed = cursor.position() as usize;
        for f in &msg.fields {
            if let Some(ref c) = f.constraint {
                if let Some(v) = values.get(&f.name) {
                    if let Err(e) = self.validate_constraint(v, Some(c)) {
                        return (consumed, Err(e));
                    }
                }
            }
        }
        (consumed, Ok(values))
    }

    /// Encode a single message by name. Padding/reserved are written as zero.
    pub fn encode_message(
        &self,
        message_name: &str,
        values: &HashMap<String, Value>,
    ) -> Result<Vec<u8>, CodecError> {
        let msg = self
            .resolved
            .get_message(message_name)
            .ok_or_else(|| CodecError::UnknownStruct(message_name.to_string()))?;
        let mut out = Vec::new();
        let mut ctx = EncodeContext::from_values(values);
        self.encode_message_fields(&mut out, msg.fields.as_slice(), &mut ctx)?;
        Ok(out)
    }

    /// Decode transport header (if defined).
    pub fn decode_transport(&self, bytes: &[u8]) -> Result<HashMap<String, Value>, CodecError> {
        let transport = match &self.resolved.protocol.transport {
            Some(t) => t,
            None => return Ok(HashMap::new()),
        };
        let mut cursor = Cursor::new(bytes);
        let mut ctx = DecodeContext::default();
        self.decode_transport_fields(&mut cursor, &transport.fields, &mut ctx)
    }

    /// Encode transport header (padding/reserved zeroed).
    pub fn encode_transport(
        &self,
        values: &HashMap<String, Value>,
    ) -> Result<Vec<u8>, CodecError> {
        let transport = match &self.resolved.protocol.transport {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        let mut ctx = EncodeContext::from_values(values);
        self.encode_transport_fields(&mut out, &transport.fields, &mut ctx)?;
        Ok(out)
    }

    fn decode_transport_fields(
        &self,
        r: &mut Cursor<&[u8]>,
        fields: &[TransportField],
        _ctx: &mut DecodeContext,
    ) -> Result<HashMap<String, Value>, CodecError> {
        let mut out = HashMap::new();
        for f in fields {
            let v = self.decode_transport_type(r, &f.type_spec)?;
            self.validate_constraint(&v, f.constraint.as_ref())?;
            out.insert(f.name.clone(), v);
        }
        Ok(out)
    }

    fn decode_transport_type(
        &self,
        r: &mut Cursor<&[u8]>,
        spec: &TransportTypeSpec,
    ) -> Result<Value, CodecError> {
        match spec {
            TransportTypeSpec::Base(bt) => self.decode_base(r, bt),
            TransportTypeSpec::SizedInt(bt, n) => self.decode_sized_int(r, bt, *n),
            TransportTypeSpec::Padding(n) => {
                let mut buf = vec![0u8; *n as usize];
                r.read_exact(&mut buf)?;
                Ok(Value::Padding)
            }
            TransportTypeSpec::Reserved(n) => {
                let mut buf = vec![0u8; *n as usize];
                r.read_exact(&mut buf)?;
                Ok(Value::Reserved)
            }
            TransportTypeSpec::Bitfield(n) => {
                let bits = (*n + 7) / 8;
                let mut buf = vec![0u8; bits as usize];
                r.read_exact(&mut buf)?;
                let v = self.bytes_to_u64(&buf);
                Ok(Value::U64(v))
            }
            TransportTypeSpec::Magic(expected) => {
                let mut buf = vec![0u8; expected.len()];
                r.read_exact(&mut buf)?;
                Ok(Value::Bytes(buf))
            }
        }
    }

    fn encode_transport_fields(
        &self,
        w: &mut Vec<u8>,
        fields: &[TransportField],
        ctx: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        for f in fields {
            let v = ctx.get(&f.name).cloned().unwrap_or(Value::Padding);
            self.encode_transport_type(w, &f.type_spec, &v)?;
        }
        Ok(())
    }

    fn encode_transport_type(
        &self,
        w: &mut Vec<u8>,
        spec: &TransportTypeSpec,
        v: &Value,
    ) -> Result<(), CodecError> {
        match spec {
            TransportTypeSpec::Base(bt) => self.encode_base(w, bt, v),
            TransportTypeSpec::SizedInt(bt, n) => self.encode_sized_int(w, bt, *n, v),
            TransportTypeSpec::Padding(n) => {
                w.write_all(&vec![0u8; *n as usize])?;
                Ok(())
            }
            TransportTypeSpec::Reserved(n) => {
                w.write_all(&vec![0u8; *n as usize])?;
                Ok(())
            }
            TransportTypeSpec::Bitfield(n) => {
                let bits = (*n + 7) / 8;
                let val = v.as_u64().unwrap_or(0);
                let buf = self.u64_to_bytes(val, bits as usize);
                w.write_all(&buf)?;
                Ok(())
            }
            TransportTypeSpec::Magic(expected) => {
                if let Value::Bytes(b) = v {
                    if b.len() == expected.len() {
                        w.write_all(b)?;
                    } else {
                        w.write_all(expected)?;
                    }
                } else {
                    w.write_all(expected)?;
                }
                Ok(())
            }
        }
    }

    fn decode_message_fields_no_validate(
        &self,
        r: &mut Cursor<&[u8]>,
        fields: &[MessageField],
        ctx: &mut DecodeContext,
    ) -> Result<HashMap<String, Value>, CodecError> {
        // Bit packing is local to a message: reset bit cursor for this scope.
        let saved_bits = ctx.bit_read;
        ctx.bit_read = BitReadState::default();
        let mut out = HashMap::new();
        for f in fields {
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            let v = self
                .decode_type_spec(r, &f.type_spec, &self.resolved.protocol.structs, ctx)
                .map_err(|e| CodecError::Validation(format!("field {}: {}", f.name, e)))?;
            ctx.set(f.name.clone(), v.clone());
            out.insert(f.name.clone(), v);
        }
        if !ctx.bit_read.is_aligned() {
            ctx.bit_read = saved_bits;
            return Err(CodecError::Validation(
                "message: bitfield/padding_bits not byte-aligned at end".to_string(),
            ));
        }
        ctx.bit_read = saved_bits;
        Ok(out)
    }

    fn encode_message_fields(
        &self,
        w: &mut Vec<u8>,
        fields: &[MessageField],
        ctx: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        // Bit packing is local to a message: reset bit cursor for this scope.
        let saved_bits = ctx.bit_write;
        ctx.bit_write = BitWriteState::default();
        let structs = &self.resolved.protocol.structs;
        let mut skip_count = 0usize;
        let mut i = 0;
        while i < fields.len() {
            if skip_count > 0 {
                skip_count -= 1;
                i += 1;
                continue;
            }
            let f = &fields[i];
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    i += 1;
                    continue;
                }
            }
            if let TypeSpec::PresenceBits(n) = &f.type_spec {
                let optional_indices = self.collect_following_optionals_message(fields, i + 1, ctx);
                let bitmap = self.build_presence_bitmap_message(fields, &optional_indices, ctx);
                self.write_bitmap_n(w, *n, bitmap)?;
                for (bit_j, &idx) in optional_indices.iter().enumerate() {
                    if (bitmap >> bit_j) & 1 != 0 {
                        let o = &fields[idx];
                        let v = ctx.get(&o.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&o.type_spec));
                        if let TypeSpec::Optional(elem) = &o.type_spec {
                            let inner = v.as_list().and_then(|l| l.first().cloned()).unwrap_or_else(|| self.default_for_type_spec(elem));
                            self.encode_type_spec(w, elem, &inner, structs, ctx)?;
                        }
                    }
                }
                skip_count = optional_indices.len();
                i += 1;
                continue;
            }
            if matches!(&f.type_spec, TypeSpec::Fspec | TypeSpec::FspecWithMapping(_)) {
                let optional_indices = self.collect_following_optionals_message(fields, i + 1, ctx);
                let fspec_bytes = self.build_fspec_bytes_message(fields, &optional_indices, ctx);
                w.write_all(&fspec_bytes)?;
                for (bit_j, &idx) in optional_indices.iter().enumerate() {
                    if fspec_bytes.get(bit_j / 7).map(|&b| (b >> (bit_j % 7)) & 1).unwrap_or(0) != 0 {
                        let o = &fields[idx];
                        let v = ctx.get(&o.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&o.type_spec));
                        if let TypeSpec::Optional(elem) = &o.type_spec {
                            let inner = v.as_list().and_then(|l| l.first().cloned()).unwrap_or_else(|| self.default_for_type_spec(elem));
                            self.encode_type_spec(w, elem, &inner, structs, ctx)?;
                        }
                    }
                }
                skip_count = optional_indices.len();
                i += 1;
                continue;
            }
            let v = ctx.get(&f.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&f.type_spec));
            self.encode_type_spec(w, &f.type_spec, &v, structs, ctx)?;
            i += 1;
        }
        if !ctx.bit_write.is_aligned() {
            ctx.bit_write = saved_bits;
            return Err(CodecError::Validation(
                "message: bitfield/padding_bits not byte-aligned at end".to_string(),
            ));
        }
        ctx.bit_write = saved_bits;
        Ok(())
    }

    fn collect_following_optionals_message(&self, fields: &[MessageField], start: usize, ctx: &EncodeContext) -> Vec<usize> {
        let mut out = Vec::new();
        for j in start..fields.len() {
            let f = &fields[j];
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            if matches!(&f.type_spec, TypeSpec::Optional(_)) {
                out.push(j);
            } else {
                break;
            }
        }
        out
    }

    fn build_presence_bitmap_message(&self, fields: &[MessageField], indices: &[usize], ctx: &EncodeContext) -> u64 {
        let mut bitmap = 0u64;
        for (bit, &idx) in indices.iter().enumerate() {
            let v = ctx.get(&fields[idx].name);
            let present = v.map(|v| v.as_list().map(|l| !l.is_empty()).unwrap_or(false)).unwrap_or(false);
            if present {
                bitmap |= 1 << bit;
            }
        }
        bitmap
    }

    /// Build ASTERIX FSPEC bytes: 7 presence bits per byte, bit 7 (FX) = 1 if more bytes follow.
    fn build_fspec_bytes_message(&self, fields: &[MessageField], indices: &[usize], ctx: &EncodeContext) -> Vec<u8> {
        let mut bits = Vec::with_capacity(indices.len());
        for &idx in indices {
            let v = ctx.get(&fields[idx].name);
            let present = v.map(|v| v.as_list().map(|l| !l.is_empty()).unwrap_or(false)).unwrap_or(false);
            bits.push(present);
        }
        let mut out = Vec::new();
        for chunk in bits.chunks(7) {
            let mut byte = 0u8;
            for (j, &present) in chunk.iter().enumerate() {
                if present {
                    byte |= 1 << j;
                }
            }
            let more = out.len() * 7 + chunk.len() < bits.len();
            if more {
                byte |= 0x80;
            }
            out.push(byte);
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    fn write_bitmap_n(&self, w: &mut Vec<u8>, n: u64, bitmap: u64) -> Result<(), CodecError> {
        let len = match n {
            1 => 1,
            2 => 2,
            4 => 4,
            _ => return Err(CodecError::Validation("presence_bits(n): n must be 1, 2, or 4".to_string())),
        };
        let buf = self.u64_to_bytes(bitmap, len);
        w.write_all(&buf)?;
        Ok(())
    }

    fn ensure_decode_bit_aligned(&self, ctx: &DecodeContext) -> Result<(), CodecError> {
        if ctx.bit_read.is_aligned() {
            Ok(())
        } else {
            Err(CodecError::Validation(
                "bitfield/padding_bits not byte-aligned (missing padding_bits?)".to_string(),
            ))
        }
    }

    fn ensure_encode_bit_aligned(&self, ctx: &EncodeContext) -> Result<(), CodecError> {
        if ctx.bit_write.is_aligned() {
            Ok(())
        } else {
            Err(CodecError::Validation(
                "bitfield/padding_bits not byte-aligned (missing padding_bits?)".to_string(),
            ))
        }
    }

    fn read_bits(&self, r: &mut Cursor<&[u8]>, ctx: &mut DecodeContext, n: u64) -> Result<u64, CodecError> {
        if n > 64 {
            return Err(CodecError::Validation(format!("bitfield({}): too many bits (max 64)", n)));
        }
        let mut out = 0u64;
        for i in 0..(n as u8) {
            if ctx.bit_read.next_bit == 8 {
                ctx.bit_read.cur = r.read_u8()?;
                ctx.bit_read.next_bit = 0;
            }
            let bit = (ctx.bit_read.cur >> ctx.bit_read.next_bit) & 1;
            if bit != 0 {
                out |= 1u64 << i;
            }
            ctx.bit_read.next_bit += 1;
            if ctx.bit_read.next_bit == 8 {
                ctx.bit_read.next_bit = 8;
            }
        }
        Ok(out)
    }

    fn write_bits(&self, w: &mut Vec<u8>, ctx: &mut EncodeContext, n: u64, mut value: u64) -> Result<(), CodecError> {
        if n > 64 {
            return Err(CodecError::Validation(format!("bitfield({}): too many bits (max 64)", n)));
        }
        for _ in 0..n {
            let bit = (value & 1) as u8;
            value >>= 1;
            if bit != 0 {
                ctx.bit_write.cur |= 1u8 << ctx.bit_write.next_bit;
            }
            ctx.bit_write.next_bit += 1;
            if ctx.bit_write.next_bit == 8 {
                w.write_all(&[ctx.bit_write.cur])?;
                ctx.bit_write.cur = 0;
                ctx.bit_write.next_bit = 0;
            }
        }
        Ok(())
    }

    fn decode_type_spec(
        &self,
        r: &mut Cursor<&[u8]>,
        spec: &TypeSpec,
        structs: &[StructSection],
        ctx: &mut DecodeContext,
    ) -> Result<Value, CodecError> {
        match spec {
            TypeSpec::Base(bt) => {
                self.ensure_decode_bit_aligned(ctx)?;
                self.decode_base(r, bt)
            }
            TypeSpec::Padding(n) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let mut buf = vec![0u8; *n as usize];
                r.read_exact(&mut buf)?;
                Ok(Value::Padding)
            }
            TypeSpec::Reserved(n) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let mut buf = vec![0u8; *n as usize];
                r.read_exact(&mut buf)?;
                Ok(Value::Reserved)
            }
            TypeSpec::Bitfield(n) => {
                let v = self.read_bits(r, ctx, *n)?;
                Ok(Value::U64(v))
            }
            TypeSpec::SizedInt(bt, n) => {
                if ctx.bit_read.is_aligned() {
                    self.decode_sized_int(r, bt, *n)
                } else {
                    let raw = self.read_bits(r, ctx, *n)?;
                    // Reuse the sign-extension and base-type casting rules of decode_sized_int.
                    let mask = if *n >= 64 { u64::MAX } else { (1u64 << *n) - 1 };
                    let raw = raw & mask;
                    let val: i64 = match bt {
                        BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64 if *n > 0 => {
                            let sign_bit = 1i64 << (*n as i64 - 1);
                            if (raw as i64) >= sign_bit {
                                (raw as i64) - (1i64 << *n as i64)
                            } else {
                                raw as i64
                            }
                        }
                        _ => raw as i64,
                    };
                    Ok(match bt {
                        BaseType::U8 => Value::U8(val as u8),
                        BaseType::U16 => Value::U16(val as u16),
                        BaseType::U32 => Value::U32(val as u32),
                        BaseType::U64 => Value::U64(val as u64),
                        BaseType::I8 => Value::I8(val as i8),
                        BaseType::I16 => Value::I16(val as i16),
                        BaseType::I32 => Value::I32(val as i32),
                        BaseType::I64 => Value::I64(val),
                        _ => Value::U64(raw),
                    })
                }
            }
            TypeSpec::LengthOf(_) => {
                self.ensure_decode_bit_aligned(ctx)?;
                // Length fields are typically u16/u32 - decode as u32 for generality
                let v = self.read_u32(r)?;
                Ok(Value::U32(v))
            }
            TypeSpec::CountOf(_) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let v = self.read_u32(r)?;
                Ok(Value::U32(v))
            }
            TypeSpec::PresenceBits(n) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let bytes = *n as usize;
                let bitmap = match bytes {
                    1 => r.read_u8()? as u64,
                    2 => self.read_u16(r)? as u64,
                    4 => self.read_u32(r)? as u64,
                    _ => return Err(CodecError::Validation("presence_bits(n): n must be 1, 2, or 4".to_string())),
                };
                ctx.presence = Some(PresenceState::Bitmap { value: bitmap, bit_index: 0 });
                Ok(Value::U64(bitmap))
            }
            TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let mut bytes = Vec::new();
                loop {
                    let b = r.read_u8()?;
                    bytes.push(b);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                ctx.presence = Some(PresenceState::Fspec { bytes: bytes.clone(), bit_index: 0 });
                Ok(Value::Bytes(bytes))
            }
            TypeSpec::PaddingBits(n) => {
                // Padding/spare bits: consume bits, ignore value (real-world captures may set FX/extension bits).
                let _ = self.read_bits(r, ctx, *n)?;
                Ok(Value::Padding)
            }
            TypeSpec::StructRef(name) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let s = self.resolved.get_struct(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                self.decode_struct(r, s, structs, ctx)
            }
            TypeSpec::Array(elem, len) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let n = match len {
                    ArrayLen::Constant(k) => *k,
                    ArrayLen::FieldRef(field) => ctx.get(field).and_then(Value::as_u64).ok_or_else(|| CodecError::UnknownField(field.clone()))?,
                };
                let mut list = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    list.push(self.decode_type_spec(r, elem, structs, ctx)?);
                }
                Ok(Value::List(list))
            }
            TypeSpec::List(elem) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let n = self.read_u32(r)?;
                let mut list = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    list.push(self.decode_type_spec(r, elem, structs, ctx)?);
                }
                Ok(Value::List(list))
            }
            TypeSpec::RepList(elem) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let n = self.read_u8(r)? as u64;
                let mut list = Vec::with_capacity(n as usize);
                for i in 0..n {
                    let v = self
                        .decode_type_spec(r, elem, structs, ctx)
                        .map_err(|e| CodecError::Validation(format!("rep_list item {}/{}: {}", i + 1, n, e)))?;
                    list.push(v);
                }
                Ok(Value::List(list))
            }
            TypeSpec::Optional(elem) => {
                self.ensure_decode_bit_aligned(ctx)?;
                let present = if let Some(ref mut pre) = ctx.presence {
                    match pre {
                        PresenceState::Bitmap { value, bit_index } => {
                            let bit = (*value >> *bit_index) & 1;
                            *bit_index += 1;
                            bit != 0
                        }
                        PresenceState::Fspec { bytes, bit_index } => {
                            let byte_idx = *bit_index / 7;
                            let bit_idx = *bit_index % 7;
                            *bit_index += 1;
                            let bit = if byte_idx < bytes.len() { (bytes[byte_idx] >> bit_idx) & 1 } else { 0 };
                            bit != 0
                        }
                    }
                } else {
                    let n = self.read_u8(r)?;
                    n != 0
                };
                if present {
                    self.decode_type_spec(r, elem, structs, ctx)
                } else {
                    Ok(Value::List(vec![]))
                }
            }
        }
    }

    fn encode_type_spec(
        &self,
        w: &mut Vec<u8>,
        spec: &TypeSpec,
        v: &Value,
        structs: &[StructSection],
        ctx: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        match spec {
            TypeSpec::Base(bt) => {
                self.ensure_encode_bit_aligned(ctx)?;
                self.encode_base(w, bt, v)
            }
            TypeSpec::Padding(n) => {
                self.ensure_encode_bit_aligned(ctx)?;
                w.write_all(&vec![0u8; *n as usize])?;
                Ok(())
            }
            TypeSpec::Reserved(n) => {
                self.ensure_encode_bit_aligned(ctx)?;
                w.write_all(&vec![0u8; *n as usize])?;
                Ok(())
            }
            TypeSpec::Bitfield(n) => {
                let val = v.as_u64().unwrap_or(0);
                self.write_bits(w, ctx, *n, val)
            }
            TypeSpec::SizedInt(bt, n) => {
                if ctx.bit_write.is_aligned() {
                    self.encode_sized_int(w, bt, *n, v)
                } else {
                    let mask = if *n >= 64 { u64::MAX } else { (1u64 << *n) - 1 };
                    let raw = match bt {
                        BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64 => {
                            (v.as_i64().unwrap_or(0) as u64) & mask
                        }
                        _ => v.as_u64().unwrap_or(0) & mask,
                    };
                    self.write_bits(w, ctx, *n, raw)
                }
            }
            TypeSpec::LengthOf(_) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let val = v.as_u64().unwrap_or(0);
                self.write_u32(w, val as u32)?;
                Ok(())
            }
            TypeSpec::CountOf(_) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let val = v.as_u64().unwrap_or(0);
                self.write_u32(w, val as u32)?;
                Ok(())
            }
            TypeSpec::PresenceBits(_) | TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => {
                // Written by encode_message_fields / encode_struct when they see this field and look ahead.
                Ok(())
            }
            TypeSpec::PaddingBits(n) => {
                self.write_bits(w, ctx, *n, 0)
            }
            TypeSpec::StructRef(name) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let s = self.resolved.get_struct(name).ok_or_else(|| CodecError::UnknownStruct(name.clone()))?;
                let m = v.as_struct().cloned().unwrap_or_default();
                let mut sub = EncodeContext::from_values(&m);
                self.encode_struct(w, s, structs, &mut sub)?;
                Ok(())
            }
            TypeSpec::Array(elem, _len) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let list = v.as_list().map(|s| s.to_vec()).unwrap_or_default();
                for item in list {
                    self.encode_type_spec(w, elem, &item, structs, ctx)?;
                }
                Ok(())
            }
            TypeSpec::List(elem) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let list = v.as_list().map(|s| s.to_vec()).unwrap_or_default();
                self.write_u32(w, list.len() as u32)?;
                for item in list {
                    self.encode_type_spec(w, elem, &item, structs, ctx)?;
                }
                Ok(())
            }
            TypeSpec::RepList(elem) => {
                self.ensure_encode_bit_aligned(ctx)?;
                let list = v.as_list().map(|s| s.to_vec()).unwrap_or_default();
                let n = list.len().min(255);
                self.write_u8(w, n as u8)?;
                for item in list.into_iter().take(n) {
                    self.encode_type_spec(w, elem, &item, structs, ctx)?;
                }
                Ok(())
            }
            TypeSpec::Optional(elem) => {
                self.ensure_encode_bit_aligned(ctx)?;
                if v.as_list().map(|s| s.is_empty()).unwrap_or(true) {
                    self.write_u8(w, 0)?;
                } else {
                    self.write_u8(w, 1)?;
                    self.encode_type_spec(w, elem, v, structs, ctx)?;
                }
                Ok(())
            }
        }
    }

    fn decode_struct(
        &self,
        r: &mut Cursor<&[u8]>,
        s: &StructSection,
        structs: &[StructSection],
        ctx: &mut DecodeContext,
    ) -> Result<Value, CodecError> {
        // Bit packing is local to a struct: reset bit cursor for this scope.
        let saved_bits = ctx.bit_read;
        ctx.bit_read = BitReadState::default();
        let mut out = HashMap::new();
        for f in &s.fields {
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            let v = self
                .decode_type_spec(r, &f.type_spec, structs, ctx)
                .map_err(|e| CodecError::Validation(format!("{}.{}: {}", s.name, f.name, e)))?;
            self.validate_constraint(&v, f.constraint.as_ref())?;
            ctx.set(f.name.clone(), v.clone());
            out.insert(f.name.clone(), v);
        }
        // Ensure the struct ends on a byte boundary (padding_bits should make it so).
        if !ctx.bit_read.is_aligned() {
            ctx.bit_read = saved_bits;
            return Err(CodecError::Validation(format!(
                "struct {}: bitfield/padding_bits not byte-aligned at end",
                s.name
            )));
        }
        ctx.bit_read = saved_bits;
        Ok(Value::Struct(out))
    }

    fn encode_struct(
        &self,
        w: &mut Vec<u8>,
        s: &StructSection,
        structs: &[StructSection],
        ctx: &mut EncodeContext,
    ) -> Result<(), CodecError> {
        // Bit packing is local to a struct: reset bit cursor for this scope.
        let saved_bits = ctx.bit_write;
        ctx.bit_write = BitWriteState::default();
        let mut skip_count = 0usize;
        let mut i = 0;
        while i < s.fields.len() {
            if skip_count > 0 {
                skip_count -= 1;
                i += 1;
                continue;
            }
            let f = &s.fields[i];
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    i += 1;
                    continue;
                }
            }
            if let TypeSpec::PresenceBits(n) = &f.type_spec {
                let optional_indices = self.collect_following_optionals_struct(&s.fields, i + 1, ctx);
                let bitmap = self.build_presence_bitmap_struct(&s.fields, &optional_indices, ctx);
                self.write_bitmap_n(w, *n, bitmap)?;
                for (bit_j, &idx) in optional_indices.iter().enumerate() {
                    if (bitmap >> bit_j) & 1 != 0 {
                        let o = &s.fields[idx];
                        let v = ctx.get(&o.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&o.type_spec));
                        if let TypeSpec::Optional(elem) = &o.type_spec {
                            let inner = v.as_list().and_then(|l| l.first().cloned()).unwrap_or_else(|| self.default_for_type_spec(elem));
                            self.encode_type_spec(w, elem, &inner, structs, ctx)?;
                        }
                    }
                }
                skip_count = optional_indices.len();
                i += 1;
                continue;
            }
            if matches!(&f.type_spec, TypeSpec::Fspec | TypeSpec::FspecWithMapping(_)) {
                let optional_indices = self.collect_following_optionals_struct(&s.fields, i + 1, ctx);
                let fspec_bytes = self.build_fspec_bytes_struct(&s.fields, &optional_indices, ctx);
                w.write_all(&fspec_bytes)?;
                for (bit_j, &idx) in optional_indices.iter().enumerate() {
                    if fspec_bytes.get(bit_j / 7).map(|&b| (b >> (bit_j % 7)) & 1).unwrap_or(0) != 0 {
                        let o = &s.fields[idx];
                        let v = ctx.get(&o.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&o.type_spec));
                        if let TypeSpec::Optional(elem) = &o.type_spec {
                            let inner = v.as_list().and_then(|l| l.first().cloned()).unwrap_or_else(|| self.default_for_type_spec(elem));
                            self.encode_type_spec(w, elem, &inner, structs, ctx)?;
                        }
                    }
                }
                skip_count = optional_indices.len();
                i += 1;
                continue;
            }
            let v = ctx.get(&f.name).cloned().unwrap_or_else(|| self.default_for_type_spec(&f.type_spec));
            self.encode_type_spec(w, &f.type_spec, &v, structs, ctx)?;
            i += 1;
        }
        if !ctx.bit_write.is_aligned() {
            ctx.bit_write = saved_bits;
            return Err(CodecError::Validation(format!(
                "struct {}: bitfield/padding_bits not byte-aligned at end",
                s.name
            )));
        }
        ctx.bit_write = saved_bits;
        Ok(())
    }

    fn collect_following_optionals_struct(&self, fields: &[StructField], start: usize, ctx: &EncodeContext) -> Vec<usize> {
        let mut out = Vec::new();
        for j in start..fields.len() {
            let f = &fields[j];
            if let Some(ref cond) = f.condition {
                let cond_val = ctx.get(cond.field.as_str()).and_then(Value::as_i64);
                let expected = cond.value.as_i64();
                if cond_val != expected {
                    continue;
                }
            }
            if matches!(&f.type_spec, TypeSpec::Optional(_)) {
                out.push(j);
            } else {
                break;
            }
        }
        out
    }

    fn build_presence_bitmap_struct(&self, fields: &[StructField], indices: &[usize], ctx: &EncodeContext) -> u64 {
        let mut bitmap = 0u64;
        for (bit, &idx) in indices.iter().enumerate() {
            let v = ctx.get(&fields[idx].name);
            let present = v.map(|v| v.as_list().map(|l| !l.is_empty()).unwrap_or(false)).unwrap_or(false);
            if present {
                bitmap |= 1 << bit;
            }
        }
        bitmap
    }

    fn build_fspec_bytes_struct(&self, fields: &[StructField], indices: &[usize], ctx: &EncodeContext) -> Vec<u8> {
        let mut bits = Vec::with_capacity(indices.len());
        for &idx in indices {
            let v = ctx.get(&fields[idx].name);
            let present = v.map(|v| v.as_list().map(|l| !l.is_empty()).unwrap_or(false)).unwrap_or(false);
            bits.push(present);
        }
        let mut out = Vec::new();
        for chunk in bits.chunks(7) {
            let mut byte = 0u8;
            for (j, &present) in chunk.iter().enumerate() {
                if present {
                    byte |= 1 << j;
                }
            }
            let more = out.len() * 7 + chunk.len() < bits.len();
            if more {
                byte |= 0x80;
            }
            out.push(byte);
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    fn default_for_type_spec(&self, spec: &TypeSpec) -> Value {
        match spec {
            TypeSpec::Base(BaseType::Bool) => Value::Bool(false),
            TypeSpec::Base(BaseType::Float) => Value::Float(0.0),
            TypeSpec::Base(BaseType::Double) => Value::Double(0.0),
            TypeSpec::Base(_) => Value::U64(0),
            TypeSpec::Padding(_) | TypeSpec::Reserved(_) | TypeSpec::PaddingBits(_) => Value::Padding,
            TypeSpec::List(_) => Value::List(vec![]),
            TypeSpec::StructRef(_) => Value::Struct(HashMap::new()),
            TypeSpec::Fspec | TypeSpec::FspecWithMapping(_) => Value::Bytes(vec![]),
            _ => Value::U64(0),
        }
    }

    fn validate_constraint(&self, v: &Value, c: Option<&Constraint>) -> Result<(), CodecError> {
        let c = match c {
            Some(x) => x,
            None => return Ok(()),
        };
        match c {
            Constraint::Range(intervals) => {
                let n = v.as_i64().ok_or_else(|| CodecError::Validation("expected numeric for range".to_string()))?;
                let in_any = intervals.iter().any(|(min, max)| n >= *min && n <= *max);
                if !in_any {
                    return Err(CodecError::Validation(format!(
                        "value {} not in any interval {:?}",
                        n,
                        intervals
                    )));
                }
            }
            Constraint::Enum(allowed) => {
                let n = v.as_i64();
                let ok = allowed.iter().any(|l| l.as_i64() == n);
                if !ok {
                    return Err(CodecError::Validation("value not in allowed enum".to_string()));
                }
            }
        }
        Ok(())
    }

    fn decode_base(&self, r: &mut Cursor<&[u8]>, bt: &BaseType) -> Result<Value, CodecError> {
        Ok(match bt {
            BaseType::U8 => Value::U8(r.read_u8()?),
            BaseType::U16 => Value::U16(self.read_u16(r)?),
            BaseType::U32 => Value::U32(self.read_u32(r)?),
            BaseType::U64 => Value::U64(self.read_u64(r)?),
            BaseType::I8 => Value::I8(r.read_i8()?),
            BaseType::I16 => Value::I16(self.read_i16(r)?),
            BaseType::I32 => Value::I32(self.read_i32(r)?),
            BaseType::I64 => Value::I64(self.read_i64(r)?),
            BaseType::Bool => Value::Bool(r.read_u8()? != 0),
            BaseType::Float => Value::Float(self.read_f32(r)?),
            BaseType::Double => Value::Double(self.read_f64(r)?),
        })
    }

    fn encode_base(&self, w: &mut Vec<u8>, bt: &BaseType, v: &Value) -> Result<(), CodecError> {
        match bt {
            BaseType::U8 => w.write_u8(v.as_u64().unwrap_or(0) as u8)?,
            BaseType::U16 => self.write_u16(w, v.as_u64().unwrap_or(0) as u16)?,
            BaseType::U32 => self.write_u32(w, v.as_u64().unwrap_or(0) as u32)?,
            BaseType::U64 => self.write_u64(w, v.as_u64().unwrap_or(0))?,
            BaseType::I8 => w.write_i8(v.as_i64().unwrap_or(0) as i8)?,
            BaseType::I16 => self.write_i16(w, v.as_i64().unwrap_or(0) as i16)?,
            BaseType::I32 => self.write_i32(w, v.as_i64().unwrap_or(0) as i32)?,
            BaseType::I64 => self.write_i64(w, v.as_i64().unwrap_or(0))?,
            BaseType::Bool => w.write_u8(if v.as_u64().unwrap_or(0) != 0 { 1 } else { 0 })?,
            BaseType::Float => self.write_f32(w, v.as_f32().unwrap_or(0.0)),
            BaseType::Double => self.write_f64(w, v.as_f64().unwrap_or(0.0)),
        }
        Ok(())
    }

    fn decode_sized_int(&self, r: &mut Cursor<&[u8]>, bt: &BaseType, n: u64) -> Result<Value, CodecError> {
        let bytes = ((n + 7) / 8) as usize;
        let mut buf = vec![0u8; bytes];
        r.read_exact(&mut buf)?;
        let mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        let raw = self.bytes_to_u64(&buf) & mask;
        let val: i64 = match bt {
            BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64 if n > 0 => {
                let sign_bit = 1i64 << (n as i64 - 1);
                if (raw as i64) >= sign_bit {
                    (raw as i64) - (1i64 << n as i64)
                } else {
                    raw as i64
                }
            }
            _ => raw as i64,
        };
        Ok(match bt {
            BaseType::U8 => Value::U8(val as u8),
            BaseType::U16 => Value::U16(val as u16),
            BaseType::U32 => Value::U32(val as u32),
            BaseType::U64 => Value::U64(val as u64),
            BaseType::I8 => Value::I8(val as i8),
            BaseType::I16 => Value::I16(val as i16),
            BaseType::I32 => Value::I32(val as i32),
            BaseType::I64 => Value::I64(val),
            _ => Value::U64(raw),
        })
    }

    fn encode_sized_int(&self, w: &mut Vec<u8>, bt: &BaseType, n: u64, v: &Value) -> Result<(), CodecError> {
        let bytes = ((n + 7) / 8) as usize;
        let mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        let raw = match bt {
            BaseType::I8 | BaseType::I16 | BaseType::I32 | BaseType::I64 => {
                let val = v.as_i64().unwrap_or(0);
                (val as u64) & mask
            }
            _ => v.as_u64().unwrap_or(0) & mask,
        };
        let buf = self.u64_to_bytes(raw, bytes);
        w.write_all(&buf)?;
        Ok(())
    }

    fn read_u8(&self, r: &mut Cursor<&[u8]>) -> Result<u8, CodecError> {
        Ok(r.read_u8()?)
    }
    fn read_u16(&self, r: &mut Cursor<&[u8]>) -> Result<u16, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_u16::<BigEndian>()?,
            Endianness::Little => r.read_u16::<LittleEndian>()?,
        })
    }
    fn read_u32(&self, r: &mut Cursor<&[u8]>) -> Result<u32, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_u32::<BigEndian>()?,
            Endianness::Little => r.read_u32::<LittleEndian>()?,
        })
    }
    fn read_u64(&self, r: &mut Cursor<&[u8]>) -> Result<u64, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_u64::<BigEndian>()?,
            Endianness::Little => r.read_u64::<LittleEndian>()?,
        })
    }
    fn read_i16(&self, r: &mut Cursor<&[u8]>) -> Result<i16, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_i16::<BigEndian>()?,
            Endianness::Little => r.read_i16::<LittleEndian>()?,
        })
    }
    fn read_i32(&self, r: &mut Cursor<&[u8]>) -> Result<i32, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_i32::<BigEndian>()?,
            Endianness::Little => r.read_i32::<LittleEndian>()?,
        })
    }
    fn read_i64(&self, r: &mut Cursor<&[u8]>) -> Result<i64, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_i64::<BigEndian>()?,
            Endianness::Little => r.read_i64::<LittleEndian>()?,
        })
    }
    fn read_f32(&self, r: &mut Cursor<&[u8]>) -> Result<f32, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_f32::<BigEndian>()?,
            Endianness::Little => r.read_f32::<LittleEndian>()?,
        })
    }
    fn read_f64(&self, r: &mut Cursor<&[u8]>) -> Result<f64, CodecError> {
        Ok(match self.endianness {
            Endianness::Big => r.read_f64::<BigEndian>()?,
            Endianness::Little => r.read_f64::<LittleEndian>()?,
        })
    }

    fn write_u8(&self, w: &mut Vec<u8>, v: u8) -> Result<(), CodecError> {
        w.write_u8(v)?;
        Ok(())
    }
    fn write_u16(&self, w: &mut Vec<u8>, v: u16) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_u16::<BigEndian>(v)?,
            Endianness::Little => w.write_u16::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_u32(&self, w: &mut Vec<u8>, v: u32) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_u32::<BigEndian>(v)?,
            Endianness::Little => w.write_u32::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_u64(&self, w: &mut Vec<u8>, v: u64) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_u64::<BigEndian>(v)?,
            Endianness::Little => w.write_u64::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_i16(&self, w: &mut Vec<u8>, v: i16) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_i16::<BigEndian>(v)?,
            Endianness::Little => w.write_i16::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_i32(&self, w: &mut Vec<u8>, v: i32) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_i32::<BigEndian>(v)?,
            Endianness::Little => w.write_i32::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_i64(&self, w: &mut Vec<u8>, v: i64) -> Result<(), CodecError> {
        match self.endianness {
            Endianness::Big => w.write_i64::<BigEndian>(v)?,
            Endianness::Little => w.write_i64::<LittleEndian>(v)?,
        }
        Ok(())
    }
    fn write_f32(&self, w: &mut Vec<u8>, v: f32) {
        let _ = match self.endianness {
            Endianness::Big => w.write_f32::<BigEndian>(v),
            Endianness::Little => w.write_f32::<LittleEndian>(v),
        };
    }
    fn write_f64(&self, w: &mut Vec<u8>, v: f64) {
        let _ = match self.endianness {
            Endianness::Big => w.write_f64::<BigEndian>(v),
            Endianness::Little => w.write_f64::<LittleEndian>(v),
        };
    }

    fn bytes_to_u64(&self, buf: &[u8]) -> u64 {
        match self.endianness {
            Endianness::Big => match buf.len() {
                1 => buf[0] as u64,
                2 => BigEndian::read_u16(buf) as u64,
                4 => BigEndian::read_u32(buf) as u64,
                8 => BigEndian::read_u64(buf),
                _ => {
                    let mut b = [0u8; 8];
                    let start = 8 - buf.len();
                    b[start..].copy_from_slice(buf);
                    BigEndian::read_u64(&b)
                }
            },
            Endianness::Little => match buf.len() {
                1 => buf[0] as u64,
                2 => LittleEndian::read_u16(buf) as u64,
                4 => LittleEndian::read_u32(buf) as u64,
                8 => LittleEndian::read_u64(buf),
                _ => {
                    let mut b = [0u8; 8];
                    b[..buf.len()].copy_from_slice(buf);
                    LittleEndian::read_u64(&b)
                }
            },
        }
    }

    fn u64_to_bytes(&self, v: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        match self.endianness {
            Endianness::Big => {
                match len {
                    1 => buf[0] = v as u8,
                    2 => BigEndian::write_u16(&mut buf, v as u16),
                    4 => BigEndian::write_u32(&mut buf, v as u32),
                    8 => BigEndian::write_u64(&mut buf, v),
                    _ => {
                        let mut b = [0u8; 8];
                        BigEndian::write_u64(&mut b, v);
                        buf.copy_from_slice(&b[8 - len..]);
                    }
                }
            }
            Endianness::Little => {
                match len {
                    1 => buf[0] = v as u8,
                    2 => LittleEndian::write_u16(&mut buf, v as u16),
                    4 => LittleEndian::write_u32(&mut buf, v as u32),
                    8 => LittleEndian::write_u64(&mut buf, v),
                    _ => {
                        let mut b = [0u8; 8];
                        LittleEndian::write_u64(&mut b, v);
                        buf.copy_from_slice(&b[..len]);
                    }
                }
            }
        }
        buf
    }
}

/// Presence state for optional fields: fixed bitmap (presence_bits) or variable-length FSPEC (fspec).
#[derive(Clone)]
enum PresenceState {
    Bitmap { value: u64, bit_index: usize },
    Fspec { bytes: Vec<u8>, bit_index: usize },
}

/// Bit-level packing state for decoding (`bitfield(n)` / `padding_bits(n)`).
/// Bits are consumed LSB-first within each byte (bit 0 = least significant bit),
/// consistent with the FSPEC bit numbering used elsewhere in this crate.
#[derive(Clone, Copy, Debug)]
struct BitReadState {
    cur: u8,
    next_bit: u8, // 0..=8, where 8 means "need new byte"
}

impl Default for BitReadState {
    fn default() -> Self {
        BitReadState { cur: 0, next_bit: 8 }
    }
}

impl BitReadState {
    fn is_aligned(&self) -> bool {
        self.next_bit == 8
    }
}

/// Bit-level packing state for encoding (`bitfield(n)` / `padding_bits(n)`).
/// Bits are written LSB-first within each byte.
#[derive(Clone, Copy, Debug)]
struct BitWriteState {
    cur: u8,
    next_bit: u8, // 0..=8, where 0 means "byte boundary / empty"
}

impl Default for BitWriteState {
    fn default() -> Self {
        BitWriteState { cur: 0, next_bit: 0 }
    }
}

impl BitWriteState {
    fn is_aligned(&self) -> bool {
        self.next_bit == 0
    }
}

#[derive(Default)]
struct DecodeContext {
    values: HashMap<String, Value>,
    /// When decoding: after presence_bits(n) or fspec, following optionals use bits from this.
    presence: Option<PresenceState>,
    bit_read: BitReadState,
}

impl DecodeContext {
    fn get(&self, k: &str) -> Option<&Value> {
        self.values.get(k)
    }
    fn set(&mut self, k: String, v: Value) {
        self.values.insert(k, v);
    }
}

struct EncodeContext {
    values: HashMap<String, Value>,
    bit_write: BitWriteState,
}

impl EncodeContext {
    fn from_values(m: &HashMap<String, Value>) -> Self {
        EncodeContext { values: m.clone(), bit_write: BitWriteState::default() }
    }
    fn get(&self, k: &str) -> Option<&Value> {
        self.values.get(k)
    }
}
