//! Runtime values for encoding/decoding (codec representation).

use std::collections::HashMap;

/// A single decoded value (field or compound).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Bool(bool),
    Float(f32),
    Double(f64),
    Bytes(Vec<u8>),
    Struct(HashMap<String, Value>),
    List(Vec<Value>),
    /// Padding/reserved: must be zero on encode.
    Padding,
    Reserved,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U8(x) => Some(*x as u64),
            Value::U16(x) => Some(*x as u64),
            Value::U32(x) => Some(*x as u64),
            Value::U64(x) => Some(*x),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::I8(x) => Some(*x as i64),
            Value::I16(x) => Some(*x as i64),
            Value::I32(x) => Some(*x as i64),
            Value::I64(x) => Some(*x),
            Value::U8(x) => Some(*x as i64),
            Value::U16(x) => Some(*x as i64),
            Value::U32(x) => Some(*x as i64),
            Value::U64(x) => Some(*x as i64),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&HashMap<String, Value>> {
        match self {
            Value::Struct(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_f32(&self) -> Option<f32> {
        match self {
            Value::Float(x) => Some(*x),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(x) => Some(*x),
            _ => None,
        }
    }
}
