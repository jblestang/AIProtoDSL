//! Abstract Syntax Tree for the Protocol Encoding DSL.

use std::collections::HashMap;

/// Root protocol definition: transport, messages, structs.
#[derive(Debug, Clone)]
pub struct Protocol {
    pub transport: Option<TransportSection>,
    pub messages: Vec<MessageSection>,
    pub structs: Vec<StructSection>,
}

#[derive(Debug, Clone)]
pub struct TransportSection {
    pub fields: Vec<TransportField>,
}

#[derive(Debug, Clone)]
pub struct TransportField {
    pub name: String,
    pub type_spec: TransportTypeSpec,
    pub default: Option<Literal>,
    pub constraint: Option<Constraint>,
}

#[derive(Debug, Clone)]
pub enum TransportTypeSpec {
    Base(BaseType),
    Padding(u64),
    Reserved(u64),
    Bitfield(u64),
    Magic(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct MessageSection {
    pub name: String,
    pub fields: Vec<MessageField>,
}

#[derive(Debug, Clone)]
pub struct MessageField {
    pub name: String,
    pub type_spec: TypeSpec,
    pub default: Option<Literal>,
    pub constraint: Option<Constraint>,
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone)]
pub struct StructSection {
    pub name: String,
    pub fields: Vec<StructField>,
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub type_spec: TypeSpec,
    pub default: Option<Literal>,
    pub constraint: Option<Constraint>,
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub value: Literal,
}

/// Field type specification.
#[derive(Debug, Clone)]
pub enum TypeSpec {
    Base(BaseType),
    Padding(u64),
    Reserved(u64),
    Bitfield(u64),
    LengthOf(String),
    CountOf(String),
    /// ASN.1-style presence bitmap: n bytes (1, 2, or 4). Following optional fields use bits 0, 1, 2, ...
    PresenceBits(u64),
    /// ASTERIX FSPEC: variable-length bytes until FX=0; 7 bits per byte; following optionals use bits 0,1,2,...
    Fspec,
    /// Spare/reserved bits (zero on encode).
    PaddingBits(u64),
    StructRef(String),
    Array(Box<TypeSpec>, ArrayLen),
    List(Box<TypeSpec>),
    Optional(Box<TypeSpec>),
}

#[derive(Debug, Clone)]
pub enum ArrayLen {
    Constant(u64),
    FieldRef(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BaseType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bool,
    Float,
    Double,
}

#[derive(Debug, Clone)]
pub enum Constraint {
    Range { min: i64, max: i64 },
    Enum(Vec<Literal>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Bool(bool),
    Hex(u64),
    String(String),
}

impl Literal {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Literal::Int(i) => (*i).try_into().ok(),
            Literal::Hex(h) => Some(*h),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Literal::Int(i) => Some(*i),
            Literal::Hex(h) => (*h as i64).into(),
            _ => None,
        }
    }
}

/// Resolved protocol: structs and messages by name for codec.
#[derive(Debug, Clone)]
pub struct ResolvedProtocol {
    pub protocol: Protocol,
    pub structs_by_name: HashMap<String, usize>,
    pub messages_by_name: HashMap<String, usize>,
}

impl ResolvedProtocol {
    pub fn resolve(protocol: Protocol) -> Result<Self, String> {
        let mut structs_by_name = HashMap::new();
        let mut messages_by_name = HashMap::new();
        for (i, s) in protocol.structs.iter().enumerate() {
            if structs_by_name.insert(s.name.clone(), i).is_some() {
                return Err(format!("Duplicate struct name: {}", s.name));
            }
        }
        for (i, m) in protocol.messages.iter().enumerate() {
            if messages_by_name.insert(m.name.clone(), i).is_some() {
                return Err(format!("Duplicate message name: {}", m.name));
            }
        }
        Ok(ResolvedProtocol {
            protocol,
            structs_by_name,
            messages_by_name,
        })
    }

    pub fn get_struct(&self, name: &str) -> Option<&StructSection> {
        self.structs_by_name
            .get(name)
            .map(|&i| &self.protocol.structs[i])
    }

    pub fn get_message(&self, name: &str) -> Option<&MessageSection> {
        self.messages_by_name
            .get(name)
            .map(|&i| &self.protocol.messages[i])
    }
}
