//! Abstract Syntax Tree for the Protocol Encoding DSL.

use std::collections::HashMap;

/// Root protocol definition: transport, payload (messages after transport), type definitions (abstract), enums, messages, structs (encoding).
#[derive(Debug, Clone)]
pub struct Protocol {
    pub transport: Option<TransportSection>,
    /// Which messages can follow the transport and how to select message type from transport fields.
    pub payload: Option<PayloadSection>,
    /// Abstract data model definitions (ASN.1-like). Describe WHAT the data is.
    pub type_defs: Vec<TypeDefSection>,
    /// Enumerated types: named constants (name = value). Can be referenced from type definitions.
    pub enum_defs: Vec<EnumSection>,
    /// Encoding: message-level wire format (ECN-like). Describe HOW the data is serialized.
    pub messages: Vec<MessageSection>,
    /// Encoding: struct-level wire format (ECN-like). Describe HOW the data is serialized.
    pub structs: Vec<StructSection>,
}

// ==================== Abstract data model (ASN.1-like) ====================

/// Abstract type definition: describes the data model independent of encoding.
#[derive(Debug, Clone)]
pub struct TypeDefSection {
    pub name: String,
    pub fields: Vec<TypeDefField>,
}

/// A field in an abstract type definition.
#[derive(Debug, Clone)]
pub struct TypeDefField {
    pub name: String,
    pub abstract_type: AbstractType,
    /// True if the field is optional (marked with `?`).
    pub optional: bool,
    /// Value constraint (e.g. [0..255]).
    pub constraint: Option<Constraint>,
    /// Resolution/unit per spec (e.g. "1/256 NM").
    pub quantum: Option<String>,
}

/// Abstract type (ASN.1-like): describes the logical type, not the wire encoding.
#[derive(Debug, Clone)]
pub enum AbstractType {
    /// Integer value (any size/sign — encoding decides the wire format).
    Integer,
    /// Boolean value.
    Boolean,
    /// Raw byte sequence (variable length).
    Octets,
    /// Floating-point value.
    Real,
    /// Reference to another defined type.
    TypeRef(String),
    /// Ordered sequence of values of a given type (list).
    SequenceOf(Box<AbstractType>),
}

/// Enumeration: named constants. Referenced from type definitions (e.g. Message Type).
#[derive(Debug, Clone)]
pub struct EnumSection {
    pub name: String,
    /// Variant name and its integer/hex value (e.g. NorthMarker=1, SectorCrossing=2).
    pub variants: Vec<(String, Literal)>,
}

// ==================== Payload & transport ====================

/// Declares which message types can appear after the transport and how to select the message from transport fields.
#[derive(Debug, Clone)]
pub struct PayloadSection {
    /// Message type names that can follow the transport.
    pub messages: Vec<String>,
    /// Optional: which transport field selects the message type and the value→message mapping.
    pub selector: Option<PayloadSelector>,
    /// When true, the payload is a list of records (zero or more messages of the selected type per data block).
    pub repeated: bool,
}

#[derive(Debug, Clone)]
pub struct PayloadSelector {
    /// Transport field name (e.g. "category") whose value selects the message type.
    pub transport_field: String,
    /// (value, message_name, is_list) triples: when transport_field equals value, use this message.
    /// `is_list` is true when the DSL uses `list<MessageName>` (one or more records of that type).
    pub value_to_message: Vec<(Literal, String, bool)>,
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
    /// Resolution/unit per spec (e.g. "1/256 NM").
    pub quantum: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TransportTypeSpec {
    Base(BaseType),
    SizedInt(BaseType, u64),
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
    /// Resolution/unit per spec (e.g. "1/256 NM").
    pub quantum: Option<String>,
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
    /// Resolution/unit per spec (e.g. "1/256 NM").
    pub quantum: Option<String>,
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
    /// Integer stored in n bits; use u16(14), i16(10) etc. when the value is an integer (not a bit mask).
    SizedInt(BaseType, u64),
    Padding(u64),
    Reserved(u64),
    Bitfield(u64),
    LengthOf(String),
    CountOf(String),
    /// ASN.1-style presence bitmap: n bytes (1, 2, or 4). Following optional fields use bits 0, 1, 2, ...
    PresenceBits(u64),
    /// FSPEC: fspec(N, n) = up to N bits. n=8 => 7 presence + 1 FX per byte; n=0 => no blocking (N consecutive presence bits).
    /// Mapping lists (logical_index, field_name); no FX in mapping.
    FspecWithMapping { max_bits: u32, bits_per_block: u32, mapping: Vec<(u32, String)> },
    /// Spare/reserved bits (zero on encode).
    PaddingBits(u64),
    StructRef(String),
    Array(Box<TypeSpec>, ArrayLen),
    List(Box<TypeSpec>),
    /// List preceded by a 1-byte repetition factor (REP) - common in ASTERIX.
    RepList(Box<TypeSpec>),
    /// ASTERIX variable-length octets with FX extension: read bytes until byte & 0x80 == 0 (7 bits payload per byte).
    OctetsFx,
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

/// Range constraint: one or more intervals; value must be in at least one.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Intervals (min, max) inclusive; value valid if in any interval.
    Range(Vec<(i64, i64)>),
    Enum(Vec<Literal>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Bool(bool),
    Hex(u64),
    String(String),
}

fn build_fspec_mappings_messages(messages: &[MessageSection]) -> Result<HashMap<String, FspecMapping>, String> {
    let mut out = HashMap::new();
    for msg in messages {
        let mut i = 0;
        while i < msg.fields.len() {
            let is_fspec = matches!(msg.fields[i].type_spec, TypeSpec::FspecWithMapping { .. });
            if is_fspec {
                let fspec_field = msg.fields[i].name.clone();
                let explicit_mapping = match &msg.fields[i].type_spec {
                    TypeSpec::FspecWithMapping { mapping: m, .. } => Some(m.clone()),
                    _ => None,
                };
                let mut optional_fields = Vec::new();
                i += 1;
                while i < msg.fields.len() {
                    if matches!(msg.fields[i].type_spec, TypeSpec::Optional(_)) {
                        optional_fields.push(msg.fields[i].name.clone());
                        i += 1;
                    } else {
                        break;
                    }
                }
                let bit_to_field = if let Some(m) = &explicit_mapping {
                    let mapping_names: Vec<String> = m.iter().map(|(_, n)| n.clone()).collect();
                    if mapping_names != optional_fields {
                        return Err(format!(
                            "message {}: fspec mapping does not match optional fields (mapping: {:?}, optional fields: {:?})",
                            msg.name, mapping_names, optional_fields
                        ));
                    }
                    m.clone()
                } else {
                    optional_fields.iter().enumerate().map(|(b, name)| (b as u32, name.clone())).collect()
                };
                out.insert(msg.name.clone(), FspecMapping { fspec_field, optional_fields, bit_to_field });
                break;
            }
            i += 1;
        }
    }
    Ok(out)
}

fn build_fspec_mappings_structs(structs: &[StructSection]) -> Result<HashMap<String, FspecMapping>, String> {
    let mut out = HashMap::new();
    for s in structs {
        let mut i = 0;
        while i < s.fields.len() {
            let is_fspec = matches!(s.fields[i].type_spec, TypeSpec::FspecWithMapping { .. });
            if is_fspec {
                let fspec_field = s.fields[i].name.clone();
                let explicit_mapping = match &s.fields[i].type_spec {
                    TypeSpec::FspecWithMapping { mapping: m, .. } => Some(m.clone()),
                    _ => None,
                };
                let mut optional_fields = Vec::new();
                i += 1;
                while i < s.fields.len() {
                    if matches!(s.fields[i].type_spec, TypeSpec::Optional(_)) {
                        optional_fields.push(s.fields[i].name.clone());
                        i += 1;
                    } else {
                        break;
                    }
                }
                let bit_to_field = if let Some(m) = &explicit_mapping {
                    let mapping_names: Vec<String> = m.iter().map(|(_, n)| n.clone()).collect();
                    if mapping_names != optional_fields {
                        return Err(format!(
                            "struct {}: fspec mapping does not match optional fields (mapping: {:?}, optional fields: {:?})",
                            s.name, mapping_names, optional_fields
                        ));
                    }
                    m.clone()
                } else {
                    optional_fields.iter().enumerate().map(|(b, name)| (b as u32, name.clone())).collect()
                };
                out.insert(s.name.clone(), FspecMapping { fspec_field, optional_fields, bit_to_field });
                break;
            }
            i += 1;
        }
    }
    Ok(out)
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

/// Mapping from an FSPEC field to the optional fields it governs (bit 0 = first, bit 1 = second, ...).
#[derive(Debug, Clone)]
pub struct FspecMapping {
    /// Name of the field with type `fspec`.
    pub fspec_field: String,
    /// Names of the optional fields that follow, in FSPEC bit order.
    pub optional_fields: Vec<String>,
    /// Explicit mapping: FSPEC bit position → field name. Bit 0 = first optional, bit 1 = second, etc.
    pub bit_to_field: Vec<(u32, String)>,
}

impl FspecMapping {
    /// Field name for a given FSPEC bit position. Returns None if bit is out of range.
    pub fn field_for_bit(&self, bit: u32) -> Option<&str> {
        self.bit_to_field.iter().find(|(b, _)| *b == bit).map(|(_, name)| name.as_str())
    }

    /// FSPEC bit position for a given field name. Returns None if the field is not in this FSPEC.
    pub fn bit_for_field(&self, field_name: &str) -> Option<u32> {
        self.bit_to_field.iter().find(|(_, name)| name.as_str() == field_name).map(|(b, _)| *b)
    }
}

/// Resolved protocol: structs and messages by name for codec, type definitions by name for validation.
#[derive(Debug, Clone)]
pub struct ResolvedProtocol {
    pub protocol: Protocol,
    /// Abstract type definitions by name (ASN.1-like data model).
    pub type_defs_by_name: HashMap<String, usize>,
    pub structs_by_name: HashMap<String, usize>,
    pub messages_by_name: HashMap<String, usize>,
    /// Message name -> FSPEC field and the optional fields it governs.
    pub message_fspec: HashMap<String, FspecMapping>,
    /// Struct name -> FSPEC field and the optional fields it governs.
    pub struct_fspec: HashMap<String, FspecMapping>,
}

impl ResolvedProtocol {
    pub fn resolve(protocol: Protocol) -> Result<Self, String> {
        let mut type_defs_by_name = HashMap::new();
        let mut structs_by_name = HashMap::new();
        let mut messages_by_name = HashMap::new();
        for (i, t) in protocol.type_defs.iter().enumerate() {
            if type_defs_by_name.insert(t.name.clone(), i).is_some() {
                return Err(format!("Duplicate type name: {}", t.name));
            }
        }
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
        if let Some(ref payload) = protocol.payload {
            for name in &payload.messages {
                if !messages_by_name.contains_key(name) {
                    return Err(format!("payload message '{}' is not a defined message", name));
                }
            }
            if let Some(ref sel) = payload.selector {
                for (_, msg_name, _) in &sel.value_to_message {
                    if !messages_by_name.contains_key(msg_name) {
                        return Err(format!("payload selector message '{}' is not a defined message", msg_name));
                    }
                }
            }
        }
        let message_fspec = build_fspec_mappings_messages(&protocol.messages)?;
        let struct_fspec = build_fspec_mappings_structs(&protocol.structs)?;
        Ok(ResolvedProtocol {
            protocol,
            type_defs_by_name,
            structs_by_name,
            messages_by_name,
            message_fspec,
            struct_fspec,
        })
    }

    /// Mapping from FSPEC field to optional fields for a message. None if the message has no fspec field.
    pub fn fspec_mapping_message(&self, message_name: &str) -> Option<&FspecMapping> {
        self.message_fspec.get(message_name)
    }

    /// Mapping from FSPEC field to optional fields for a struct. None if the struct has no fspec field.
    pub fn fspec_mapping_struct(&self, struct_name: &str) -> Option<&FspecMapping> {
        self.struct_fspec.get(struct_name)
    }

    /// Message type names that can follow the transport. Empty if no payload section.
    pub fn messages_after_transport(&self) -> &[String] {
        self.protocol
            .payload
            .as_ref()
            .map(|p| p.messages.as_slice())
            .unwrap_or(&[])
    }

    /// Resolve which message type to use from decoded transport values using the payload selector.
    /// Returns None if no payload/selector, or if the selector field is missing or value has no mapping.
    pub fn message_for_transport_values(&self, transport_values: &std::collections::HashMap<String, crate::value::Value>) -> Option<&str> {
        let payload = self.protocol.payload.as_ref()?;
        let sel = payload.selector.as_ref()?;
        let v = transport_values.get(&sel.transport_field)?;
        let n = v.as_i64()?;
        for (lit, msg_name, _) in &sel.value_to_message {
            if lit.as_i64() == Some(n) {
                return Some(msg_name);
            }
        }
        None
    }

    /// When true, the payload after transport is a list of records (zero or more messages of the selected type per block).
    /// True if the `repeated;` directive is present, or if any selector mapping uses `list<MessageName>`.
    pub fn payload_repeated(&self) -> bool {
        self.protocol.payload.as_ref().map(|p| {
            p.repeated || p.selector.as_ref().map(|s| s.value_to_message.iter().any(|(_, _, is_list)| *is_list)).unwrap_or(false)
        }).unwrap_or(false)
    }

    /// Check if the payload for a specific transport value is a list (uses `list<MessageName>` in selector).
    pub fn payload_is_list_for_transport(&self, transport_values: &std::collections::HashMap<String, crate::value::Value>) -> bool {
        if let Some(payload) = &self.protocol.payload {
            if payload.repeated {
                return true;
            }
            if let Some(sel) = &payload.selector {
                if let Some(v) = transport_values.get(&sel.transport_field) {
                    if let Some(n) = v.as_i64() {
                        for (lit, _, is_list) in &sel.value_to_message {
                            if lit.as_i64() == Some(n) {
                                return *is_list;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Get an abstract type definition by name.
    pub fn get_type_def(&self, name: &str) -> Option<&TypeDefSection> {
        self.type_defs_by_name
            .get(name)
            .map(|&i| &self.protocol.type_defs[i])
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
