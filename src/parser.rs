//! Parse DSL source into AST using PEST.

use crate::ast::*;
use pest::Parser;
use pest_derive::Parser as PestParser;

#[derive(PestParser)]
#[grammar = "grammar.pest"]
struct ProtocolParser;

/// Parse protocol source into AST.
pub fn parse(source: &str) -> Result<Protocol, String> {
    let pairs = ProtocolParser::parse(Rule::protocol, source)
        .map_err(|e| format!("Parse error: {}", e))?;
    let pair = pairs.into_iter().next().ok_or("Empty parse")?;
    build_protocol(pair)
}

fn build_protocol(pair: pest::iterators::Pair<Rule>) -> Result<Protocol, String> {
    let mut transport = None;
    let mut payload = None;
    let mut type_defs = Vec::new();
    let mut enum_defs = Vec::new();
    let mut messages = Vec::new();
    let mut structs = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::transport_section => transport = Some(build_transport(inner)?),
            Rule::payload_section => payload = Some(build_payload(inner)?),
            Rule::type_section => type_defs.push(build_type_def_section(inner)?),
            Rule::enum_section => enum_defs.push(build_enum_section(inner)?),
            Rule::message_section => messages.push(build_message(inner)?),
            Rule::struct_section => structs.push(build_struct(inner)?),
            _ => {}
        }
    }

    Ok(Protocol {
        transport,
        payload,
        type_defs,
        enum_defs,
        messages,
        structs,
    })
}

fn build_enum_section(pair: pest::iterators::Pair<Rule>) -> Result<EnumSection, String> {
    let mut name = String::new();
    let mut variants = Vec::new();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => {
                if name.is_empty() {
                    name = inner.as_str().to_string();
                } else {
                    return Err("enum_variant: ident".to_string());
                }
            }
            Rule::enum_variant => {
                let mut it = inner.into_inner();
                let name_pair = it.next().ok_or("enum variant: name")?;
                let var_name = name_pair.as_str().to_string();
                let lit_pair = it.next().ok_or("enum variant: value")?;
                let literal = parse_literal(lit_pair.as_str());
                variants.push((var_name, literal));
            }
            _ => {}
        }
    }
    if name.is_empty() {
        return Err("enum section: missing name".to_string());
    }
    Ok(EnumSection { name, variants })
}

fn build_payload(pair: pest::iterators::Pair<Rule>) -> Result<PayloadSection, String> {
    let mut messages = Vec::new();
    let mut selector = None;
    let mut repeated = false;
    for payload_field in pair.into_inner() {
        if payload_field.as_rule() != Rule::payload_field {
            continue;
        }
        let inner = payload_field.into_inner().next().ok_or("empty payload_field")?;
        match inner.as_rule() {
            Rule::messages_list => {
                for part in inner.into_inner() {
                    if part.as_rule() == Rule::ident {
                        messages.push(part.as_str().to_string());
                    } else {
                        for sub in part.into_inner() {
                            if sub.as_rule() == Rule::ident {
                                messages.push(sub.as_str().to_string());
                            }
                        }
                    }
                }
            }
            Rule::selector_spec => selector = Some(build_selector_spec(inner)?),
            Rule::repeated_spec => repeated = true,
            _ => {}
        }
    }
    if messages.is_empty() {
        return Err("payload must list at least one message".to_string());
    }
    Ok(PayloadSection { messages, selector, repeated })
}

fn build_selector_spec(pair: pest::iterators::Pair<Rule>) -> Result<PayloadSelector, String> {
    let mut inner = pair.into_inner();
    let transport_field = inner
        .find(|p| p.as_rule() == Rule::ident)
        .map(|p| p.as_str().to_string())
        .ok_or("selector: missing transport field")?;
    let mut value_to_message = Vec::new();
    for part in inner {
        if part.as_rule() == Rule::selector_mapping {
            let mut it = part.into_inner();
            let lit_pair = it.next().ok_or("selector mapping: literal")?;
            let msg_type_pair = it.next().ok_or("selector mapping: message type")?;
            let literal = parse_literal(lit_pair.as_str());
            // selector_msg_type: either selector_list_type (list<ident>) or plain ident
            let (message_name, is_list) = if msg_type_pair.as_rule() == Rule::selector_msg_type {
                let first = msg_type_pair.into_inner().next().ok_or("selector msg type")?;
                match first.as_rule() {
                    Rule::selector_list_type => {
                        let ident = first.into_inner().next().ok_or("list<ident>: missing ident")?;
                        (ident.as_str().to_string(), true)
                    }
                    Rule::ident => {
                        (first.as_str().to_string(), false)
                    }
                    _ => return Err(format!("unexpected selector_msg_type child: {:?}", first.as_rule())),
                }
            } else {
                (msg_type_pair.as_str().to_string(), false)
            };
            value_to_message.push((literal, message_name, is_list));
        }
    }
    if value_to_message.is_empty() {
        return Err("selector must have at least one value: MessageName mapping".to_string());
    }
    Ok(PayloadSelector {
        transport_field,
        value_to_message,
    })
}

// ==================== Abstract data model (type sections) ====================

fn build_type_def_section(pair: pest::iterators::Pair<Rule>) -> Result<TypeDefSection, String> {
    let mut name = String::new();
    let mut fields = Vec::new();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => name = inner.as_str().to_string(),
            Rule::type_def_field => fields.push(build_type_def_field(inner)?),
            _ => {}
        }
    }
    Ok(TypeDefSection { name, fields })
}

fn build_type_def_field(pair: pest::iterators::Pair<Rule>) -> Result<TypeDefField, String> {
    let mut name = String::new();
    let mut abstract_type = None;
    let mut optional = false;
    let mut constraint = None;
    let mut quantum = None;
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => {
                if name.is_empty() {
                    name = inner.as_str().to_string();
                }
            }
            Rule::abstract_type_spec => abstract_type = Some(build_abstract_type(inner)?),
            Rule::type_optional => optional = true,
            Rule::constraint => constraint = Some(build_constraint(inner)?),
            Rule::quantum_spec => quantum = Some(parse_quantum_string(inner)?),
            _ => {}
        }
    }
    Ok(TypeDefField {
        name,
        abstract_type: abstract_type.ok_or("Missing abstract type in type field")?,
        optional,
        constraint,
        quantum,
    })
}

fn build_abstract_type(pair: pest::iterators::Pair<Rule>) -> Result<AbstractType, String> {
    let inner = pair.into_inner().next().ok_or("Empty abstract_type_spec")?;
    match inner.as_rule() {
        Rule::abstract_base_type => {
            match inner.as_str() {
                "integer" => Ok(AbstractType::Integer),
                "boolean" => Ok(AbstractType::Boolean),
                "octets" => Ok(AbstractType::Octets),
                "real" => Ok(AbstractType::Real),
                other => Err(format!("Unknown abstract base type: {}", other)),
            }
        }
        Rule::abstract_seq_type => {
            let inner_type = inner.into_inner()
                .find(|p| p.as_rule() == Rule::abstract_type_spec)
                .ok_or("sequence of: missing element type")?;
            Ok(AbstractType::SequenceOf(Box::new(build_abstract_type(inner_type)?)))
        }
        Rule::ident => Ok(AbstractType::TypeRef(inner.as_str().to_string())),
        _ => Err(format!("Unhandled abstract type rule: {:?}", inner.as_rule())),
    }
}

// ==================== Encoding (transport, message, struct) ====================

fn build_transport(pair: pest::iterators::Pair<Rule>) -> Result<TransportSection, String> {
    let mut fields = Vec::new();
    for inner in pair.into_inner() {
        if matches!(inner.as_rule(), Rule::transport_field) {
            fields.push(build_transport_field(inner)?);
        }
    }
    Ok(TransportSection { fields })
}

fn build_transport_field(
    pair: pest::iterators::Pair<Rule>,
) -> Result<TransportField, String> {
    let mut name = String::new();
    let mut type_spec = None;
    let mut default = None;
    let mut constraint = None;
    let mut quantum = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => name = inner.as_str().to_string(),
            Rule::transport_type_spec => type_spec = Some(build_transport_type_spec(inner)?),
            Rule::literal => default = Some(parse_literal(inner.as_str())),
            Rule::constraint => constraint = Some(build_constraint(inner)?),
            Rule::quantum_spec => quantum = Some(parse_quantum_string(inner)?),
            _ => {}
        }
    }

    Ok(TransportField {
        name,
        type_spec: type_spec.ok_or("Missing type in transport field")?,
        default,
        constraint,
        quantum,
    })
}

fn build_transport_type_spec(
    pair: pest::iterators::Pair<Rule>,
) -> Result<TransportTypeSpec, String> {
    let inner = pair.into_inner().next().ok_or("Empty transport type")?;
    match inner.as_rule() {
        Rule::base_type => Ok(TransportTypeSpec::Base(parse_base_type(inner.as_str())?)),
        Rule::sized_int_type => {
            let mut it = inner.into_inner();
            let base = it.next().ok_or("sized_int base")?;
            let n = it.next().and_then(|p| p.as_str().parse().ok()).ok_or("sized_int(n) needs number")?;
            let bt = parse_base_type(base.as_str())?;
            Ok(TransportTypeSpec::SizedInt(bt, n))
        }
        Rule::padding_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("padding(n) needs number")?;
            Ok(TransportTypeSpec::Padding(n))
        }
        Rule::reserved_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("reserved(n) needs number")?;
            Ok(TransportTypeSpec::Reserved(n))
        }
        Rule::bitfield_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("bitfield(n) needs number")?;
            Ok(TransportTypeSpec::Bitfield(n))
        }
        Rule::magic_type => {
            let rest = inner.into_inner().next().ok_or("magic() needs literal")?;
            let bytes = parse_literal_bytes(rest.as_str())?;
            Ok(TransportTypeSpec::Magic(bytes))
        }
        _ => Err("Unknown transport type".to_string()),
    }
}

fn build_message(pair: pest::iterators::Pair<Rule>) -> Result<MessageSection, String> {
    let mut name = String::new();
    let mut fields = Vec::new();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => name = inner.as_str().to_string(),
            Rule::message_field => fields.push(build_message_field(inner)?),
            _ => {}
        }
    }
    Ok(MessageSection { name, fields })
}

fn build_message_field(pair: pest::iterators::Pair<Rule>) -> Result<MessageField, String> {
    build_generic_field(pair, build_type_spec).map(|(name, type_spec, default, constraint, condition, quantum)| MessageField {
        name,
        type_spec,
        default,
        constraint,
        condition,
        quantum,
        saturating: false,
    })
}

fn build_struct(pair: pest::iterators::Pair<Rule>) -> Result<StructSection, String> {
    let mut name = String::new();
    let mut fields = Vec::new();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => name = inner.as_str().to_string(),
            Rule::struct_field => fields.push(build_struct_field(inner)?),
            _ => {}
        }
    }
    Ok(StructSection { name, fields })
}

fn build_struct_field(pair: pest::iterators::Pair<Rule>) -> Result<StructField, String> {
    build_generic_field(pair, build_type_spec).map(|(name, type_spec, default, constraint, condition, quantum)| StructField {
        name,
        type_spec,
        default,
        constraint,
        condition,
        quantum,
    })
}

fn build_generic_field<F>(
    pair: pest::iterators::Pair<Rule>,
    type_builder: F,
) -> Result<(String, TypeSpec, Option<Literal>, Option<Constraint>, Option<Condition>, Option<String>), String>
where
    F: FnOnce(pest::iterators::Pair<Rule>) -> Result<TypeSpec, String>,
{
    let mut name = String::new();
    let mut type_spec_pair = None;
    let mut default = None;
    let mut constraint = None;
    let mut cond_field = None;
    let mut cond_value = None;
    let mut quantum = None;
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => {
                if name.is_empty() {
                    name = inner.as_str().to_string();
                } else if type_spec_pair.is_some() {
                    cond_field = Some(inner.as_str().to_string());
                }
            }
            Rule::type_spec => type_spec_pair = Some(inner),
            Rule::literal => {
                if cond_field.is_some() {
                    cond_value = Some(parse_literal(inner.as_str()));
                } else {
                    default = Some(parse_literal(inner.as_str()));
                }
            }
            Rule::constraint => constraint = Some(build_constraint(inner)?),
            Rule::quantum_spec => quantum = Some(parse_quantum_string(inner)?),
            _ => {}
        }
    }
    let type_spec = type_builder(type_spec_pair.ok_or("Missing type in field")?)?;
    let condition = cond_field.zip(cond_value).map(|(field, value)| Condition { field, value });
    Ok((name, type_spec, default, constraint, condition, quantum))
}

fn build_type_spec(pair: pest::iterators::Pair<Rule>) -> Result<TypeSpec, String> {
    let inner = pair.into_inner().next().ok_or("Empty type_spec")?;
    match inner.as_rule() {
        Rule::base_type => Ok(TypeSpec::Base(parse_base_type(inner.as_str())?)),
        Rule::sized_int_type => {
            let mut it = inner.into_inner();
            let base = it.next().ok_or("sized_int base")?;
            let n = it.next().and_then(|p| p.as_str().parse().ok()).ok_or("sized_int(n) needs number")?;
            let bt = parse_base_type(base.as_str())?;
            Ok(TypeSpec::SizedInt(bt, n))
        }
        Rule::padding_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("padding(n)")?;
            Ok(TypeSpec::Padding(n))
        }
        Rule::reserved_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("reserved(n)")?;
            Ok(TypeSpec::Reserved(n))
        }
        Rule::bitfield_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("bitfield(n)")?;
            Ok(TypeSpec::Bitfield(n))
        }
        Rule::length_of_type => {
            let id = inner.into_inner().next().ok_or("length_of(field)")?.as_str().to_string();
            Ok(TypeSpec::LengthOf(id))
        }
        Rule::count_of_type => {
            let id = inner.into_inner().next().ok_or("count_of(field)")?.as_str().to_string();
            Ok(TypeSpec::CountOf(id))
        }
        Rule::presence_bits_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("presence_bits(n)")?;
            if ![1, 2, 4].contains(&n) {
                return Err("presence_bits(n): n must be 1, 2, or 4".to_string());
            }
            Ok(TypeSpec::PresenceBits(n))
        }
        Rule::bitmap_presence_type => {
            let pairs: Vec<_> = inner.into_inner().collect();
            let nums: Vec<u32> = pairs
                .iter()
                .find(|p| p.as_rule() == Rule::bitmap_presence_size)
                .map(|p| p.clone().into_inner().filter_map(|q| q.as_str().parse().ok()).collect())
                .unwrap_or_default();
            let total_bits = nums.get(0).copied().ok_or("bitmap_presence requires (total_bits, presence_per_block)")?;
            let presence_per_block = nums.get(1).copied().ok_or("bitmap_presence requires (total_bits, presence_per_block)")?;
            let mapping = pairs
                .into_iter()
                .find(|p| p.as_rule() == Rule::bitmap_presence_mapping_list)
                .map(|pair| {
                    let all_entries: Vec<(u32, String)> = pair.into_inner()
                        .filter(|p| p.as_rule() == Rule::bitmap_presence_bit_mapping)
                        .map(|p| {
                            let mut it = p.into_inner();
                            let num_p = it.next().ok_or("bitmap_presence bit mapping")?;
                            let ident_p = it.next().ok_or("bitmap_presence bit mapping")?;
                            let bit = num_p.as_str().parse::<u32>().map_err(|_| "bitmap_presence bit number")?;
                            let name = ident_p.as_str().to_string();
                            Ok((bit, name))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    // FX is not a mapped field; filter out if present for backward compat, renumber to logical indices.
                    let mut logical = Vec::new();
                    let mut logical_idx: u32 = 0;
                    let block_bits = if presence_per_block == 0 { 8 } else { presence_per_block + 1 };
                    for (phys_bit, name) in &all_entries {
                        if name == "FX" {
                            if block_bits > 0 && phys_bit % block_bits != block_bits - 1 {
                                return Err(format!(
                                    "bitmap_presence mapping: FX at physical bit {} is invalid (must be last bit of each block of {})",
                                    phys_bit, block_bits
                                ));
                            }
                        } else {
                            logical.push((logical_idx, name.clone()));
                            logical_idx += 1;
                        }
                    }
                    Ok(logical)
                })
                .transpose()?
                .unwrap_or_default();
            Ok(TypeSpec::BitmapPresence {
                total_bits,
                presence_per_block,
                mapping,
            })
        }
        Rule::padding_bits_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("padding_bits(n)")?;
            Ok(TypeSpec::PaddingBits(n))
        }
        Rule::struct_ref_type => Ok(TypeSpec::StructRef(inner.as_str().to_string())),
        Rule::array_type => {
            let mut inner_iter = inner.into_inner();
            let elem_type = inner_iter.next().ok_or("array type")?;
            let len_pair = inner_iter.next().ok_or("array len")?;
            let elem_spec = match elem_type.as_rule() {
                Rule::type_spec_inner => build_type_spec_inner(elem_type)?,
                _ => build_type_spec(elem_type)?,
            };
            let len = match len_pair.as_rule() {
                Rule::num => ArrayLen::Constant(len_pair.as_str().parse().map_err(|_| "array length")?),
                Rule::ident => ArrayLen::FieldRef(len_pair.as_str().to_string()),
                _ => return Err("array length".to_string()),
            };
            Ok(TypeSpec::Array(Box::new(elem_spec), len))
        }
        Rule::list_type => {
            let inner_type = inner.into_inner().next().ok_or("list<T>")?;
            Ok(TypeSpec::List(Box::new(build_type_spec_inner(inner_type)?)))
        }
        Rule::rep_list_type => {
            let inner_type = inner.into_inner().next().ok_or("rep_list<T>")?;
            Ok(TypeSpec::RepList(Box::new(build_type_spec_inner(inner_type)?)))
        }
        Rule::octets_fx_type => Ok(TypeSpec::OctetsFx),
        Rule::optional_type => {
            let inner_type = inner.into_inner().next().ok_or("optional<T>")?;
            Ok(TypeSpec::Optional(Box::new(build_type_spec_inner(inner_type)?)))
        }
        _ => Err(format!("Unhandled type rule: {:?}", inner.as_rule())),
    }
}

fn build_type_spec_inner(pair: pest::iterators::Pair<Rule>) -> Result<TypeSpec, String> {
    let inner = pair.into_inner().next().ok_or("Empty type_spec_inner")?;
    match inner.as_rule() {
        Rule::base_type => Ok(TypeSpec::Base(parse_base_type(inner.as_str())?)),
        Rule::sized_int_type => {
            let mut it = inner.into_inner();
            let base = it.next().ok_or("sized_int base")?;
            let n = it.next().and_then(|p| p.as_str().parse().ok()).ok_or("sized_int(n)")?;
            let bt = parse_base_type(base.as_str())?;
            Ok(TypeSpec::SizedInt(bt, n))
        }
        Rule::padding_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("padding")?;
            Ok(TypeSpec::Padding(n))
        }
        Rule::reserved_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("reserved")?;
            Ok(TypeSpec::Reserved(n))
        }
        Rule::bitfield_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("bitfield")?;
            Ok(TypeSpec::Bitfield(n))
        }
        Rule::padding_bits_type => {
            let n = inner.into_inner().next().and_then(|p| p.as_str().parse().ok()).ok_or("padding_bits")?;
            Ok(TypeSpec::PaddingBits(n))
        }
        Rule::struct_ref_type => Ok(TypeSpec::StructRef(inner.as_str().to_string())),
        Rule::list_type => {
            let inner_type = inner.into_inner().next().ok_or("list<T>")?;
            Ok(TypeSpec::List(Box::new(build_type_spec_inner(inner_type)?)))
        }
        Rule::rep_list_type => {
            let inner_type = inner.into_inner().next().ok_or("rep_list<T>")?;
            Ok(TypeSpec::RepList(Box::new(build_type_spec_inner(inner_type)?)))
        }
        Rule::octets_fx_type => Ok(TypeSpec::OctetsFx),
        _ => Err("Invalid inner type".to_string()),
    }
}

fn build_constraint(pair: pest::iterators::Pair<Rule>) -> Result<Constraint, String> {
    let inner = pair.into_inner().next().ok_or("Empty constraint")?;
    match inner.as_rule() {
        Rule::range_constraint => {
            let mut intervals = Vec::new();
            for part in inner.into_inner() {
                if part.as_rule() == Rule::interval {
                    let mut nums = part.into_inner();
                    let min_s = nums.next().ok_or("interval min")?.as_str();
                    let max_s = nums.next().ok_or("interval max")?.as_str();
                    let min: i64 = min_s.parse().map_err(|_| "interval min number")?;
                    let max: i64 = max_s.parse().map_err(|_| "interval max number")?;
                    intervals.push((min, max));
                }
            }
            if intervals.is_empty() {
                return Err("range constraint must have at least one interval".to_string());
            }
            Ok(Constraint::Range(intervals))
        }
        Rule::enum_constraint => {
            let mut literals = Vec::new();
            for p in inner.into_inner() {
                if matches!(p.as_rule(), Rule::literal) {
                    literals.push(parse_literal(p.as_str()));
                }
            }
            Ok(Constraint::Enum(literals))
        }
        _ => Err("Unknown constraint".to_string()),
    }
}

fn parse_quantum_string(quantum_spec: pest::iterators::Pair<Rule>) -> Result<String, String> {
    let lit = quantum_spec.into_inner().next().ok_or("quantum_spec: missing string_literal")?;
    let s = lit.as_str();
    if s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        Ok(inner.replace("\\\"", "\"").replace("\\n", "\n").replace("\\t", "\t"))
    } else {
        Ok(s.to_string())
    }
}

fn parse_base_type(s: &str) -> Result<BaseType, String> {
    match s {
        "u8" => Ok(BaseType::U8),
        "u16" => Ok(BaseType::U16),
        "u32" => Ok(BaseType::U32),
        "u64" => Ok(BaseType::U64),
        "i8" => Ok(BaseType::I8),
        "i16" => Ok(BaseType::I16),
        "i32" => Ok(BaseType::I32),
        "i64" => Ok(BaseType::I64),
        "bool" => Ok(BaseType::Bool),
        "float" => Ok(BaseType::Float),
        "double" => Ok(BaseType::Double),
        _ => Err(format!("Unknown base type: {}", s)),
    }
}

fn parse_literal(s: &str) -> Literal {
    let s = s.trim();
    if s == "true" {
        return Literal::Bool(true);
    }
    if s == "false" {
        return Literal::Bool(false);
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        if let Ok(n) = u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16) {
            return Literal::Hex(n);
        }
    }
    if let Ok(n) = s.parse::<i64>() {
        return Literal::Int(n);
    }
    if s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let unescaped = inner.replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"");
        return Literal::String(unescaped);
    }
    Literal::Int(0)
}

fn parse_literal_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let unescaped = inner.replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"");
        return Ok(unescaped.into_bytes());
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex = s[2..].replace(" ", "");
        if hex.len() % 2 != 0 {
            return Err("Hex literal must have even length".to_string());
        }
        let mut bytes = Vec::new();
        for chunk in hex.as_bytes().chunks(2) {
            let s = std::str::from_utf8(chunk).map_err(|_| "Invalid hex")?;
            let b = u8::from_str_radix(s, 16).map_err(|_| "Invalid hex")?;
            bytes.push(b);
        }
        return Ok(bytes);
    }
    Err("literal_bytes: expected string or 0x...".to_string())
}
