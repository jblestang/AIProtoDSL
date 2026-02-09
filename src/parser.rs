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
    let mut messages = Vec::new();
    let mut structs = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::transport_section => transport = Some(build_transport(inner)?),
            Rule::message_section => messages.push(build_message(inner)?),
            Rule::struct_section => structs.push(build_struct(inner)?),
            _ => {}
        }
    }

    Ok(Protocol {
        transport,
        messages,
        structs,
    })
}

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

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => name = inner.as_str().to_string(),
            Rule::transport_type_spec => type_spec = Some(build_transport_type_spec(inner)?),
            Rule::literal => default = Some(parse_literal(inner.as_str())),
            Rule::constraint => constraint = Some(build_constraint(inner)?),
            _ => {}
        }
    }

    Ok(TransportField {
        name,
        type_spec: type_spec.ok_or("Missing type in transport field")?,
        default,
        constraint,
    })
}

fn build_transport_type_spec(
    pair: pest::iterators::Pair<Rule>,
) -> Result<TransportTypeSpec, String> {
    let inner = pair.into_inner().next().ok_or("Empty transport type")?;
    match inner.as_rule() {
        Rule::base_type => Ok(TransportTypeSpec::Base(parse_base_type(inner.as_str())?)),
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
    build_generic_field(pair, build_type_spec).map(|(name, type_spec, default, constraint, condition)| MessageField {
        name,
        type_spec,
        default,
        constraint,
        condition,
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
    build_generic_field(pair, build_type_spec).map(|(name, type_spec, default, constraint, condition)| StructField {
        name,
        type_spec,
        default,
        constraint,
        condition,
    })
}

fn build_generic_field<F>(
    pair: pest::iterators::Pair<Rule>,
    type_builder: F,
) -> Result<(String, TypeSpec, Option<Literal>, Option<Constraint>, Option<Condition>), String>
where
    F: FnOnce(pest::iterators::Pair<Rule>) -> Result<TypeSpec, String>,
{
    let mut name = String::new();
    let mut type_spec_pair = None;
    let mut default = None;
    let mut constraint = None;
    let mut cond_field = None;
    let mut cond_value = None;
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
            _ => {}
        }
    }
    let type_spec = type_builder(type_spec_pair.ok_or("Missing type in field")?)?;
    let condition = cond_field.zip(cond_value).map(|(field, value)| Condition { field, value });
    Ok((name, type_spec, default, constraint, condition))
}

fn build_type_spec(pair: pest::iterators::Pair<Rule>) -> Result<TypeSpec, String> {
    let inner = pair.into_inner().next().ok_or("Empty type_spec")?;
    match inner.as_rule() {
        Rule::base_type => Ok(TypeSpec::Base(parse_base_type(inner.as_str())?)),
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
        Rule::fspec_type => Ok(TypeSpec::Fspec),
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
        _ => Err("Invalid inner type".to_string()),
    }
}

fn build_constraint(pair: pest::iterators::Pair<Rule>) -> Result<Constraint, String> {
    let inner = pair.into_inner().next().ok_or("Empty constraint")?;
    match inner.as_rule() {
        Rule::range_constraint => {
            let mut nums = inner.into_inner();
            let min_s = nums.next().ok_or("range min")?.as_str();
            let max_s = nums.next().ok_or("range max")?.as_str();
            let min: i64 = min_s.parse().map_err(|_| "range min number")?;
            let max: i64 = max_s.parse().map_err(|_| "range max number")?;
            Ok(Constraint::Range { min, max })
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
