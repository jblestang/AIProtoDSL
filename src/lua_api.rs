use crate::{parse, ResolvedProtocol, codec::{Codec, Endianness}, value::Value};
use mlua::prelude::*;
use mlua::{UserData, UserDataMethods};
use std::sync::Arc;
use std::collections::HashMap;

/// A wrapper around ResolvedProtocol so we can safely pass it to Lua
#[derive(Clone)]
struct ProtocolUserData(Arc<ResolvedProtocol>);



/// Helper to convert a TypeSpec to a Wireshark ftype string
fn type_spec_to_ftype(spec: &crate::ast::TypeSpec) -> &'static str {
    use crate::ast::{TypeSpec, BaseType};
    match spec {
        TypeSpec::Base(bt) | TypeSpec::SizedInt(bt, _) => match bt {
            BaseType::U8 => "uint8",
            BaseType::U16 => "uint16",
            BaseType::U32 => "uint32",
            BaseType::U64 => "uint64",
            BaseType::I8 => "int8",
            BaseType::I16 => "int16",
            BaseType::I32 => "int32",
            BaseType::I64 => "int64",
            BaseType::Bool => "bool",
            BaseType::Float => "float",
            BaseType::Double => "double",
        },
        TypeSpec::Bitfield(bits) => {
            if *bits <= 8 { "uint8" }
            else if *bits <= 16 { "uint16" }
            else if *bits <= 32 { "uint32" }
            else { "uint64" }
        },
        TypeSpec::PresenceBits(bytes) => {
            if *bytes <= 1 { "uint8" }
            else if *bytes <= 2 { "uint16" }
            else if *bytes <= 4 { "uint32" }
            else { "uint64" }
        },
        TypeSpec::Optional(inner) => type_spec_to_ftype(inner),
        _ => "uint64", // Fallback
    }
}

impl UserData for ProtocolUserData {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("get_all_fields", |lua, this, _: ()| {
            let proto = &this.0;
            let mut fields = HashMap::new();

            // Helper to add a field if not already present
            let mut add_field = |container: &str, name: &str, type_spec: &crate::ast::TypeSpec, doc: Option<&str>, quantum: Option<&str>| -> mlua::Result<()> {
                if fields.contains_key(name) {
                    return Ok(());
                }

                let f_table = lua.create_table()?;
                f_table.set("name", name)?;
                f_table.set("type", type_spec_to_ftype(type_spec))?;
                if let Some(d) = doc {
                    f_table.set("doc", d)?;
                }
                if let Some(q) = quantum {
                    f_table.set("quantum", q)?;
                }

                // Identify constraints (enum or range)
                if let Some(constraint) = proto.field_constraint(container, name) {
                    match constraint {
                        crate::ast::Constraint::Enum(variants) => {
                            let vt = lua.create_table()?;
                            for var in variants {
                                if let crate::ast::Literal::Int(val) = var {
                                    if let Some(variant_name) = proto.enum_variant_name_for_type_and_value(type_spec, *val) {
                                        vt.set(*val, variant_name)?;
                                    }
                                }
                            }
                            f_table.set("enum", vt)?;
                        }
                        crate::ast::Constraint::Range(intervals) => {
                            let rt = lua.create_table()?;
                            for (i, (min, max)) in intervals.iter().enumerate() {
                                let interval = lua.create_table()?;
                                interval.set("min", *min)?;
                                interval.set("max", *max)?;
                                rt.set(i + 1, interval)?;
                            }
                            f_table.set("ranges", rt)?;
                        }
                    }
                }

                fields.insert(name.to_string(), f_table);
                Ok(())
            };

            // Collect fields from the transport header
            if let Some(transport_def) = &proto.protocol.transport {
                for field in &transport_def.fields {
                    let doc = proto.field_doc("transport", &field.name);
                    let type_spec = match &field.type_spec {
                        crate::ast::TransportTypeSpec::Base(bt) => crate::ast::TypeSpec::Base(bt.clone()),
                        crate::ast::TransportTypeSpec::SizedInt(bt, bits) => crate::ast::TypeSpec::SizedInt(bt.clone(), *bits),
                        _ => crate::ast::TypeSpec::Base(crate::ast::BaseType::U64),
                    };
                    add_field("transport", &field.name, &type_spec, doc, field.quantum.as_deref())?;
                }
            }

            // Collect fields from all messages
            for msg in &proto.protocol.messages {
                for field in &msg.fields {
                    let doc = proto.field_doc(&msg.name, &field.name).or(field.doc.as_deref());
                    add_field(&msg.name, &field.name, &field.type_spec, doc, field.quantum.as_deref())?;
                }
            }

            // Collect fields from all structs
            for s in &proto.protocol.structs {
                for field in &s.fields {
                    let doc = proto.field_doc(&s.name, &field.name);
                    add_field(&s.name, &field.name, &field.type_spec, doc, field.quantum.as_deref())?;
                }
            }

            let result = lua.create_table()?;
            let mut i = 1;
            for (_, f_table) in fields {
                result.set(i, f_table)?;
                i += 1;
            }
            Ok(result)
        });
    }
}

/// Parse a DSL file and return a Lua UserData object holding the ResolvedProtocol.
fn load_dsl(_: &Lua, filepath: String) -> LuaResult<ProtocolUserData> {
    let dsl_src = std::fs::read_to_string(&filepath).map_err(|e| {
        LuaError::RuntimeError(format!("Failed to read {}: {}", filepath, e))
    })?;

    let ast = parse(&dsl_src)
        .map_err(|e| LuaError::RuntimeError(format!("Parse error: {:?}", e)))?;

    let resolved = ResolvedProtocol::resolve(ast)
        .map_err(|e| LuaError::RuntimeError(format!("Resolution error: {:?}", e)))?;

    Ok(ProtocolUserData(Arc::new(resolved)))
}

fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::U8(x) => Some(*x as i64),
        Value::U16(x) => Some(*x as i64),
        Value::U32(x) => Some(*x as i64),
        Value::U64(x) => (*x).try_into().ok(),
        Value::I8(x) => Some(*x as i64),
        Value::I16(x) => Some(*x as i64),
        Value::I32(x) => Some(*x as i64),
        Value::I64(x) => Some(*x),
        Value::List(l) if l.len() == 1 => value_as_i64(&l[0]),
        _ => None,
    }
}

fn value_to_lua<'lua>(
    lua: &'lua Lua,
    proto: &ResolvedProtocol,
    container: Option<&str>,
    val: &Value,
) -> mlua::Result<mlua::Value> {
    match val {
        Value::U8(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::U16(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::U32(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::U64(v) => Ok(mlua::Value::Integer(*v as i64)), // Warning: u64 > i64::MAX will wrap/truncate in Lua 5.4 integers.
        Value::I8(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::I16(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::I32(v) => Ok(mlua::Value::Integer(*v as i64)),
        Value::I64(v) => Ok(mlua::Value::Integer(*v)),
        Value::Bool(v) => Ok(mlua::Value::Boolean(*v)),
        Value::Float(v) => Ok(mlua::Value::Number(*v as f64)),
        Value::Double(v) => Ok(mlua::Value::Number(*v)),
        Value::Bytes(b) => {
            // Hex string representation for bytes (simplified for GUI)
            let hex: String = b.iter().map(|byte| format!("{:02X}", byte)).collect();
            lua.create_string(&hex)?.into_lua(lua)
        }
        Value::Struct(m) => {
            let t = lua.create_table()?;
            for (k, v) in m {
                let mut child_container = None;
                if let Some(c) = container {
                    let (quantum, child) = proto.field_quantum_and_child(c, k);
                    if let Some(q) = quantum {
                        t.set(format!("__quantum_{}", k), q)?;
                    }
                    if let Some(doc) = proto.field_doc(c, k) {
                        t.set(format!("__doc_{}", k), doc)?;
                    }
                    if let Some(n) = value_as_i64(v) {
                        let mut enum_resolved = false;
                        if let Some(ts) = proto.field_type_spec(c, k) {
                            if let Some(var_name) = proto.enum_variant_name_for_type_and_value(ts, n) {
                                t.set(format!("__enum_{}", k), var_name)?;
                                enum_resolved = true;
                            }
                        }
                        if !enum_resolved {
                            if let Some(constraint) = proto.field_constraint(c, k) {
                                if let Some(var_name) = proto.enum_variant_name_for_value(constraint, n) {
                                    t.set(format!("__enum_{}", k), var_name)?;
                                }
                            }
                        }
                    }
                    child_container = child;
                }
                t.set(k.as_str(), value_to_lua(lua, proto, child_container, v)?)?;
            }
            Ok(mlua::Value::Table(t))
        }
        Value::List(l) => {
            let t = lua.create_table()?;
            for (i, v) in l.iter().enumerate() {
                t.set(i + 1, value_to_lua(lua, proto, container, v)?)?; // Lua arrays are 1-indexed
            }
            Ok(mlua::Value::Table(t))
        }
        Value::Padding => Ok(mlua::Value::Nil),
    }
}

/// A simplified dissect function for now to prove MLua works.
fn dissect_packet(lua: &Lua, (protocol, data): (mlua::AnyUserData, mlua::String)) -> mlua::Result<mlua::Value> {
    let resolved = protocol.borrow::<ProtocolUserData>()?;
    let _resolved_proto = &resolved.0;
    
    let bytes = data.as_bytes();
    let codec = Codec::new((**_resolved_proto).clone(), Endianness::Big);
    
    let results = lua.create_table()?;
    let mut offset = 0;
    let mut block_idx = 1;

    while offset < bytes.len() {
        let rem_bytes = &bytes[offset..];
        let transport_result = codec.decode_transport(rem_bytes);
        
        let t = lua.create_table()?;
        match transport_result {
            Ok(t_vals) => {
                let (mut consumed, mut transport_len) = (0, 0);
                if let Ok(enc_t) = codec.encode_transport(&t_vals) {
                    transport_len = enc_t.len();
                    consumed += transport_len;
                }
                
                t.set("Transport Header", value_to_lua(lua, _resolved_proto, None, &Value::Struct(t_vals.clone()))?)?;
                t.set("__transport_len", transport_len)?;
                t.set("__offset_Transport Header", offset as u64)?;
                t.set("__len_Transport Header", transport_len as u64)?;
                
                let mut block_limit = rem_bytes.len();
                if let Some(Value::U64(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                    block_limit = (*len as usize).min(rem_bytes.len());
                } else if let Some(Value::U32(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                    block_limit = (*len as usize).min(rem_bytes.len());
                } else if let Some(Value::U16(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                    block_limit = (*len as usize).min(rem_bytes.len());
                }
                
                let mut transport_valid = false;
                if let Some(msg_name) = _resolved_proto.message_for_transport_values(&t_vals) {
                    transport_valid = true;
                    t.set("__message_type", msg_name)?;
                    let is_list = _resolved_proto.payload_is_list_for_transport(&t_vals);
                    
                    if is_list {
                        let payloads = lua.create_table()?;
                        let mut p_idx = 1;
                        
                        while consumed < block_limit {
                            let p_rem = &rem_bytes[consumed..block_limit];
                            if p_rem.is_empty() { break; }
                            
                            let (msg_len, msg_res) = codec.decode_message_with_extent(msg_name, p_rem);
                            let msg_t = match msg_res {
                                Ok(msg_vals) => {
                                    let mut adjusted_vals = msg_vals;
                                    for (k, v) in adjusted_vals.iter_mut() {
                                        if k.starts_with("__offset_") {
                                            if let Value::U64(off) = v {
                                                *off += (offset + consumed) as u64;
                                            }
                                        } else if let Value::Struct(m) = v {
                                            for (sk, sv) in m.iter_mut() {
                                                if sk.starts_with("__offset_") {
                                                    if let Value::U64(off) = sv {
                                                        *off += (offset + consumed) as u64;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    match value_to_lua(lua, _resolved_proto, Some(msg_name), &Value::Struct(adjusted_vals))? {
                                        mlua::Value::Table(tbl) => tbl,
                                        _ => lua.create_table()?,
                                    }
                                }
                                Err(e) => {
                                    let tbl = lua.create_table()?;
                                    tbl.set("__error", e.to_string())?;
                                    tbl
                                }
                            };
                            msg_t.set("__len", msg_len)?;
                            let had_error = msg_t.contains_key("__error")?;
                            payloads.set(p_idx, msg_t)?;
                            p_idx += 1;
                            
                            if had_error { break; }
                            if msg_len == 0 || msg_len > p_rem.len() { break; }
                            consumed += msg_len;
                        }
                        t.set("payloads", payloads)?;
                    } else {
                        let p_rem = &rem_bytes[consumed..block_limit];
                        let (msg_len, msg_res) = codec.decode_message_with_extent(msg_name, p_rem);
                        let msg_t = match msg_res {
                            Ok(msg_vals) => {
                                let mut adjusted_vals = msg_vals;
                                for (k, v) in adjusted_vals.iter_mut() {
                                    if k.starts_with("__offset_") {
                                        if let Value::U64(off) = v {
                                            *off += (offset + consumed) as u64;
                                        }
                                    } else if let Value::Struct(m) = v {
                                        for (sk, sv) in m.iter_mut() {
                                            if sk.starts_with("__offset_") {
                                                if let Value::U64(off) = sv {
                                                    *off += (offset + consumed) as u64;
                                                }
                                            }
                                        }
                                    }
                                }
                                match value_to_lua(lua, _resolved_proto, Some(msg_name), &Value::Struct(adjusted_vals))? {
                                    mlua::Value::Table(tbl) => tbl,
                                    _ => lua.create_table()?,
                                }
                            }
                            Err(e) => {
                                let tbl = lua.create_table()?;
                                tbl.set("__error", e.to_string())?;
                                tbl
                            }
                        };
                        msg_t.set("__len", msg_len)?;
                        t.set("payload", msg_t)?;
                        consumed += msg_len;
                    }
                }
                
                t.set("__block_len", block_limit)?;
                results.set(block_idx, t)?;
                block_idx += 1;
                
                if block_limit == 0 { break; }
                offset += block_limit;
            }
            Err(e) => {
                t.set("__error", e.to_string())?;
                results.set(block_idx, t)?;
                break;
            }
        }
    }

    Ok(mlua::Value::Table(results))
}

/// This is the entry point that `package.loadlib` calls.
/// The function must be named `luaopen_<module_name>`.
#[mlua::lua_module]
fn aiprotodsl(lua: &Lua) -> mlua::Result<mlua::Table> {
    let exports = lua.create_table()?;

    exports.set("load_dsl", lua.create_function(load_dsl)?)?;
    exports.set("dissect_packet", lua.create_function(dissect_packet)?)?;

    Ok(exports)
}
