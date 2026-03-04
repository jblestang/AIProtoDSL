use crate::{parse, ResolvedProtocol, codec::{Codec, Endianness}, value::Value};
use mlua::prelude::*;
use mlua::UserData;
use std::sync::Arc;
use std::collections::HashMap;

/// A wrapper around ResolvedProtocol so we can safely pass it to Lua
#[derive(Clone)]
struct ProtocolUserData(Arc<ResolvedProtocol>);

impl UserData for ProtocolUserData {}

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

fn value_to_lua(lua: &Lua, val: &Value) -> mlua::Result<mlua::Value> {
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
                t.set(k.as_str(), value_to_lua(lua, v)?)?;
            }
            Ok(mlua::Value::Table(t))
        }
        Value::List(l) => {
            let t = lua.create_table()?;
            for (i, v) in l.iter().enumerate() {
                t.set(i + 1, value_to_lua(lua, v)?)?; // Lua arrays are 1-indexed
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
    
    // Get the raw byte slice from the Lua string
    let bytes = data.as_bytes();
    
    let codec = Codec::new((**_resolved_proto).clone(), Endianness::Big);
    
    // Attempt to decode the generic transport first
    let transport_result = codec.decode_transport(bytes.as_ref());
    
    let t = lua.create_table()?;
    match transport_result {
        Ok(t_vals) => {
            let (mut consumed, mut transport_len) = (0, 0);
            
            // If the transport wasn't empty, let's just guess its length or put it in natively?
            // Actually, we can encode it back to get its length for now, or assume the first N bytes.
            // A small trick: re-encode transport to find its byte-length.
            if let Ok(enc_t) = codec.encode_transport(&t_vals) {
                transport_len = enc_t.len();
                consumed += transport_len;
            }
            
            t.set("__transport", value_to_lua(lua, &Value::Struct(t_vals.clone()))?)?;
            t.set("__transport_len", transport_len)?;
            
            // Resolve following payloads using the selector
            if let Some(msg_name) = _resolved_proto.message_for_transport_values(&t_vals) {
                t.set("__message_type", msg_name)?;
                
                let is_list = _resolved_proto.payload_is_list_for_transport(&t_vals);
                
                if is_list {
                    let payloads = lua.create_table()?;
                    let mut idx = 1;
                    
                    let mut payload_limit = bytes.len();
                    // If the transport layer has a `length` field, limit our decode loop to that length
                    // to avoid overrunning into Ethernet padding or trailer bytes.
                    if let Some(Value::U64(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                        payload_limit = (*len as usize).min(bytes.len());
                    } else if let Some(Value::U32(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                        payload_limit = (*len as usize).min(bytes.len());
                    } else if let Some(Value::U16(len)) = t_vals.get("length").or_else(|| t_vals.get("len")) {
                        payload_limit = (*len as usize).min(bytes.len());
                    }
                    
                    while consumed < payload_limit {
                        let rem = &bytes[consumed..payload_limit];
                        if rem.is_empty() { break; }
                        
                        let (msg_len, msg_res) = codec.decode_message_with_extent(msg_name, rem);
                        
                        let msg_t = lua.create_table()?;
                        msg_t.set("__len", msg_len)?;
                        
                        match msg_res {
                            Ok(msg_vals) => {
                                for (k, v) in msg_vals {
                                    msg_t.set(k, value_to_lua(lua, &v)?)?;
                                }
                            }
                            Err(e) => {
                                msg_t.set("__error", e.to_string())?;
                                payloads.set(idx, msg_t)?;
                                break; // Stop decoding on error
                            }
                        }
                        
                        payloads.set(idx, msg_t)?;
                        idx += 1;
                        if msg_len == 0 || msg_len > rem.len() { break; } // Prevent infinite loops or overruns
                        consumed += msg_len;
                    }
                    t.set("payloads", payloads)?;
                } else {
                    // Single message payload
                    let rem = &bytes[consumed..];
                    let (msg_len, msg_res) = codec.decode_message_with_extent(msg_name, rem);
                    let msg_t = lua.create_table()?;
                    msg_t.set("__len", msg_len)?;
                    match msg_res {
                        Ok(msg_vals) => {
                            for (k, v) in msg_vals {
                                msg_t.set(k, value_to_lua(lua, &v)?)?;
                            }
                        }
                        Err(e) => {
                            msg_t.set("__error", e.to_string())?;
                        }
                    }
                    t.set("payload", msg_t)?;
                }
            }
        }
        Err(e) => {
            t.set("__error", e.to_string())?;
        }
    }

    Ok(mlua::Value::Table(t))
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
