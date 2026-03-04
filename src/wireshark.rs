use crate::ast::{BaseType, ResolvedProtocol, TypeSpec, PaddingKind};
use std::fmt::Write;

pub fn generate_lua_dissector(protocol: &ResolvedProtocol, protocol_name: &str) -> String {
    let mut out = String::new();
    let safe_name = protocol_name.replace("-", "_").replace(".", "_").to_lowercase();
    
    writeln!(out, "-- Auto-generated Wireshark Lua Dissector for {}", protocol_name).unwrap();
    writeln!(out, "local {}_proto = Proto(\"{}\", \"{} Protocol\")\n", safe_name, safe_name, protocol_name).unwrap();
    
    writeln!(out, "-- ProtoFields").unwrap();
    writeln!(out, "local f = {{}}").unwrap();
    
    // Generate Fields for Transport
    if let Some(transport) = &protocol.protocol.transport {
        for field in &transport.fields {
            // Simplified: we treat everything as bytes or basic ints in prototype
            let wt = "bytes"; 
            writeln!(out, "f.transport_{} = ProtoField.{}(\"{}.transport.{}\", \"{}\", base.HEX)", 
                     field.name, wt, safe_name, field.name, field.name).unwrap();
        }
    }

    // Generate Fields for Messages
    for msg in &protocol.protocol.messages {
        writeln!(out, "f.msg_{} = ProtoField.none(\"{}.msg.{}\", \"Message {}\")", msg.name, safe_name, msg.name, msg.name).unwrap();
        for field in &msg.fields {
            let wt = rust_type_to_ws_type(&field.type_spec);
            writeln!(out, "f.msg_{}_{} = ProtoField.{}(\"{}.msg.{}.{}\", \"{}\", base.DEC)", 
                     msg.name, field.name, wt, safe_name, msg.name, field.name, field.name).unwrap();
        }
    }

    // Generate Fields for Structs
    for s in &protocol.protocol.structs {
        writeln!(out, "f.struct_{} = ProtoField.none(\"{}.struct.{}\", \"Struct {}\")", s.name, safe_name, s.name, s.name).unwrap();
        for field in &s.fields {
            let wt = rust_type_to_ws_type(&field.type_spec);
            writeln!(out, "f.struct_{}_{} = ProtoField.{}(\"{}.struct.{}.{}\", \"{}\", base.DEC)", 
                     s.name, field.name, wt, safe_name, s.name, field.name, field.name).unwrap();
        }
    }
    
    writeln!(out, "\n{}_proto.fields = {{", safe_name).unwrap();
    if let Some(transport) = &protocol.protocol.transport {
        for field in &transport.fields {
            writeln!(out, "  f.transport_{},", field.name).unwrap();
        }
    }
    for msg in &protocol.protocol.messages {
        writeln!(out, "  f.msg_{},", msg.name).unwrap();
        for field in &msg.fields {
            writeln!(out, "  f.msg_{}_{},", msg.name, field.name).unwrap();
        }
    }
    for s in &protocol.protocol.structs {
        writeln!(out, "  f.struct_{},", s.name).unwrap();
        for field in &s.fields {
            writeln!(out, "  f.struct_{}_{},", s.name, field.name).unwrap();
        }
    }
    writeln!(out, "}}\n").unwrap();

    // Dissector function
    writeln!(out, "-- Main Dissector").unwrap();
    writeln!(out, "function {}_proto.dissector(buffer, pinfo, tree)", safe_name).unwrap();
    writeln!(out, "  pinfo.cols.protocol = \"{}\"", protocol_name).unwrap();
    writeln!(out, "  local subtree = tree:add({}_proto, buffer(), \"{} Protocol Data\")", safe_name, protocol_name).unwrap();
    writeln!(out, "  local offset = 0").unwrap();
    writeln!(out, "  local len = buffer:len()").unwrap();
    writeln!(out, "\n  -- TODO: Implemented actual decoding logic here, interpreting the AST").unwrap();
    writeln!(out, "  -- Currently displaying an empty tree for the plugin skeleton structure").unwrap();
    writeln!(out, "end\n").unwrap();
    
    // Register the dissector to a dummy port just for showcase
    out.push_str("-- Register the dissector to a default UDP port (change as needed)\n");
    writeln!(out, "local udp_port = DissectorTable.get(\"udp.port\")").unwrap();
    writeln!(out, "udp_port:add(12345, {}_proto)", safe_name).unwrap();

    out
}

fn rust_type_to_ws_type(spec: &TypeSpec) -> &'static str {
    match spec {
        TypeSpec::Base(b) => match b {
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
        TypeSpec::SizedInt(_, _) | TypeSpec::Bitfield(_) => "uint32", // simplify
        TypeSpec::Array(_, _) | TypeSpec::List(_) | TypeSpec::RepList(_) | TypeSpec::OctetsFx => "bytes",
        TypeSpec::Padding(_) => "bytes",
        TypeSpec::StructRef(_) => "none",
        _ => "bytes",
    }
}
