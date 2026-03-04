use aiprotodsl::{generate_lua_dissector, parse, ResolvedProtocol};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: gen_wireshark <spec.dsl> [output.lua]");
        std::process::exit(1);
    }
    let input_path = &args[1];
    let dsl_src = fs::read_to_string(input_path).unwrap_or_else(|err| {
        eprintln!("Failed to read DSL file '{}': {}", input_path, err);
        std::process::exit(1);
    });

    let protocol_ast = parse(&dsl_src).unwrap_or_else(|err| {
        eprintln!("Failed to parse DSL syntax:\n{}", err);
        std::process::exit(1);
    });
    
    let resolved = ResolvedProtocol::resolve(protocol_ast).unwrap_or_else(|err| {
        eprintln!("Failed to resolve protocol semantics:\n{}", err);
        std::process::exit(1);
    });

    let default_name = Path::new(input_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("protocol");

    let lua_code = generate_lua_dissector(&resolved, default_name);

    if args.len() >= 3 {
        let output_path = &args[2];
        fs::write(output_path, &lua_code).unwrap_or_else(|err| {
            eprintln!("Failed to write output file '{}': {}", output_path, err);
            std::process::exit(1);
        });
        println!("Generated Wireshark Lua dissector at {}", output_path);
    } else {
        println!("{}", lua_code);
    }
}
