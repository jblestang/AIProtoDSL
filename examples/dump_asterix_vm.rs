use aiprotodsl::ast::ResolvedProtocol;
use aiprotodsl::compiler::Compiler;
use aiprotodsl::parse;
use aiprotodsl::vm::Op;

fn main() {
    // Load the DSL from file
    let dsl = std::fs::read_to_string("examples/asterix_family.dsl")
        .expect("Failed to read examples/asterix_family.dsl");

    let protocol = parse(&dsl).expect("Failed to parse DSL");
    let resolved = ResolvedProtocol::resolve(protocol).expect("Failed to resolve protocol");

    // Compile Cat034
    let compiler = Compiler::new(&resolved);
    let prog034 = compiler
        .compile("Cat034Record")
        .expect("Compilation failed for Cat034");

    // Compile Cat048
    let compiler = Compiler::new(&resolved);
    let prog048 = compiler
        .compile("Cat048Record")
        .expect("Compilation failed for Cat048");

    // Generate Markdown
    let mut out = String::new();
    out.push_str("# ASTERIX VM Programs\n\n");
    out.push_str(
        "This document shows the compiled bytecode programs for validating ASTERIX packets.\n\n",
    );

    out.push_str("## Category 034\n\n");
    dump_program(&mut out, &prog034);

    out.push_str("\n\n## Category 048\n\n");
    dump_program(&mut out, &prog048);

    std::fs::write("asterix_vm_programs.md", out).expect("Failed to write output");
    println!("Generated asterix_vm_programs.md");
}

fn dump_program(out: &mut String, prog: &aiprotodsl::vm::Program) {
    out.push_str(&format!(
        "**Registers allocated:** {}\n\n",
        prog.max_registers
    ));
    out.push_str("### Instruction Listing\n\n");
    out.push_str("| PC | Source Field | Opcode | Description |\n");
    out.push_str("|---:|:-------------|:-------|:------------|\n");

    for (i, op) in prog.ops.iter().enumerate() {
        let debug = if i < prog.debug_info.len() {
            &prog.debug_info[i]
        } else {
            ""
        };
        let desc = match op {
            Op::ReadU8 => "Read 1 byte (u8) into accumulator".to_string(),
            Op::ReadU16Be => "Read 2 bytes (u16, big-endian) into accumulator".to_string(),
            Op::ReadU16Le => "Read 2 bytes (u16, little-endian) into accumulator".to_string(),
            Op::ReadU32Be => "Read 4 bytes (u32, big-endian) into accumulator".to_string(),
            Op::ReadU32Le => "Read 4 bytes (u32, little-endian) into accumulator".to_string(),
            Op::Skip(n) => format!("**Skip {} bytes** (unused field, optimization)", n),
            Op::ReadBytes(n) => format!("Read {} bytes (skip payload)", n),
            Op::StoreReg(r) => format!("Store accumulator → register[{}]", r),
            Op::LoadReg(r) => format!("Load register[{}] → accumulator", r),
            Op::JumpIfEq(val, off) => format!(
                "If accumulator == {}, jump forward {} instructions",
                val, off
            ),
            Op::JumpIfNe(val, off) => format!(
                "If accumulator != {}, jump forward {} instructions",
                val, off
            ),
            Op::JumpBack(off) => format!("Jump back {} instructions", off),
            Op::LoopDecNz(reg, off) => format!(
                "Decrement register[{}]; if > 0, jump back {} instructions",
                reg, off
            ),
            Op::ReadBits(n) => format!("Read {} bits into accumulator", n),
            Op::SkipBits(n) => format!("**Skip {} bits** (unused field, optimization)", n),
            Op::Align => "Align bit cursor to next byte".to_string(),
            Op::TestBit(reg, bit) => format!(
                "Test bit {} of register[{}] → accumulator (0 or 1)",
                bit, reg
            ),
            Op::JumpIfBitSet(reg, bit, offset) => format!(
                "**Jump +{}** if bit {} of register[{}] is SET (Fused)",
                offset, bit, reg
            ),
            Op::JumpIfBitClear(reg, bit, offset) => format!(
                "**Jump +{}** if bit {} of register[{}] is CLEAR (Fused)",
                offset, bit, reg
            ),
            Op::Ret => "**Return** (packet validation successful)".to_string(),
            Op::ZeroBytes(n) => format!("**Write {} zero bytes** (padding)", n),
            Op::ZeroBits(n) => format!("**Write {} zero bits** (padding)", n),
            Op::CheckRange(min, max) => format!("**✓ Validate acc ∈ [{}..{}]**", min, max),
            Op::CheckEnum(_) => "**✓ Validate acc ∈ Enum**".to_string(), // Changed from `vals` to `_` as `vals` is not used
            _ => format!("{:?}", op),
        };
        out.push_str(&format!("| {} | {} | `{:?}` | {} |\n", i, debug, op, desc));
    }

    out.push_str("\n## How It Works\n\n");
    out.push_str("The VM executes these instructions sequentially:\n\n");
    out.push_str("1. **Read operations** (`ReadU8`, `ReadU16Be`, etc.) load data from the packet into the accumulator\n");
    out.push_str("2. **Skip operations** advance the read pointer without loading data (optimization for unused fields)\n");
    out.push_str("3. **Store/Load** operations move data between the accumulator and registers\n");
    out.push_str(
        "4. **Jump operations** implement conditional logic (optional fields, presence bitmaps)\n",
    );
    out.push_str("5. **Loop operations** handle arrays and repetition structures\n");
    out.push_str("6. **Ret** indicates successful validation\n\n");
    out.push_str("### Performance Benefits\n\n");
    out.push_str(
        "- **Zero recursion**: Linear instruction stream eliminates call stack overhead\n",
    );
    out.push_str("- **Register-based**: O(1) field access vs HashMap lookups\n");
    out.push_str(
        "- **Skip optimization**: Unused fields are skipped without reading (see `Skip` opcodes)\n",
    );
    out.push_str("- **Compact**: Single-pass validation with minimal memory allocation\n");

    std::fs::write("cat034_vm_program.md", &out).expect("Failed to write output");
    println!("Generated cat034_vm_program.md");
    println!("\nProgram stats:");
    println!("  Total instructions: {}", prog.ops.len());
    println!("  Registers used: {}", prog.max_registers);

    // Count instruction types
    // Count instruction types
    println!(
        "  Read operations: {}",
        prog.ops
            .iter()
            .filter(|op| matches!(
                op,
                Op::ReadU8
                    | Op::ReadU16Be
                    | Op::ReadU16Le
                    | Op::ReadU32Be
                    | Op::ReadU32Le
                    | Op::ReadBits(_)
            ))
            .count()
    );
    println!(
        "  Skip operations: {}",
        prog.ops
            .iter()
            .filter(|op| matches!(op, Op::Skip(_) | Op::SkipBits(_)))
            .count()
    );
}
