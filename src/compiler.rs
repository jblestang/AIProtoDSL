//! Compiler for translating ResolvedProtocol into VM Bytecode.

use crate::ast::{ArrayLen, BaseType, Condition, PaddingKind, ResolvedProtocol, TypeSpec};
use crate::vm::{Op, Program};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Message not found: {0}")]
    MessageNotFound(String),
    #[error("Struct not found: {0}")]
    StructNotFound(String),
    #[error("Field not found for length/count: {0}")]
    FieldNotFound(String),
    #[error("Register allocation failed (too many registers)")]
    TooManyRegisters,
    #[error("Unsupported feature in VM: {0}")]
    Unsupported(String),
}

/// Compiles a ResolvedProtocol message into a VM Program.
pub struct Compiler<'a> {
    resolved: &'a ResolvedProtocol,
    ops: Vec<Op>,
    /// Map field names (in the current scope) to register indices.
    /// When entering a struct, we might need to prefix names or handle scope.
    /// For now, we assume flattened scope or unique names per optimization proposal.
    /// Actually, simple scope: just store "current level" field names.
    field_regs: HashMap<String, u8>,
    /// Map field name to (register_index, bit_index) for presence check.
    /// Map field name to (register_index, bit_index) for presence check.
    presence_checks: HashMap<String, (u8, u8)>,
    next_reg: u8,

    // Debug info
    debug_info: Vec<String>,
    current_context: String,
}

impl<'a> Compiler<'a> {
    pub fn new(resolved: &'a ResolvedProtocol) -> Self {
        Self {
            resolved,
            ops: Vec::new(),
            field_regs: HashMap::new(),
            presence_checks: HashMap::new(),
            next_reg: 0,
            debug_info: Vec::new(),
            current_context: "program_start".to_string(),
        }
    }

    pub fn push_op(&mut self, op: Op) {
        self.ops.push(op);
        self.debug_info.push(self.current_context.clone());
    }

    pub fn compile(mut self, msg_name: &str) -> Result<Program, CompileError> {
        let msg = self
            .resolved
            .protocol
            .messages
            .iter()
            .find(|m| m.name == msg_name)
            .ok_or_else(|| CompileError::MessageNotFound(msg_name.to_string()))?;

        // Pass 1: Analyze dependencies (which fields are needed for length/count/cond)
        let needed_unscoped = self.analyze_dependencies_message(msg);

        // Pass 2: Compile
        for field in &msg.fields {
            let is_needed = needed_unscoped.contains(&field.name);
            // In walk.rs, validation is done if check_constraints is true (which comes from !saturating &&/|| constraint exists).
            let must_validate = field.constraint.is_some() && !field.saturating;
            let should_read = is_needed || must_validate;

            self.compile_field(field, should_read)?;
        }

        self.push_op(Op::Ret);

        let mut prog = Program {
            ops: self.ops,
            debug_info: self.debug_info,
            max_registers: self.next_reg as usize,
        };

        // Run peephole optimizer
        prog.optimize();

        Ok(prog)
    }

    fn analyze_dependencies_message(
        &self,
        msg: &crate::ast::MessageSection,
    ) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for f in &msg.fields {
            if let Some(cond) = &f.condition {
                set.insert(cond.field.clone());
            }
            self.analyze_type_spec(&f.type_spec, &mut set);
        }
        set
    }

    fn analyze_dependencies_struct(
        &self,
        s: &crate::ast::StructSection,
    ) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for f in &s.fields {
            if let Some(cond) = &f.condition {
                set.insert(cond.field.clone());
            }
            self.analyze_type_spec(&f.type_spec, &mut set);
        }
        set
    }

    fn analyze_type_spec(&self, spec: &TypeSpec, set: &mut std::collections::HashSet<String>) {
        match spec {
            TypeSpec::LengthOf(n) | TypeSpec::CountOf(n) => {
                set.insert(n.clone());
            }
            TypeSpec::Array(inner, len) => {
                if let ArrayLen::FieldRef(n) = len {
                    set.insert(n.clone());
                }
                self.analyze_type_spec(inner, set);
            }
            TypeSpec::List(inner) | TypeSpec::RepList(inner) | TypeSpec::Optional(inner) => {
                self.analyze_type_spec(inner, set);
            }
            _ => {}
        }
    }

    fn compile_field(
        &mut self,
        field: &crate::ast::MessageField,
        should_read: bool,
    ) -> Result<(), CompileError> {
        self.current_context = field.name.clone();
        let name = &field.name;
        let spec = &field.type_spec;
        // TODO: Handle condition (JumpIfFalse). For now assumed handled by caller logic or minimal.

        match spec {
            TypeSpec::Base(bt) => {
                if should_read {
                    self.emit_base_type(bt)?;
                    self.maybe_store_reg(name);
                    // Emit constraint check if field has non-saturating constraint
                    if let Some(ref constraint) = field.constraint {
                        if !field.saturating {
                            self.emit_constraint_check(constraint)?;
                        }
                    }
                } else {
                    use BaseType::*;
                    let size = match bt {
                        U8 | I8 | Bool => 1,
                        U16 | I16 => 2,
                        U32 | I32 | Float => 4,
                        U64 | I64 | Double => 8,
                    };
                    self.push_op(Op::Skip(size));
                }
            }
            TypeSpec::SizedInt(bt, bits) => {
                // SizedInt usually implies reading specific bits, but if mapped to standard types or just skipping blocks:
                // walk.rs handles it as `pos += (n+7)/8`.
                let byte_len = ((*bits + 7) / 8) as u32;
                if should_read {
                    // For now emitting same as base type (approximate for prototype)
                    self.emit_base_type(bt)?;
                    self.maybe_store_reg(name);
                } else {
                    self.push_op(Op::Skip(byte_len));
                }
            }
            TypeSpec::Padding(kind) => {
                let byte_len = match kind {
                    PaddingKind::Bytes(n) => *n as u32,
                    PaddingKind::Bits(n) => ((*n + 7) / 8) as u32,
                };
                self.push_op(Op::ZeroBytes(byte_len));
            }
            TypeSpec::Bitfield(n) => {
                let byte_len = ((*n + 7) / 8) as u32;
                if should_read {
                    self.push_op(Op::ReadBits(*n as u8));
                    self.maybe_store_reg(name);
                } else {
                    self.push_op(Op::Skip(byte_len));
                }
            }
            TypeSpec::Array(inner, len) => {
                match len {
                    ArrayLen::Constant(n) => {
                        let _ctr_reg = self.alloc_reg();
                        if *n <= 16 {
                            for _ in 0..*n {
                                // Arrays imply recursion. Inner element 'should_read' dep depends on struct analysis if struct.
                                // If inner is Base, it's anonymous.
                                // We need to handle this. `compile_type` needs `should_read`?
                                // For now, let's assume array elements are always read if simple?
                                // No, we should optimize them too.
                                // But `compile_type` is generic.
                                // Let's simplify: call compile_type which defaults to "READ EVERYTHING" for now inside,
                                // OR pass down logic.
                                // Since `compile_type` calls `compile_field("_")`, we can pass forced read?
                                // Actually, for Array of Structs, the Struct analysis determines what fields are read.
                                // For Array of u8, if it's just data blob...
                                // `walk.rs` skips `u8[n]` by `pos += n`.
                                // My loop optimization handles this if inner is Skip.
                                self.compile_type(inner)?;
                            }
                        } else {
                            return Err(CompileError::Unsupported(
                                "Large fixed arrays not supported yet".into(),
                            ));
                        }
                    }
                    ArrayLen::FieldRef(len_field) => {
                        if let Some(&reg) = self.field_regs.get(len_field) {
                            let start_idx = self.ops.len();
                            self.compile_type(inner)?;
                            let body_len = self.ops.len() - start_idx;
                            self.push_op(Op::LoopDecNz(reg, (body_len + 1) as u32));
                        } else {
                            return Err(CompileError::FieldNotFound(len_field.clone()));
                        }
                    }
                }
            }
            TypeSpec::StructRef(sname) => {
                if let Some(s) = self
                    .resolved
                    .protocol
                    .structs
                    .iter()
                    .find(|s| s.name == *sname)
                {
                    // Analyze struct dependencies
                    let struct_deps = self.analyze_dependencies_struct(s);
                    for f in &s.fields {
                        let is_needed = struct_deps.contains(&f.name);
                        // Struct fields don't have constraints, so just compile the type
                        if is_needed {
                            match &f.type_spec {
                                TypeSpec::Base(bt) => {
                                    self.emit_base_type(bt)?;
                                    self.maybe_store_reg(&f.name);
                                }
                                _ => {
                                    // For other types in structs, use compile_type
                                    self.compile_type(&f.type_spec)?;
                                }
                            }
                        } else {
                            // Skip the field
                            match &f.type_spec {
                                TypeSpec::Base(bt) => {
                                    use BaseType::*;
                                    let size = match bt {
                                        U8 | I8 | Bool => 1,
                                        U16 | I16 => 2,
                                        U32 | I32 | Float => 4,
                                        U64 | I64 | Double => 8,
                                    };
                                    self.push_op(Op::Skip(size));
                                }
                                TypeSpec::SizedInt(_bt, bits) => {
                                    let byte_len = ((bits + 7) / 8) as u32;
                                    self.push_op(Op::Skip(byte_len));
                                }
                                _ => {
                                    // For complex types, still compile but don't store
                                    self.compile_type(&f.type_spec)?;
                                }
                            }
                        }
                    }
                } else if let Some(_e) = self
                    .resolved
                    .protocol
                    .enum_defs
                    .iter()
                    .find(|e| e.name == *sname)
                {
                    if should_read {
                        self.emit_base_type(&BaseType::U8)?;
                        self.maybe_store_reg(name);
                    } else {
                        self.push_op(Op::Skip(1));
                    }
                } else {
                    return Err(CompileError::StructNotFound(sname.clone()));
                }
            }
            TypeSpec::BitmapPresence {
                presence_per_block,
                mapping,
                ..
            } => {
                // ... same as before, but ensure we use Skip/Read?
                // Bitmap logic is complex, usually involves control flow.
                // We always execute it to populate presence_checks for optionals.
                // So "should_read" is ignored (always true conceptually).
                // Implementation follows... (pasted previous logic)
                let max_logical = mapping.iter().map(|(bit, _)| *bit).max().unwrap_or(0);
                let ppb = *presence_per_block;
                let num_blocks = if ppb > 0 { (max_logical / ppb) + 1 } else { 1 };

                let mut byte_regs = Vec::new();
                for _ in 0..num_blocks {
                    byte_regs.push(self.alloc_reg());
                }

                let mut exit_labels = Vec::new();
                for i in 0..num_blocks {
                    let reg = byte_regs[i as usize];
                    self.push_op(Op::ReadU8);
                    self.push_op(Op::StoreReg(reg));

                    if i < num_blocks - 1 && ppb > 0 {
                        self.push_op(Op::LoadReg(reg));
                        self.push_op(Op::TestBit(reg, 0));
                        self.push_op(Op::JumpIfEq(0, 0));
                        exit_labels.push(self.ops.len() - 1);
                    }
                }

                let end_idx = self.ops.len();
                for label_idx in exit_labels {
                    let offset = end_idx - label_idx - 1;
                    if let Op::JumpIfEq(val, _) = self.ops[label_idx] {
                        self.ops[label_idx] = Op::JumpIfEq(val, offset as u32);
                    }
                }

                for (logical_bit, field_name) in mapping {
                    let block_idx = if ppb > 0 { logical_bit / ppb } else { 0 };
                    if block_idx < num_blocks {
                        let reg = byte_regs[block_idx as usize];
                        let bit_in_block = if ppb > 0 {
                            logical_bit % ppb
                        } else {
                            *logical_bit
                        };
                        let phys_bit = 7 - bit_in_block;
                        self.presence_checks
                            .insert(field_name.clone(), (reg, phys_bit as u8));
                    }
                }
            }
            TypeSpec::Optional(inner) => {
                // Optional handling:
                // 1. Check dependency (Condition) or presence bit.
                // 2. If present, read.
                // Presence bit logic depends on FSPEC (handled by BitmapPresence logic prior).
                // But we need to know IF we should read it based on presence.
                // Start simple: Check presence_checks map.
                if let Some(&(reg, bit)) = self.presence_checks.get(name) {
                    // Test bit
                    self.push_op(Op::TestBit(reg, bit));
                    // Jump if 0 to skip
                    let jump_idx = self.ops.len();
                    self.push_op(Op::JumpIfEq(0, 0)); // patched later

                    // Compile inner
                    // For Optional, we pass 'should_read' down?
                    // If the field is present, we read it. 'should_read' from analysis applies to whether we keep the value.
                    // But compile_type doesn't take should_read. It always reads.
                    // So if we are here, we read.
                    self.compile_type(inner)?;

                    // Emit constraint check if field has non-saturating constraint
                    // Note: compile_type might have emitted checks for inner struct fields,
                    // but this check is for the Optional field itself (e.g. enum constraint).
                    if let Some(ref constraint) = field.constraint {
                        if !field.saturating {
                            self.emit_constraint_check(constraint)?;
                        }
                    }

                    // Patch jump
                    let end_idx = self.ops.len();
                    let offset = end_idx - jump_idx - 1;
                    self.ops[jump_idx] = Op::JumpIfEq(0, offset as u32);
                } else {
                    // No presence check? Maybe always present or condition logic?
                    // For now, assume if not in map, it's not present or handled differently.
                    // In Cat034, all optional fields are in FSPEC.
                    // Maybe warn?
                    // eprintln!("Warning: No presence check found for optional field {}", name);
                }
            }
            TypeSpec::RepList(inner) => {
                self.push_op(Op::ReadU8);
                let count_reg = self.alloc_reg();
                self.push_op(Op::StoreReg(count_reg));

                self.push_op(Op::LoadReg(count_reg));
                self.push_op(Op::JumpIfEq(0, 0));
                let skip_idx = self.ops.len() - 1;

                let start_idx = self.ops.len();
                self.compile_type(inner)?;
                let body_len = self.ops.len() - start_idx;

                self.push_op(Op::LoopDecNz(count_reg, (body_len + 1) as u32));

                let end_idx = self.ops.len();
                let offset = end_idx - skip_idx - 1;
                if let Op::JumpIfEq(val, _) = self.ops[skip_idx] {
                    self.ops[skip_idx] = Op::JumpIfEq(val, offset as u32);
                }
            }
            TypeSpec::OctetsFx => {
                let tmp = self.alloc_reg();
                let start_idx = self.ops.len();

                self.push_op(Op::ReadU8);
                self.push_op(Op::StoreReg(tmp));

                self.push_op(Op::LoadReg(tmp));
                self.push_op(Op::TestBit(tmp, 0));

                self.push_op(Op::JumpIfEq(0, 0));
                let exit_op_idx = self.ops.len() - 1;

                let jump_back_idx = self.ops.len();
                let offset_back = (jump_back_idx + 1) - start_idx;
                self.push_op(Op::JumpBack(offset_back as u32));

                if let Op::JumpIfEq(val, _) = self.ops[exit_op_idx] {
                    self.ops[exit_op_idx] = Op::JumpIfEq(val, 1);
                }
            }
            _ => return Err(CompileError::Unsupported(format!("{:?}", spec))),
        }
        Ok(())
    }

    fn compile_type(&mut self, spec: &TypeSpec) -> Result<(), CompileError> {
        // Wrapper for anonymous types (inside arrays/lists)
        // For safe default: force Read (should_read=true).
        // Since we don't have a MessageField here, we inline the logic for Base types
        match spec {
            TypeSpec::Base(bt) => {
                self.emit_base_type(bt)?;
                // No register storage for anonymous types
                // No constraint check (anonymous types don't have constraints)
            }
            TypeSpec::SizedInt(bt, _bits) => {
                self.emit_base_type(bt)?;
            }
            TypeSpec::StructRef(sname) => {
                if let Some(s) = self
                    .resolved
                    .protocol
                    .structs
                    .iter()
                    .find(|s| s.name == *sname)
                {
                    let struct_deps = self.analyze_dependencies_struct(s);
                    for f in &s.fields {
                        self.current_context = f.name.clone();
                        let is_needed = struct_deps.contains(&f.name);
                        // Struct fields don't have constraints (Comment removed - they DO)
                        if is_needed {
                            match &f.type_spec {
                                TypeSpec::Base(bt) => {
                                    self.emit_base_type(bt)?;
                                    self.maybe_store_reg(&f.name);
                                    if let Some(ref constraint) = f.constraint {
                                        if !f.saturating {
                                            self.emit_constraint_check(constraint)?;
                                        }
                                    }
                                }
                                _ => {
                                    self.compile_type(&f.type_spec)?;
                                }
                            }
                        } else {
                            // Skip
                            match &f.type_spec {
                                TypeSpec::Base(bt) => {
                                    use BaseType::*;
                                    let size = match bt {
                                        U8 | I8 | Bool => 1,
                                        U16 | I16 => 2,
                                        U32 | I32 | Float => 4,
                                        U64 | I64 | Double => 8,
                                    };
                                    self.push_op(Op::Skip(size));
                                }
                                TypeSpec::SizedInt(_bt, bits) => {
                                    let byte_len = ((bits + 7) / 8) as u32;
                                    self.push_op(Op::Skip(byte_len));
                                }
                                _ => {
                                    self.compile_type(&f.type_spec)?;
                                }
                            }
                        }
                    }
                } else if let Some(e) = self.resolved.get_enum(sname) {
                    // Enum: assume u8 for ASTERIX message types (usually small values)
                    self.emit_base_type(&BaseType::U8)?;

                    // Validate against enum variants
                    let mut valid_values = Vec::new();
                    for (_, lit) in &e.variants {
                        match lit {
                            crate::ast::Literal::Int(v) => valid_values.push(*v),
                            crate::ast::Literal::Hex(v) => valid_values.push(*v as i64),
                            _ => {} // Skip strings/bools for integer enum validation
                        }
                    }
                    if !valid_values.is_empty() {
                        // Optimization: if enum covers all u8 values (0..255), skip check
                        // But enums usually don't.
                        self.push_op(Op::CheckEnum(valid_values));
                    }
                }
            }
            TypeSpec::BitmapPresence {
                presence_per_block,
                mapping,
                ..
            } => {
                // Similar to compile_field logic for BitmapPresence
                let byte_count = if *presence_per_block == 0 {
                    1 // Single byte, no FX
                } else {
                    // Calculate bytes needed based on mapping
                    let max_bits = mapping.iter().map(|(idx, _)| idx).max().unwrap_or(&0) + 1;
                    ((max_bits + presence_per_block) / (presence_per_block + 1)) as usize
                };

                // Read the bitmap bytes
                for _ in 0..byte_count {
                    self.emit_base_type(&BaseType::U8)?;
                }
            }
            TypeSpec::Bitfield(n) => {
                self.push_op(Op::ReadBits(*n as u8));
            }
            TypeSpec::Padding(kind) => {
                match kind {
                    PaddingKind::Bytes(n) => {
                        self.push_op(Op::ZeroBytes(*n as u32));
                    }
                    PaddingKind::Bits(n) => {
                        let mut rem = *n;
                        while rem > 0 {
                            let chunk = std::cmp::min(rem, 255);
                            self.push_op(Op::ZeroBits(chunk as u8));
                            rem -= chunk;
                        }
                    }
                }
            }
            TypeSpec::Optional(inner) => {
                // For anonymous optional types, just compile the inner type
                // Presence checks are handled at the MessageField level
                self.compile_type(inner)?;
            }
            TypeSpec::Array(inner, len) => {
                // Handle arrays in compile_type
                match len {
                    ArrayLen::Constant(n) => {
                        if *n <= 16 {
                            for _ in 0..*n {
                                self.compile_type(inner)?;
                            }
                        } else {
                            return Err(CompileError::Unsupported(
                                "Large fixed arrays not supported yet".into(),
                            ));
                        }
                    }
                    ArrayLen::FieldRef(_) => {
                        // Variable-length arrays need register support, skip for now
                        return Err(CompileError::Unsupported(
                            "Variable-length arrays in compile_type".into(),
                        ));
                    }
                }
            }
            TypeSpec::RepList(inner) => {
                // RepList: read 1-byte REP count, then loop
                self.emit_base_type(&BaseType::U8)?;
                let ctr = self.alloc_reg();
                self.push_op(Op::StoreReg(ctr));

                // Jump to end if count is 0
                // Placeholder for jump offset
                let jump_idx = self.ops.len();
                self.push_op(Op::JumpIfEq(0, 0)); // Will be patched

                let loop_start = self.ops.len();
                self.compile_type(inner)?;

                let loop_end = self.ops.len();
                let loop_len = loop_end - loop_start;

                // LoopDecNz unwraps register, decrements, and jumps back if > 0
                // Op::LoopDecNz(reg, offset_back)
                // Offset back is from *after* the instruction.
                // So if we are at loop_end, we want to jump to loop_start.
                // The LoopDecNz instruction itself is at loop_end.
                // Next PC would be loop_end + 1.
                // We want loop_start.
                // Diff = (loop_end + 1) - loop_start = loop_len + 1.
                self.push_op(Op::LoopDecNz(ctr, (loop_len + 1) as u32));

                // Patch the initial jump over
                // Jump from jump_idx to here (loop_end + 1)
                // jump_idx is at jump_idx.
                // Target is self.ops.len() (which is loop_end + 1).
                // Offset = target - jump_idx - 1 = (loop_end + 1) - jump_idx - 1 = loop_end - jump_idx
                let jump_len = self.ops.len() - 1 - jump_idx;
                self.ops[jump_idx] = Op::JumpIfEq(0, jump_len as u32);
            }
            TypeSpec::List(inner) => {
                // List: variable length, needs external length
                // Can't handle in compile_type without more context
                return Err(CompileError::Unsupported(
                    "List in compile_type (needs length)".into(),
                ));
            }
            TypeSpec::OctetsFx => {
                // Read bytes until MSB (0x80) is 0
                // We need a temp register to test the bit
                let tmp_reg = self.next_reg;
                self.next_reg += 1;

                // Label: Loop Start (index of next MakeOp)
                // 1. Read byte
                self.push_op(Op::ReadU8);
                // 2. Store to temp
                self.push_op(Op::StoreReg(tmp_reg));
                // 3. Test bit 7 (MSB, 0x80)
                self.push_op(Op::TestBit(tmp_reg, 7));
                // 4. If 0 (no extension), jump to end (break)
                // Jump +2 to skip the backward jump
                self.push_op(Op::JumpIfEq(0, 2));
                // 5. Jump back to ReadU8
                // We are at index X. ReadU8 is at X-4.
                // JumpBack is 1 instruction.
                // Current instruction is JumpBack.
                // Count: ReadU8(1), Store(1), Test(1), JumpIf(1), JumpBack(1).
                // Target is start. Offset = 5.
                self.push_op(Op::JumpBack(5));
            }
            TypeSpec::LengthOf(_) | TypeSpec::CountOf(_) | TypeSpec::PresenceBits(_) => {
                // These are special types that should be handled in compile_field
                return Err(CompileError::Unsupported(format!(
                    "Special type {:?} in compile_type",
                    spec
                )));
            }
            _ => {
                return Err(CompileError::Unsupported(format!(
                    "compile_type for {:?}",
                    spec
                )));
            }
        }
        Ok(())
    }

    fn emit_base_type(&mut self, bt: &BaseType) -> Result<(), CompileError> {
        use BaseType::*;
        let op = match bt {
            U8 | I8 | Bool => Op::ReadU8,
            U16 | I16 => Op::ReadU16Be,
            U32 | I32 | Float => Op::ReadU32Be,
            U64 | I64 | Double => {
                return Err(CompileError::Unsupported(
                    "64-bit types not yet supported".into(),
                ))
            }
        };
        self.push_op(op);
        Ok(())
    }

    fn emit_constraint_check(
        &mut self,
        constraint: &crate::ast::Constraint,
    ) -> Result<(), CompileError> {
        use crate::ast::Constraint;
        match constraint {
            Constraint::Range(intervals) => {
                // For simplicity, emit check for first interval only
                // TODO: Support multiple intervals properly
                if let Some((min, max)) = intervals.first() {
                    self.push_op(Op::CheckRange(*min, *max));
                }
            }
            Constraint::Enum(literals) => {
                let values: Vec<i64> = literals.iter().filter_map(|lit| lit.as_i64()).collect();
                self.push_op(Op::CheckEnum(values));
            }
        }
        Ok(())
    }

    fn alloc_reg(&mut self) -> u8 {
        let r = self.next_reg;
        self.next_reg += 1;
        r
    }

    fn maybe_store_reg(&mut self, name: &str) {
        // For prototype: Always store named fields if simple integer.
        // Real impl: check referenced_fields set.
        if name != "_" {
            let reg = self.alloc_reg();
            self.field_regs.insert(name.to_string(), reg);
            self.push_op(Op::StoreReg(reg));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use crate::vm::Machine;

    #[test]
    fn test_compile_simple_struct() {
        let dsl = r#"
            message Simple {
                a: u8;
                b: u16;
                c: u32;
            }
        "#;
        let protocol = parse(dsl).expect("parse");
        let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
        let compiler = Compiler::new(&resolved);
        let prog = compiler.compile("Simple").expect("compile");

        // Verify Program
        // Op::ReadU8, Op::StoreReg(0), Op::ReadU16Be, Op::StoreReg(1), Op::ReadU32Be, Op::StoreReg(2), Op::Ret
        assert_eq!(prog.ops.len(), 7, "Ops: {:?}", prog.ops);

        // Run it
        let data = vec![10u8, 0, 20, 0, 0, 0, 30];
        let mut machine = Machine::new(prog.max_registers);
        let res = machine.run(&data, &prog);
        assert!(res.is_ok());
        assert_eq!(machine.get_reg(0), Some(10));
        assert_eq!(machine.get_reg(1), Some(20));
        assert_eq!(machine.get_reg(2), Some(30));
    }

    #[test]
    fn test_compile_array() {
        let dsl = r#"
            message ArrayMsg {
                len: u8;
                data: u8[len];
            }
        "#;
        let protocol = parse(dsl).expect("parse");
        let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
        let compiler = Compiler::new(&resolved);
        let prog = compiler.compile("ArrayMsg").expect("compile");

        // Ops expected:
        // ReadU8 (len)
        // StoreReg(0) (len)
        // ReadU8 (element)
        // StoreReg(1) (element - inside loop, overwrites)
        // LoopDecNz(0, 2) (jump back to ReadU8 - 2 ops back)
        // Ret

        let data = vec![3, 10, 20, 30];
        let mut machine = Machine::new(prog.max_registers);
        let res = machine.run(&data, &prog);
        assert!(res.is_ok());
        assert_eq!(machine.get_reg(0), Some(0)); // Loop counter exhausted
        assert_eq!(res.unwrap(), 4); // Consumed 1 (len) + 3 (data) bytes
    }

    #[test]
    fn test_compile_bitmap() {
        let dsl = r#"
            message B {
                fspec: bitmap(8, 7) -> (0: a, 1: b);
                a: optional<u8>;
                b: optional<u16>;
            }
        "#;
        let protocol = parse(dsl).expect("parse");
        let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
        let compiler = Compiler::new(&resolved);
        let prog = compiler.compile("B").expect("compile");

        // 1. Case: a present, b absent.
        // FSPEC: logical 0 is bit 7 (MSB). logical 1 is bit 6.
        // 0x80 -> bit 7 set. bit 6 clear. bit 0 (FX) clear.
        let data = vec![0x80, 0xAA];
        let mut machine = Machine::new(prog.max_registers);
        let res = machine.run(&data, &prog);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 2, "Should consume FSPEC + a");

        // 2. Case: a present, b present.
        // 0xC0 -> bit 7 set, bit 6 set.
        // Data: 0xC0, a(0xAA), b(0xBB, 0xCC).
        let data2 = vec![0xC0, 0xAA, 0xBB, 0xCC];
        let mut machine2 = Machine::new(prog.max_registers);
        let res2 = machine2.run(&data2, &prog);
        assert!(res2.is_ok());
        assert_eq!(res2.unwrap(), 4, "Should consume FSPEC + a + b");
    }

    #[test]
    fn dump_cat034_vm_program() {
        let path = std::path::Path::new("grammar.dsl");
        if !path.exists() {
            eprintln!("grammar.dsl not found, skipping dump");
            return;
        }
        let dsl = std::fs::read_to_string(path).expect("read grammar.dsl");
        let protocol = parse(&dsl).expect("parse");
        let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
        let compiler = Compiler::new(&resolved);

        let prog = compiler.compile("Cat034").expect("compile Cat034");

        let mut out = String::new();
        out.push_str("# Cat034 VM Program\n\n");
        out.push_str(&format!("Registers used: {}\n\n", prog.max_registers));
        out.push_str("| PC | Op | Description |\n");
        out.push_str("|:---|:---|:---|\n");

        for (i, op) in prog.ops.iter().enumerate() {
            let desc = match op {
                Op::ReadU8 => "Read 1 byte (u8) to acc".to_string(),
                Op::ReadU16Be => "Read 2 bytes (u16be) to acc".to_string(),
                Op::ReadU32Be => "Read 4 bytes (u32be) to acc".to_string(),
                Op::ReadBytes(n) => format!("Read {} bytes to acc", n),
                Op::Skip(n) => format!("**Skip {} bytes**", n),
                Op::ZeroBytes(n) => format!("**Zero {} bytes**", n),
                Op::StoreReg(r) => format!("Store acc -> reg[{}]", r),
                Op::LoadReg(r) => format!("Load reg[{}] -> acc", r),
                Op::JumpIfEq(v, off) => format!("If acc == {}, jump +{}", v, off),
                Op::JumpIfNe(v, off) => format!("If acc != {}, jump +{}", v, off),
                Op::JumpBack(off) => format!("Jump -{}", off),
                Op::LoopDecNz(r, off) => format!("Dec reg[{}], if > 0 jump -{}", r, off),
                Op::ReadBits(n) => format!("Read {} bits to acc", n),
                Op::Align => "Align to byte boundary".to_string(),
                Op::TestBit(r, b) => format!("acc = (reg[{}] >> {}) & 1", r, b),
                Op::CheckRange(min, max) => format!("**✓ Validate acc ∈ [{}..{}]**", min, max),
                Op::CheckEnum(vals) => format!("**✓ Validate acc ∈ {:?}**", vals),
                Op::Ret => "Return (Success)".to_string(),
                Op::Fail => "Return (Fail)".to_string(),
                _ => format!("{:?}", op),
            };
            out.push_str(&format!("| {} | {:?} | {} |\n", i, op, desc));
        }

        std::fs::write("cat034_vm_program.md", out).expect("write failed");
    }

    #[test]
    fn dump_asterix_vm() {
        let path = std::path::Path::new("examples/asterix_family.dsl");
        if !path.exists() {
            eprintln!("examples/asterix_family.dsl not found, skipping dump");
            return;
        }
        let dsl = std::fs::read_to_string(path).expect("read asterix_family.dsl");
        let protocol = parse(&dsl).expect("parse");
        let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
        let compiler = Compiler::new(&resolved);

        // Try compiling Cat034Record first
        let prog = compiler
            .compile("Cat034Record")
            .expect("compile Cat034Record");

        let mut out = String::new();
        out.push_str("# Asterix Cat034 VM Program\n\n");
        out.push_str(&format!("Registers used: {}\n\n", prog.max_registers));
        out.push_str("| PC | Op | Description |\n");
        out.push_str("|:---|:---|:---|\n");

        for (i, op) in prog.ops.iter().enumerate() {
            let desc = match op {
                Op::ReadU8 => "Read 1 byte (u8) to acc".to_string(),
                Op::ReadU16Be => "Read 2 bytes (u16be) to acc".to_string(),
                Op::ReadU32Be => "Read 4 bytes (u32be) to acc".to_string(),
                Op::ReadBytes(n) => format!("Read {} bytes to acc", n),
                Op::Skip(n) => format!("**Skip {} bytes**", n),
                Op::ZeroBytes(n) => format!("**Zero {} bytes**", n),
                Op::StoreReg(r) => format!("Store acc -> reg[{}]", r),
                Op::LoadReg(r) => format!("Load reg[{}] -> acc", r),
                Op::JumpIfEq(v, off) => format!("If acc == {}, jump +{}", v, off),
                Op::JumpIfNe(v, off) => format!("If acc != {}, jump +{}", v, off),
                Op::JumpBack(off) => format!("Jump -{}", off),
                Op::LoopDecNz(r, off) => format!("Dec reg[{}], if > 0 jump -{}", r, off),
                Op::ReadBits(n) => format!("Read {} bits to acc", n),
                Op::Align => "Align to byte boundary".to_string(),
                Op::TestBit(r, b) => format!("acc = (reg[{}] >> {}) & 1", r, b),
                Op::CheckRange(min, max) => format!("**✓ Validate acc ∈ [{}..{}]**", min, max),
                Op::CheckEnum(vals) => format!("**✓ Validate acc ∈ {:?}**", vals),
                Op::Ret => "Return (Success)".to_string(),
                Op::Fail => "Return (Fail)".to_string(),
                _ => format!("{:?}", op),
            };
            out.push_str(&format!("| {} | {:?} | {} |\n", i, op, desc));
        }

        std::fs::write("asterix_vm_program.md", out).expect("write failed");
    }
}
