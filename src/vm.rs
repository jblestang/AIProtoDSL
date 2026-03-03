//! Bytecode VM for high-performance protocol walking.
//!
//! This module implements a register-based virtual machine that executes linear bytecode
//! instead of recursively walking a tree of TypeSpecs. This eliminates recursion overhead,
//! improves cache locality, and replaces hashmap lookups with array indexing.

use byteorder::{BigEndian, ByteOrder, LittleEndian};

/// Virtual Machine Instructions.
/// Designed to be compact and execute in a tight loop.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    // --- Data Access ---
    /// Read u8, advance 1 byte.
    ReadU8,
    /// Read u16 (Big Endian), advance 2 bytes.
    ReadU16Be,
    /// Read u16 (Little Endian), advance 2 bytes.
    ReadU16Le,
    /// Read u32 (Big Endian), advance 4 bytes.
    ReadU32Be,
    /// Read u32 (Little Endian), advance 4 bytes.
    ReadU32Le,

    // --- Scanning / Skipping ---
    /// Skip N bytes unconditionally.
    Skip(u32),
    /// Read N bytes (store nothing, just advance).
    /// Used for `padding(n)` or fixed blobs.
    ReadBytes(u32),

    // --- Registers ---
    /// Store the last read value into register `reg_id`.
    /// Used for `length_of(x)`, `count_of(x)`, or conditions.
    StoreReg(u8),
    /// Load value from register `reg_id` into the "accumulator" (internal temp).
    LoadReg(u8),

    // --- Control Flow ---
    /// Jump forward by `offset` instructions if the last read value == `val`.
    /// Used for `if x == val`.
    JumpIfEq(i64, u32),
    /// Jump forward by `offset` instructions if the last read value != `val`.
    JumpIfNe(i64, u32),
    /// Jump backward by `offset` instructions unconditionally.
    JumpBack(u32),

    // --- Loops (for lists) ---
    /// Decrement register `reg_id`. If > 0, jump back `offset` instructions.
    /// Used for `list<T>` or `rep_list<T>`.
    LoopDecNz(u8, u32),

    // --- Bit Manipulation (Basic) ---
    /// Read N bits (1-64) into accumulator.
    ReadBits(u8),
    /// Skip N bits.
    SkipBits(u8),
    /// Align to next byte boundary (noop if already aligned).
    Align,
    /// Skip `accumulator * multiplier` bytes.
    // SkipDyn(u32), -- Removed

    /// Test bit `bit` of register `reg`. Set accumulator to 1 if set, 0 if clear.
    TestBit(u8, u8),
    /// Jump forward by `offset` instructions if bit `bit` of register `reg` is set.
    /// Fused `TestBit` + `JumpIfNe(0)`.
    JumpIfBitSet(u8, u8, u32),
    /// Jump forward by `offset` instructions if bit `bit` of register `reg` is clear.
    /// Fused `TestBit` + `JumpIfEq(0)`.
    JumpIfBitClear(u8, u8, u32),
    

    // --- Validation ---
    /// Check that accumulator is in range [min, max] (inclusive). Fail if not.
    /// Used for non-saturating range constraints like `u24 [0..86400]`.
    CheckRange(i64, i64),
    /// Check that accumulator is in the allowed set. Fail if not.
    /// Used for enum constraints like `u8 [1, 2, 4, 8]`.
    CheckEnum(Vec<i64>),

    // --- Lifecycle ---
    /// Write N bytes of zeros (mutable mode only).
    ZeroBytes(u32),
    /// Write N bits of zeros (mutable mode only).
    ZeroBits(u8),

    // --- Lifecycle ---
    /// Stop execution (success).
    Ret,
    /// Fail (validation error).
    Fail,
}

/// A compiled protocol definition.
#[derive(Debug, Clone)]
pub struct Program {
    pub ops: Vec<Op>,
    /// Debug info: name of the field that generated each instruction (1-to-1 with ops).
    pub debug_info: Vec<String>,
    /// How many registers this program uses (so we can pre-allocate).
    pub max_registers: usize,
}

impl Program {
    /// Peephole optimizer:
    /// 1. Dead Code Elimination: Convert unused `Read` ops to `Skip`.
    /// 2. Merge consecutive `Skip` and `ZeroBytes` operations.
    pub fn optimize(&mut self) {
        self.optimize_redundant_moves();
        self.optimize_consecutive_skips();
        self.optimize_dead_reads();
        self.optimize_consecutive_skips();
        self.optimize_dead_reads();
        self.optimize_bit_jumps();
    }

    fn optimize_dead_reads(&mut self) {
        // Pass 1: Dead Read Elimination
        // If a Read operation's result (acc) is unused before being overwritten, convert it to Skip.
        for i in 0..self.ops.len() {
            let op = &self.ops[i];
            let (is_read, skip_op) = match op {
                Op::ReadU8 => (true, Op::Skip(1)),
                Op::ReadU16Be | Op::ReadU16Le => (true, Op::Skip(2)),
                Op::ReadU32Be | Op::ReadU32Le => (true, Op::Skip(4)),
                Op::ReadBits(n) => (true, Op::SkipBits(*n)),
                _ => (false, Op::Skip(0)), // Dummy
            };

            if !is_read {
                continue;
            }

            // Scan forward to check if `acc` is used
            let mut is_unused = true; // Assume unused until proven otherwise
                                      // If we reach end of program without use, it's unused.

            for j in i + 1..self.ops.len() {
                match &self.ops[j] {
                    // Transparent ops: don't use or modify acc
                    Op::Skip(_)
                    | Op::ReadBytes(_)
                    | Op::ZeroBytes(_)
                    | Op::Align
                    | Op::SkipBits(_)
                    | Op::ZeroBits(_)
                    | Op::LoopDecNz(_, _) => continue,

                    // Ops that USE the accumulator
                    Op::StoreReg(_)
                    | Op::CheckRange(_, _)
                    | Op::CheckEnum(_)
                    | Op::JumpIfEq(_, _)
                    | Op::JumpIfNe(_, _) => {
                        is_unused = false;
                        break;
                    }

                    // Ops that OVERWRITE the accumulator (without reading it first)
                    Op::ReadU8
                    | Op::ReadU16Be
                    | Op::ReadU16Le
                    | Op::ReadU32Be
                    | Op::ReadU32Le
                    | Op::ReadBits(_)
                    | Op::LoadReg(_)
                    | Op::TestBit(_, _)
                    | Op::JumpIfBitSet(_, _, _) 
                    | Op::JumpIfBitClear(_, _, _) => {
                        // Overwritten before use! check pass.
                        break;
                    }

                    // Control flow barriers - assume used (conservative)
                    Op::JumpBack(_) | Op::Ret | Op::Fail => {
                        is_unused = false;
                        break;
                    }
                }
            }

            if is_unused {
                self.ops[i] = skip_op;
                if i < self.debug_info.len() {
                    self.debug_info[i].push_str(" (opt: unused)");
                }
            }
        }
    }

    fn optimize_consecutive_skips(&mut self) {
        // Pass 2: Merge consecutive Skips (Bytes and Bits)
        // Map from old_index -> new_index (for target resolution)
        let mut old_to_new = vec![0; self.ops.len() + 1];
        // Map from new_index -> old_index (for source resolution)
        let mut new_to_old = Vec::with_capacity(self.ops.len());

        let mut optimized_ops = Vec::with_capacity(self.ops.len());
        let mut optimized_debug = Vec::with_capacity(self.ops.len());
        let mut i = 0;

        while i < self.ops.len() {
            let start_new_idx = optimized_ops.len();
            let op = &self.ops[i];
            
            // Check if this is a skip op
            // Note: ZeroBytes also behaves like Skip in immutable run
            let is_skip = matches!(op, Op::Skip(_) | Op::SkipBits(_));

            if is_skip {
                // Start accumulating bits
                let mut total_bits: u64 = 0;
                let start_debug = self.debug_info[i].clone();
                let mut merged_count = 0;

                let mut j = i;
                while j < self.ops.len() {
                    match &self.ops[j] {
                        Op::Skip(n) => {
                            total_bits += *n as u64 * 8;
                            merged_count += 1;
                            old_to_new[j] = start_new_idx;
                            j += 1;
                        }
                        Op::SkipBits(n) => {
                            total_bits += *n as u64;
                            merged_count += 1;
                            old_to_new[j] = start_new_idx;
                            j += 1;
                        }
                        _ => break,
                    }
                }

                // Regenerate optimal sequence
                let bytes = total_bits / 8;
                let rem_bits = (total_bits % 8) as u8;

                let debug_msg = if merged_count > 1 {
                    format!("{} (merged {} ops)", start_debug, merged_count)
                } else {
                    start_debug
                };
                
                if total_bits > 0 {
                    if rem_bits == 0 {
                         optimized_ops.push(Op::Skip(bytes as u32));
                         optimized_debug.push(debug_msg.clone());
                         new_to_old.push(i);
                    } else if total_bits <= 255 {
                         optimized_ops.push(Op::SkipBits(total_bits as u8));
                         optimized_debug.push(debug_msg.clone());
                         new_to_old.push(i);
                    } else {
                        if bytes > 0 {
                            optimized_ops.push(Op::Skip(bytes as u32));
                            optimized_debug.push(debug_msg.clone());
                            new_to_old.push(i);
                        }
                        if rem_bits > 0 {
                            optimized_ops.push(Op::SkipBits(rem_bits));
                            optimized_debug.push(debug_msg.clone());
                            // Map second part to start as well
                            new_to_old.push(i); 
                        }
                    }
                }

                i = j;
            } else if let Op::ZeroBytes(n1) = op {
                let mut total = *n1;
                let debug = self.debug_info[i].clone();
                let mut j = i;
                
                // First pass: scan to find total
                 let mut k = i + 1;
                 while k < self.ops.len() {
                    if let Op::ZeroBytes(n2) = &self.ops[k] {
                        total += n2;
                        k += 1;
                    } else {
                        break;
                    }
                }
                
                // Second pass: map indices
                while j < k {
                    old_to_new[j] = start_new_idx;
                    j += 1;
                }

                optimized_ops.push(Op::ZeroBytes(total));
                if k > i + 1 {
                    optimized_debug.push(format!("{} (merged {} ops)", debug, k - i));
                } else {
                    optimized_debug.push(debug);
                }
                new_to_old.push(i);
                i = k;
            } else {
                old_to_new[i] = start_new_idx;
                optimized_ops.push(self.ops[i].clone());
                optimized_debug.push(self.debug_info[i].clone());
                new_to_old.push(i);
                i += 1;
            }
        }
        
        // Map end sentinel
        old_to_new[self.ops.len()] = optimized_ops.len();

        // Pass 3: Fixup Jumps
        for (new_idx, op) in optimized_ops.iter_mut().enumerate() {
            let old_idx = new_to_old[new_idx];
            
            match op {
                Op::JumpIfEq(_, offset) | Op::JumpIfNe(_, offset) => {
                    // Forward jump: target = old_idx + 1 + old_offset
                    let old_next = old_idx + 1;
                    if old_next + (*offset as usize) <= self.ops.len() {
                         let old_target = old_next + (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_target >= new_next {
                             *offset = (new_target - new_next) as u32;
                         } else {
                             *offset = 0;
                         }
                    }
                }
                Op::JumpBack(offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                Op::LoopDecNz(_, offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                _ => {}
            }
        }

        self.ops = optimized_ops;
        self.debug_info = optimized_debug;
    }

    fn optimize_redundant_moves(&mut self) {
        // Remove LoadReg(r) if immediately preceded by StoreReg(r),
        // PROVIDED that LoadReg is not a jump target.

        // Step 1: Identify all jump targets
        let mut jump_targets = std::collections::HashSet::new();
        for (idx, op) in self.ops.iter().enumerate() {
            match op {
                Op::JumpIfEq(_, off) | Op::JumpIfNe(_, off) => {
                    let target = idx + 1 + *off as usize;
                    if target < self.ops.len() {
                        jump_targets.insert(target);
                    }
                }
                Op::JumpBack(off) => {
                     let next_pc = idx + 1;
                     if next_pc >= *off as usize {
                         jump_targets.insert(next_pc - *off as usize);
                     }
                }
                Op::LoopDecNz(_, off) => {
                     let next_pc = idx + 1;
                     if next_pc >= *off as usize {
                         jump_targets.insert(next_pc - *off as usize);
                     }
                }
                _ => {}
            }
        }

        // Step 2: Rewrite ops
        let mut optimized_ops = Vec::with_capacity(self.ops.len());
        let mut optimized_debug = Vec::with_capacity(self.ops.len());
        
        let mut old_to_new = vec![0; self.ops.len() + 1];
        let mut new_to_old = Vec::with_capacity(self.ops.len());

        let mut i = 0;
        while i < self.ops.len() {
            let start_new_idx = optimized_ops.len();
            old_to_new[i] = start_new_idx;
            
            // Pattern: StoreReg(r) @ i, LoadReg(r) @ i+1
            let mut removed = false;
            if i + 1 < self.ops.len() {
                if let Op::StoreReg(r1) = &self.ops[i] {
                    if let Op::LoadReg(r2) = &self.ops[i + 1] {
                        if r1 == r2 {
                            // Check if i+1 is a jump target
                            if !jump_targets.contains(&(i + 1)) {
                                // Safe to remove i+1
                                
                                // Push StoreReg
                                optimized_ops.push(self.ops[i].clone());
                                optimized_debug.push(self.debug_info[i].clone());
                                new_to_old.push(i);
                                
                                // Skip LoadReg
                                // Map i+1 to start_new_idx + 1 (next instruction)
                                // or to start_new_idx (current StoreReg)?
                                // If something jumps to i+1 (Load), we said it's forbidden.
                                // But mapping should be robust.
                                // If we remove it, it maps to the *next* instruction (index i+2 maps to start_new_idx + 1).
                                // old_to_new[i+1] = ???
                                // Usually we map removed instructions to the *next* valid one.
                                // So old_to_new[i+1] should be start_new_idx + 1?
                                // Let's leave it for the next loop iteration to handle i+2?
                                // No, we skip i+1.
                                
                                // old_to_new[i] = start_new_idx (Set above)
                                
                                i += 2;
                                removed = true;
                                
                                // We need to handle mapping for the skipped instruction.
                                // Iterate backwards? No.
                                // Just set old_to_new[i+1] later?
                                // old_to_new[original_i + 1] = start_new_idx + 1;
                                // Since we advanced i by 2, the loop logic will process i (which is old i+2) next.
                                // So old_to_new[old_i+2] = start_new_idx + 1. Correct.
                                // But what about old_to_new[old_i+1]?
                                // It maps to start_new_idx + 1 as well (as if it was replaced by NOP or skipped).
                                old_to_new[i - 1] = start_new_idx + 1; 
                            }
                        }
                    }
                }
            }
            
            if !removed {
                optimized_ops.push(self.ops[i].clone());
                optimized_debug.push(self.debug_info[i].clone());
                new_to_old.push(i);
                i += 1;
            }
        }
        old_to_new[self.ops.len()] = optimized_ops.len();
        
        // Pass 3: Fixup Jumps
         for (new_idx, op) in optimized_ops.iter_mut().enumerate() {
            let old_idx = new_to_old[new_idx];
            
            match op {
                Op::JumpIfEq(_, offset) | Op::JumpIfNe(_, offset) 
                | Op::JumpIfBitSet(_, _, offset) | Op::JumpIfBitClear(_, _, offset) => {
                    let old_next = old_idx + 1;
                    if old_next + (*offset as usize) <= self.ops.len() {
                         let old_target = old_next + (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_target >= new_next {
                             *offset = (new_target - new_next) as u32;
                         } else {
                             *offset = 0;
                         }
                    }
                }
                Op::JumpBack(offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                Op::LoopDecNz(_, offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                _ => {}
            }
        }

        self.ops = optimized_ops;
        self.debug_info = optimized_debug;
    }

    fn optimize_bit_jumps(&mut self) {
        // Fuse TestBit(reg, bit) + JumpIfEq/Ne(0/1, off) -> JumpIfBitSet/Clear.
        // PROVIDED that Jump is not a jump target.

        // Step 1: Identify all jump targets
        let mut jump_targets = std::collections::HashSet::new();
        for (idx, op) in self.ops.iter().enumerate() {
            match op {
                Op::JumpIfEq(_, off) | Op::JumpIfNe(_, off) 
                | Op::JumpIfBitSet(_, _, off) | Op::JumpIfBitClear(_, _, off) => {
                    let target = idx + 1 + *off as usize;
                    if target < self.ops.len() {
                        jump_targets.insert(target);
                    }
                }
                Op::JumpBack(off) => {
                     let next_pc = idx + 1;
                     if next_pc >= *off as usize {
                         jump_targets.insert(next_pc - *off as usize);
                     }
                }
                Op::LoopDecNz(_, off) => {
                     let next_pc = idx + 1;
                     if next_pc >= *off as usize {
                         jump_targets.insert(next_pc - *off as usize);
                     }
                }
                _ => {}
            }
        }

        // Step 2: Rewrite ops
        let mut optimized_ops = Vec::with_capacity(self.ops.len());
        let mut optimized_debug = Vec::with_capacity(self.ops.len());
        
        let mut old_to_new = vec![0; self.ops.len() + 1];
        let mut new_to_old = Vec::with_capacity(self.ops.len());

        let mut i = 0;
        while i < self.ops.len() {
            let start_new_idx = optimized_ops.len();
            old_to_new[i] = start_new_idx;
            
            let mut fused = false;
            
            if i + 1 < self.ops.len() {
                if let Op::TestBit(reg, bit) = &self.ops[i] {
                    // Check next op
                    if !jump_targets.contains(&(i + 1)) {
                         match &self.ops[i+1] {
                             Op::JumpIfEq(val, off) => {
                                 // Eq(0) -> Clear. Eq(1) -> Set.
                                 if *val == 0 {
                                     optimized_ops.push(Op::JumpIfBitClear(*reg, *bit, *off));
                                     optimized_debug.push(format!("Fused TestBit+JumpIfEq(0)"));
                                     fused = true;
                                 } else if *val == 1 {
                                     optimized_ops.push(Op::JumpIfBitSet(*reg, *bit, *off));
                                     optimized_debug.push(format!("Fused TestBit+JumpIfEq(1)"));
                                     fused = true;
                                 }
                             }
                             Op::JumpIfNe(val, off) => {
                                 // Ne(0) -> Set. Ne(1) -> Clear.
                                 if *val == 0 {
                                     optimized_ops.push(Op::JumpIfBitSet(*reg, *bit, *off));
                                     optimized_debug.push(format!("Fused TestBit+JumpIfNe(0)"));
                                     fused = true;
                                 } else if *val == 1 {
                                     optimized_ops.push(Op::JumpIfBitClear(*reg, *bit, *off));
                                     optimized_debug.push(format!("Fused TestBit+JumpIfNe(1)"));
                                     fused = true;
                                 }
                             }
                             _ => {}
                         }
                         
                         if fused {
                             new_to_old.push(i);
                             // Skip Jump
                             old_to_new[i+1] = start_new_idx + 1; // Map to next
                             i += 2;
                         }
                    }
                }
            }
            
            if !fused {
                optimized_ops.push(self.ops[i].clone());
                optimized_debug.push(self.debug_info[i].clone());
                new_to_old.push(i);
                i += 1;
            }
        }
        old_to_new[self.ops.len()] = optimized_ops.len();
        
        // Pass 3: Fixup Jumps
         for (new_idx, op) in optimized_ops.iter_mut().enumerate() {
            let old_idx = new_to_old[new_idx];
            
            match op {
                Op::JumpIfEq(_, offset) | Op::JumpIfNe(_, offset) 
                | Op::JumpIfBitSet(_, _, offset) | Op::JumpIfBitClear(_, _, offset) => {
                    let old_next = old_idx + 1;
                    if old_next + (*offset as usize) <= self.ops.len() {
                         let old_target = old_next + (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_target >= new_next {
                             *offset = (new_target - new_next) as u32;
                         } else {
                             *offset = 0;
                         }
                    }
                }
                Op::JumpBack(offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                Op::LoopDecNz(_, offset) => {
                     let old_next = old_idx + 1;
                     if old_next >= (*offset as usize) {
                         let old_target = old_next - (*offset as usize);
                         let new_target = old_to_new[old_target];
                         let new_next = new_idx + 1;
                         
                         if new_next >= new_target {
                             *offset = (new_next - new_target) as u32;
                         } else {
                             *offset = 0;
                         }
                     }
                }
                _ => {}
            }
        }

        self.ops = optimized_ops;
        self.debug_info = optimized_debug;
    }
}

#[derive(Debug)]
pub enum VmError {
    UnexpectedEof,
    Validation,
    ConstraintViolation(String),
    InvalidOp,
}

/// Run the program on the data.
/// Returns the number of bytes consumed on success.
pub struct Machine {
    regs: Vec<u64>,
}

impl Machine {
    pub fn new(max_regs: usize) -> Self {
        Self {
            regs: vec![0; max_regs],
        }
    }

    pub fn get_reg(&self, idx: usize) -> Option<u64> {
        self.regs.get(idx).copied()
    }

    /// Read-only run: executes program but `ZeroBytes` acts like `Skip`.
    pub fn run(&mut self, data: &[u8], prog: &Program) -> Result<usize, VmError> {
        self.run_inner(data, prog, false)
    }

    /// Mutable run: executes program and performs writes (e.g. `ZeroBytes`).
    /// Note: This is an unsafe workaround to reuse the same inner loop logic for both `&[u8]` and `&mut [u8]`.
    /// We cast `&mut [u8]` to `&[u8]` for the inner loop, and use `ptr::write` for mutation if `mutable` is true.
    /// A cleaner Rusty way would be two separate functions or a macro, but this avoids code duplication.
    pub fn run_mut(&mut self, data: &mut [u8], prog: &Program) -> Result<usize, VmError> {
        // SAFETY: We have exclusive access to data via &mut. We effectively hold a mutable ptr to it.
        // The inner loop only writes if `mutable` is true.
        // We pass the slice as immutable to inner, but we keep the mutable pointer to write.
        let ptr = data.as_mut_ptr();
        // Run inner logic.
        self.run_inner(
            unsafe { std::slice::from_raw_parts(ptr, data.len()) },
            prog,
            true,
        )
    }

    // Unified runner using raw pointers to allow mutation if enabled.
    fn run_inner_mut(
        &mut self,
        data_ptr: *mut u8,
        data_len: usize,
        prog: &Program,
    ) -> Result<usize, VmError> {
        let mut pos = 0usize;
        let mut acc = 0u64;
        let mut bit_pos = 0u8;
        let mut pc = 0;
        let ops = &prog.ops;

        // Ensure registers are sufficient size
        if self.regs.len() < prog.max_registers {
            self.regs.resize(prog.max_registers, 0);
        }
        self.regs.fill(0);

        while pc < ops.len() {
            let op = unsafe { ops.get_unchecked(pc) };
            pc += 1;

            match op {
                Op::ReadU8 => {
                    if pos >= data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = unsafe { *data_ptr.add(pos) } as u64;
                    pos += 1;
                }
                Op::ReadU16Be => {
                    if pos + 2 > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = unsafe {
                        let slice = std::slice::from_raw_parts(data_ptr.add(pos), 2);
                        BigEndian::read_u16(slice) as u64
                    };
                    pos += 2;
                }
                Op::ReadU16Le => {
                    if pos + 2 > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = unsafe {
                        let slice = std::slice::from_raw_parts(data_ptr.add(pos), 2);
                        LittleEndian::read_u16(slice) as u64
                    };
                    pos += 2;
                }
                Op::ReadU32Be => {
                    if pos + 4 > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = unsafe {
                        let slice = std::slice::from_raw_parts(data_ptr.add(pos), 4);
                        BigEndian::read_u32(slice) as u64
                    };
                    pos += 4;
                }
                Op::ReadU32Le => {
                    if pos + 4 > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = unsafe {
                        let slice = std::slice::from_raw_parts(data_ptr.add(pos), 4);
                        LittleEndian::read_u32(slice) as u64
                    };
                    pos += 4;
                }
                Op::Skip(n) => {
                    if pos + *n as usize > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    pos += *n as usize;
                }
                Op::ReadBytes(n) => {
                    if pos + *n as usize > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    pos += *n as usize;
                }
                Op::ZeroBytes(n) => {
                    let len = *n as usize;
                    if pos + len > data_len {
                        return Err(VmError::UnexpectedEof);
                    }
                    // Write zeros if we are in mutable mode (implied by run_mut calling this)
                    unsafe {
                        std::ptr::write_bytes(data_ptr.add(pos), 0, len);
                    }
                    pos += len;
                }
                Op::ZeroBits(n) => {
                    let n = *n as usize;
                    if n > 0 {
                         let total_bits = bit_pos as usize + n;
                         // Check bounds
                         let last_byte_idx = pos + (total_bits - 1) / 8;
                         if last_byte_idx >= data_len {
                             return Err(VmError::UnexpectedEof);
                         }

                         // Clear bits
                         // Simple bit-by-bit impl for safety and correctness with LSB-first assumption
                         // congruent with ReadBits impl.
                         for _ in 0..n {
                             unsafe {
                                 let ptr = data_ptr.add(pos);
                                 *ptr &= !(1 << bit_pos);
                             }
                             bit_pos += 1;
                             if bit_pos == 8 {
                                 pos += 1;
                                 bit_pos = 0;
                             }
                         }
                    }
                }
                Op::StoreReg(idx) => {
                    self.regs[*idx as usize] = acc;
                }
                Op::LoadReg(idx) => {
                    acc = self.regs[*idx as usize];
                }
                Op::JumpIfEq(val, offset) => {
                    if acc as i64 == *val {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfNe(val, offset) => {
                    if acc as i64 != *val {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfBitSet(reg, bit, offset) => {
                    let r = self.regs[*reg as usize];
                    let val = (r >> bit) & 1;
                    acc = val;
                    if val == 1 {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfBitClear(reg, bit, offset) => {
                    let r = self.regs[*reg as usize];
                    let val = (r >> bit) & 1;
                    acc = val;
                    if val == 0 {
                        pc += *offset as usize;
                    }
                }
                Op::JumpBack(offset) => {
                    pc -= *offset as usize;
                }
                Op::LoopDecNz(reg, offset) => {
                    let r = &mut self.regs[*reg as usize];
                    if *r > 0 {
                        *r -= 1;
                        if *r > 0 {
                            pc -= *offset as usize;
                        }
                    }
                }
                Op::ReadBits(n) => {
                    let mut val = 0u64;
                    for i in 0..*n {
                        if pos >= data_len {
                            return Err(VmError::UnexpectedEof);
                        }
                        let b = unsafe { *data_ptr.add(pos) };
                        let bit = (b >> bit_pos) & 1;
                        val |= (bit as u64) << i;
                        bit_pos += 1;
                        if bit_pos == 8 {
                            pos += 1;
                            bit_pos = 0;
                        }
                    }
                    acc = val;
                }
                Op::SkipBits(n) => {
                    if *n != 0 {
                        let total_bits = bit_pos as usize + *n as usize;
                        let bytes_adv = total_bits / 8;
                        let new_bit_pos = (total_bits % 8) as u8;

                        let last_byte_idx = pos + (total_bits - 1) / 8;
                        if last_byte_idx >= data_len {
                            return Err(VmError::UnexpectedEof);
                        }

                        pos += bytes_adv;
                        bit_pos = new_bit_pos;
                    }
                }
                Op::Align => {
                    if bit_pos != 0 {
                        pos += 1;
                        bit_pos = 0;
                    }
                }
                Op::TestBit(reg, bit) => {
                    let r = self.regs[*reg as usize];
                    acc = (r >> bit) & 1;
                }
                Op::CheckRange(min, max) => {
                    let val = acc as i64;
                    if val < *min || val > *max {
                        return Err(VmError::ConstraintViolation(format!(
                            "value {} not in range [{}..{}]",
                            val, min, max
                        )));
                    }
                }
                Op::CheckEnum(ref allowed) => {
                    let val = acc as i64;
                    if !allowed.contains(&val) {
                        return Err(VmError::ConstraintViolation(format!(
                            "value {} not in allowed set {:?}",
                            val, allowed
                        )));
                    }
                }
                Op::Ret => return Ok(pos),
                Op::Fail => return Err(VmError::Validation),
            }
        }
        Ok(pos)
    }

    fn run_inner(&mut self, data: &[u8], prog: &Program, mutable: bool) -> Result<usize, VmError> {
        // Fallback for immutable run reusing code structure?
        // Actually, let's keep the original run simple and safe, and use the ptr version only for run_mut.
        // Duplication is better than unsafe hacking for the immutable case.
        // BUT, to avoid huge diff, I will paste the original `run` body as `run_inner` (immutable)
        // and have `run_mut` use unsafe ptr.
        // To save space/complexity in this tool call, I will rewrite `run` to be the immutable version (as it was)
        // plus `ZeroBytes` handling (as skip). And `run_mut` as the unsafe version.

        let mut pos = 0usize;
        let mut acc = 0u64;
        let mut bit_pos = 0u8;
        let mut pc = 0;
        let ops = &prog.ops;

        if self.regs.len() < prog.max_registers {
            self.regs.resize(prog.max_registers, 0);
        }
        self.regs.fill(0);

        while pc < ops.len() {
            let op = unsafe { ops.get_unchecked(pc) };
            pc += 1;

            match op {
                Op::ReadU8 => {
                    if pos >= data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = data[pos] as u64;
                    pos += 1;
                }
                Op::ReadU16Be => {
                    if pos + 2 > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = BigEndian::read_u16(&data[pos..]) as u64;
                    pos += 2;
                }
                Op::ReadU16Le => {
                    if pos + 2 > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = LittleEndian::read_u16(&data[pos..]) as u64;
                    pos += 2;
                }
                Op::ReadU32Be => {
                    if pos + 4 > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = BigEndian::read_u32(&data[pos..]) as u64;
                    pos += 4;
                }
                Op::ReadU32Le => {
                    if pos + 4 > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    acc = LittleEndian::read_u32(&data[pos..]) as u64;
                    pos += 4;
                }
                Op::Skip(n) => {
                    if pos + *n as usize > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    pos += *n as usize;
                }
                Op::ReadBytes(n) => {
                    if pos + *n as usize > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    pos += *n as usize;
                }
                Op::ZeroBytes(n) => {
                    if pos + *n as usize > data.len() {
                        return Err(VmError::UnexpectedEof);
                    }
                    pos += *n as usize;
                }
                Op::ZeroBits(n) => {
                    // Immutable run: treats ZeroBits as SkipBits
                    if *n != 0 {
                        let total_bits = bit_pos as usize + *n as usize;
                        let bytes_adv = total_bits / 8;
                        let new_bit_pos = (total_bits % 8) as u8;

                        let last_byte_idx = pos + (total_bits - 1) / 8;
                        if last_byte_idx >= data.len() {
                            return Err(VmError::UnexpectedEof);
                        }

                        pos += bytes_adv;
                        bit_pos = new_bit_pos;
                    }
                }
                Op::StoreReg(idx) => {
                    self.regs[*idx as usize] = acc;
                }
                Op::LoadReg(idx) => {
                    acc = self.regs[*idx as usize];
                }
                Op::JumpIfEq(val, offset) => {
                    if acc as i64 == *val {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfNe(val, offset) => {
                    if acc as i64 != *val {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfBitSet(reg, bit, offset) => {
                    let r = self.regs[*reg as usize];
                    let val = (r >> bit) & 1;
                    acc = val;
                    if val == 1 {
                        pc += *offset as usize;
                    }
                }
                Op::JumpIfBitClear(reg, bit, offset) => {
                    let r = self.regs[*reg as usize];
                    let val = (r >> bit) & 1;
                    acc = val;
                    if val == 0 {
                        pc += *offset as usize;
                    }
                }
                Op::JumpBack(offset) => {
                    pc -= *offset as usize;
                }
                Op::LoopDecNz(reg, offset) => {
                    let r = &mut self.regs[*reg as usize];
                    if *r > 0 {
                        *r -= 1;
                        if *r > 0 {
                            pc -= *offset as usize;
                        }
                    }
                }
                Op::ReadBits(n) => {
                    let mut val = 0u64;
                    for i in 0..*n {
                        if pos >= data.len() {
                            return Err(VmError::UnexpectedEof);
                        }
                        let bit = (data[pos] >> bit_pos) & 1;
                        val |= (bit as u64) << i;
                        bit_pos += 1;
                        if bit_pos == 8 {
                            pos += 1;
                            bit_pos = 0;
                        }
                    }
                    acc = val;
                }
                Op::SkipBits(n) => {
                    if *n != 0 {
                        let total_bits = bit_pos as usize + *n as usize;
                        let bytes_adv = total_bits / 8;
                        let new_bit_pos = (total_bits % 8) as u8;

                        let last_byte_idx = pos + (total_bits - 1) / 8;
                        if last_byte_idx >= data.len() {
                            return Err(VmError::UnexpectedEof);
                        }

                        pos += bytes_adv;
                        bit_pos = new_bit_pos;
                    }
                }
                Op::Align => {
                    if bit_pos != 0 {
                        pos += 1;
                        bit_pos = 0;
                    }
                }
                Op::TestBit(reg, bit) => {
                    let r = self.regs[*reg as usize];
                    acc = (r >> bit) & 1;
                }
                Op::CheckRange(min, max) => {
                    let val = acc as i64;
                    if val < *min || val > *max {
                        return Err(VmError::ConstraintViolation(format!(
                            "value {} not in range [{}..{}]",
                            val, min, max
                        )));
                    }
                }
                Op::CheckEnum(ref allowed) => {
                    let val = acc as i64;
                    if !allowed.contains(&val) {
                        return Err(VmError::ConstraintViolation(format!(
                            "value {} not in allowed set {:?}",
                            val, allowed
                        )));
                    }
                }
                Op::Ret => return Ok(pos),
                Op::Fail => return Err(VmError::Validation),
            }
        }
        Ok(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_basic() {
        // Data: u8(10), u16(2000), u32(100_000)
        let mut data = vec![10u8];
        data.extend_from_slice(&2000u16.to_be_bytes());
        data.extend_from_slice(&100_000u32.to_be_bytes());

        let prog = Program {
            ops: vec![
                Op::ReadU8,
                Op::StoreReg(0), // Reg[0] = 10
                Op::ReadU16Be,
                Op::StoreReg(1), // Reg[1] = 2000
                Op::ReadU32Be,
                Op::StoreReg(2), // Reg[2] = 100_000
                Op::Ret,
            ],
            debug_info: vec![],
            max_registers: 3,
        };

        let mut machine = Machine::new(prog.max_registers);
        let res = machine.run(&data, &prog);

        assert!(res.is_ok());
        assert_eq!(machine.regs[0], 10);
        assert_eq!(machine.regs[1], 2000);
        assert_eq!(machine.regs[2], 100_000);
        assert_eq!(res.unwrap(), 7);
    }

    #[test]
    fn test_vm_loop() {
        // List length = 3. Items = [1, 2, 3]
        let mut data = vec![3u8, 1, 2, 3];

        let prog = Program {
            ops: vec![
                Op::ReadU8, // Read 3
                Op::StoreReg(0),
                Op::ReadU8,          // Read Item
                Op::StoreReg(1),     // Validates we read (last one will be 3)
                Op::LoopDecNz(0, 3), // Jump back 3 instructions (to ReadU8)
                Op::Ret,
            ],
            debug_info: vec![],
            max_registers: 2,
        };

        let mut machine = Machine::new(prog.max_registers);
        let res = machine.run(&data, &prog);

        assert!(res.is_ok());
        assert_eq!(machine.regs[0], 0); // Loop counter exhausted
        assert_eq!(machine.regs[1], 3); // Last item
        assert_eq!(res.unwrap(), 4);
    }

    #[test]
    fn test_optimize_dead_read_in_loop() {
        // Reg 0 = count. Loop 3 times.
        // Body: ReadU8 (result unused).
        // After loop: ReadU8 (overwrites acc contextually, though we need to be careful).
        
        // Ops expected:
        // 0: ReadU8
        // 1: StoreReg(0)
        // 2: ReadU8 -> Should optimize to Skip(1) because next op is LoopDecNz (transparent) -> ReadU16Be (Overwrites)
        // 3: LoopDecNz
        // 4: ReadU16Be
        // 5: Ret
        
        let mut prog = Program {
            ops: vec![
                Op::ReadU8, // count
                Op::StoreReg(0),
                // Loop Start
                Op::ReadU8,          // Item (should become Skip(1))
                Op::LoopDecNz(0, 2), // Jump back 2 (to ReadU8)
                // Loop End
                Op::ReadU16Be, // Post-loop (overwrites acc)
                Op::Ret,
            ],
            debug_info: vec![
                "count".to_string(),
                "store".to_string(),
                "item".to_string(),
                "loop".to_string(),
                "post".to_string(),
                "ret".to_string(),
            ],
            max_registers: 1,
        };

        prog.optimize();

        // Check that item ReadU8 became Skip(1)
        // Ops: ReadU8, StoreReg, Skip(1), LoopDecNz, ReadU16Be, Ret
        // Index 2 should be Skip(1)
        if let Op::Skip(n) = prog.ops[2] {
            assert_eq!(n, 1);
        } else {
            panic!("Expected Op::Skip(1) at index 2, got {:?}", prog.ops[2]);
        }
    }

    #[test]
    fn test_optimize_consecutive_skips_combinations() {
        // Test various combinations of consecutive skip operations
        struct TestCase {
            name: &'static str,
            input: Vec<Op>,
            expected: Vec<Op>,
        }

        let cases = vec![
            TestCase {
                name: "Skip(1) + Skip(2) -> Skip(3)",
                input: vec![Op::Skip(1), Op::Skip(2)],
                expected: vec![Op::Skip(3)],
            },
            TestCase {
                name: "SkipBits(2) + SkipBits(5) -> SkipBits(7)",
                input: vec![Op::SkipBits(2), Op::SkipBits(5)],
                expected: vec![Op::SkipBits(7)],
            },
            TestCase {
                name: "SkipBits(4) + SkipBits(4) -> Skip(1)",
                input: vec![Op::SkipBits(4), Op::SkipBits(4)],
                expected: vec![Op::Skip(1)],
            },
            TestCase {
                name: "Skip(1) + SkipBits(2) -> SkipBits(10)",
                input: vec![Op::Skip(1), Op::SkipBits(2)],
                expected: vec![Op::SkipBits(10)],
            },
            TestCase {
                name: "SkipBits(2) + Skip(1) -> SkipBits(10)",
                input: vec![Op::SkipBits(2), Op::Skip(1)],
                expected: vec![Op::SkipBits(10)],
            },
            TestCase {
                name: "Mixed Sequence -> Skip(4)",
                input: vec![Op::Skip(1), Op::SkipBits(4), Op::Skip(1), Op::SkipBits(12)],
                expected: vec![Op::Skip(4)],
            },
            TestCase {
                // Large bits: SkipBits(7) * 3 = 21 bits. Fits in u8.
                name: "Multiple small SkipBits -> SkipBits(21)",
                input: vec![Op::SkipBits(7), Op::SkipBits(7), Op::SkipBits(7)],
                expected: vec![Op::SkipBits(21)],
            },
            TestCase {
                // Interrupted by non-skip op
                name: "Interrupted Sequence",
                input: vec![Op::Skip(1), Op::ReadU8, Op::Skip(2)],
                expected: vec![Op::Skip(1), Op::ReadU8, Op::Skip(2)],
            },
        ];

        for case in cases {
            let mut prog = Program {
                ops: case.input.clone(),
                // Generate dummy debug info
                debug_info: case.input.iter().map(|_| "test".to_string()).collect(),
                max_registers: 0,
            };

            prog.optimize_consecutive_skips();

            assert_eq!(
                prog.ops, case.expected,
                "Test case '{}' failed. \nExpected: {:?}\nGot:      {:?}",
                case.name, case.expected, prog.ops
            );
        }
    }

    #[test]
    fn test_optimize_consecutive_skips_with_jumps() {
        let input = vec![
            Op::JumpIfEq(0, 3), // Jumps to Ret. offset=3 lands on Ret (index 4) if pc starts at 1.
            Op::Skip(1),
            Op::Skip(1),
            Op::ReadU8,
            Op::Ret,
        ];

        let mut prog = Program {
            ops: input,
            debug_info: vec![
                "jump".into(),
                "skip1".into(),
                "skip2".into(),
                "read".into(),
                "ret".into(),
            ],
            max_registers: 1,
        };

        prog.optimize_consecutive_skips();

        // Expected if fixed:
        // Op 0: JumpIfEq(0, 2)
        // Op 1: Skip(2)
        // Op 2: ReadU8
        // Op 3: Ret
        let expected = vec![Op::JumpIfEq(0, 2), Op::Skip(2), Op::ReadU8, Op::Ret];

        assert_eq!(prog.ops, expected);
    }

    #[test]
    fn test_optimize_redundant_moves() {
        // Case 1: Redundant Load (StoreReg(0), LoadReg(0)) -> Remove LoadReg
        let input1 = vec![
            Op::StoreReg(0),
            Op::LoadReg(0),
            Op::Ret,
        ];
        let mut prog1 = Program {
            ops: input1,
            debug_info: vec!["store".into(), "load".into(), "ret".into()],
            max_registers: 1,
        };
        prog1.optimize_redundant_moves();
        assert_eq!(prog1.ops, vec![Op::StoreReg(0), Op::Ret]);

        // Case 2: Different Registers (StoreReg(0), LoadReg(1)) -> Keep
        let input2 = vec![
            Op::StoreReg(0),
            Op::LoadReg(1),
            Op::Ret,
        ];
        let mut prog2 = Program {
            ops: input2,
            debug_info: vec!["store".into(), "load".into(), "ret".into()],
            max_registers: 2,
        };
        prog2.optimize_redundant_moves();
        assert_eq!(prog2.ops, vec![Op::StoreReg(0), Op::LoadReg(1), Op::Ret]);

        // Case 3: LoadReg is Jump Target -> Keep
        // JumpIfEq(0, 1) skips StoreReg, lands on LoadReg (index 2)
        // Op 0: JumpIfEq(0, 1)
        // Op 1: StoreReg(0)
        // Op 2: LoadReg(0)
        let input3 = vec![
            Op::JumpIfEq(0, 1), 
            Op::StoreReg(0),
            Op::LoadReg(0),
            Op::Ret,
        ];
        let mut prog3 = Program {
            ops: input3,
            debug_info: vec!["jump".into(), "store".into(), "load".into(), "ret".into()],
            max_registers: 1,
        };
        prog3.optimize_redundant_moves();
        // Should NOT remove LoadReg because it's a jump target
        assert_eq!(prog3.ops, vec![
            Op::JumpIfEq(0, 1),
            Op::StoreReg(0),
            Op::LoadReg(0),
            Op::Ret
        ]);
        
        // Case 4: Jump Fixup after removal
        // Jump over removed LoadReg
        // Jump(2) -> lands on Ret (index 3).
        // Store, Load (removed), Ret.
        // After removal: Store, Ret.
        // Jump should become Jump(1).
        let input4 = vec![
            Op::JumpIfEq(0, 2), // Target: Ret (index 3)
            Op::StoreReg(0),
            Op::LoadReg(0),     // Removed
            Op::Ret,
        ];
        let mut prog4 = Program {
            ops: input4,
            debug_info: vec!["jump".into(), "store".into(), "load".into(), "ret".into()],
            max_registers: 1,
        };
        prog4.optimize_redundant_moves();
        assert_eq!(prog4.ops, vec![Op::JumpIfEq(0, 1), Op::StoreReg(0), Op::Ret]);
    }

    #[test]
    fn test_optimize_bit_jumps() {
        // Case 1: TestBit + JumpIfEq(0) -> JumpIfBitClear
        let input1 = vec![
            Op::TestBit(0, 3), // Bit 3 of Reg 0
            Op::JumpIfEq(0, 5), // If acc == 0 (clear), jump 5
            Op::Ret,
        ];
        let mut prog1 = Program {
            ops: input1,
            debug_info: vec!["test".into(), "jump".into(), "ret".into()],
            max_registers: 1,
        };
        prog1.optimize_bit_jumps();
        assert_eq!(prog1.ops, vec![Op::JumpIfBitClear(0, 3, 5), Op::Ret]);

        // Case 2: TestBit + JumpIfNe(0) -> JumpIfBitSet
        let input2 = vec![
            Op::TestBit(1, 4),
            Op::JumpIfNe(0, 6), // If acc != 0 (set), jump 6
            Op::Ret,
        ];
        let mut prog2 = Program {
            ops: input2,
            debug_info: vec!["test".into(), "jump".into(), "ret".into()],
            max_registers: 2,
        };
        prog2.optimize_bit_jumps();
        assert_eq!(prog2.ops, vec![Op::JumpIfBitSet(1, 4, 6), Op::Ret]);
        
        // Case 3: TestBit + JumpIfEq(1) -> JumpIfBitSet
        // Check if val == 1 (Set)
        let input3 = vec![
            Op::TestBit(2, 0),
            Op::JumpIfEq(1, 10),
            Op::Ret,
        ];
        let mut prog3 = Program {
            ops: input3,
            debug_info: vec!["test".into(), "jump".into(), "ret".into()],
            max_registers: 3,
        };
        prog3.optimize_bit_jumps();
        assert_eq!(prog3.ops, vec![Op::JumpIfBitSet(2, 0, 10), Op::Ret]);

        // Case 4: Safety Check - Jump targets the Jump instruction -> No Fuse
        // JumpIfEq(0, 1) -> Lands on JumpIfNe(0, 5) (Index 2)
        // Op 0: JumpIfEq(0, 1)
        // Op 1: TestBit(0, 0)
        // Op 2: JumpIfNe(0, 5)
        let input4 = vec![
            Op::JumpIfEq(0, 1),
            Op::TestBit(0, 0),
            Op::JumpIfNe(0, 5),
            Op::Ret,
        ];
        let mut prog4 = Program {
            ops: input4,
            debug_info: vec!["jump1".into(), "test".into(), "jump2".into(), "ret".into()],
            max_registers: 1,
        };
        prog4.optimize_bit_jumps();
        // Should NOT fuse because JumpIfNe(0, 5) (Index 2) is a jump target
        assert_eq!(prog4.ops, vec![
            Op::JumpIfEq(0, 1),
            Op::TestBit(0, 0),
            Op::JumpIfNe(0, 5),
            Op::Ret
        ]);
        
        // Case 5: Safety Check - Jump targets TestBit -> Fuse is OK
        // Jump(0) -> Lands on TestBit (Index 1).
        // Fuse should happen. Jump target logic maps index 1 to new index 1.
        let input5 = vec![
            Op::JumpIfEq(0, 0), // Jump 0 -> Next instruction (TestBit)
            Op::TestBit(0, 0),
            Op::JumpIfNe(0, 5),
            Op::Ret,
        ];
        let mut prog5 = Program {
            ops: input5,
            debug_info: vec!["jump1".into(), "test".into(), "jump2".into(), "ret".into()],
            max_registers: 1,
        };
        prog5.optimize_bit_jumps();
        // Should fuse to JumpIfEq(0, 0), JumpIfBitSet(0, 0, 5), Ret
        assert_eq!(prog5.ops, vec![
            Op::JumpIfEq(0, 0),
            Op::JumpIfBitSet(0, 0, 5),
            Op::Ret
        ]);
    }
}
