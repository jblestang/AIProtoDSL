# ASTERIX VM Programs

This document shows the compiled bytecode programs for validating ASTERIX packets.

## Category 034

**Registers allocated:** 3

### Instruction Listing

| PC | Source Field | Opcode | Description |
|---:|:-------------|:-------|:------------|
| 0 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 1 | fspec | `StoreReg(0)` | Store accumulator → register[0] |
| 2 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 0, 1)` | **Jump +1** if bit 0 of register[0] is CLEAR (Fused) |
| 3 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 4 | fspec | `StoreReg(1)` | Store accumulator → register[1] |
| 5 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 7, 0)` | **Jump +0** if bit 7 of register[0] is CLEAR (Fused) |
| 6 | sac (merged 2 ops) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 7 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 6, 1)` | **Jump +1** if bit 6 of register[0] is CLEAR (Fused) |
| 8 | i034_000 | `ReadU8` | Read 1 byte (u8) into accumulator |
| 9 | i034_000 | `CheckEnum([1, 2, 3, 4, 5])` | **✓ Validate acc ∈ Enum** |
| 10 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 5, 0)` | **Jump +0** if bit 5 of register[0] is CLEAR (Fused) |
| 11 | tod | `Skip(3)` | **Skip 3 bytes** (unused field, optimization) |
| 12 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 4, 0)` | **Jump +0** if bit 4 of register[0] is CLEAR (Fused) |
| 13 | i034_020 (opt: unused) | `Skip(1)` | **Skip 1 bytes** (unused field, optimization) |
| 14 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 3, 0)` | **Jump +0** if bit 3 of register[0] is CLEAR (Fused) |
| 15 | i034_041 (opt: unused) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 16 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 2, 3)` | **Jump +3** if bit 2 of register[0] is CLEAR (Fused) |
| 17 | fspec (opt: unused) (merged 8 ops) | `SkipBits(15)` | **Skip 15 bits** (unused field, optimization) |
| 18 | spare | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 19 | status (merged 2 ops) (merged 9 ops) | `SkipBits(25)` | **Skip 25 bits** (unused field, optimization) |
| 20 | spare | `ZeroBits(7)` | **Write 7 zero bits** (padding) |
| 21 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 1, 3)` | **Jump +3** if bit 1 of register[0] is CLEAR (Fused) |
| 22 | fspec (opt: unused) | `Skip(1)` | **Skip 1 bytes** (unused field, optimization) |
| 23 | spare | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 24 | redrdp (merged 2 ops) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 25 | spare2 | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 26 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 7, 4)` | **Jump +4** if bit 7 of register[1] is CLEAR (Fused) |
| 27 | i034_070 | `ReadU8` | Read 1 byte (u8) into accumulator |
| 28 | i034_070 | `StoreReg(2)` | Store accumulator → register[2] |
| 29 | i034_070 | `JumpIfEq(0, 2)` | If accumulator == 0, jump forward 2 instructions |
| 30 | typ (opt: unused) (merged 2 ops) | `SkipBits(21)` | **Skip 21 bits** (unused field, optimization) |
| 31 | count | `LoopDecNz(2, 2)` | Decrement register[2]; if > 0, jump back 2 instructions |
| 32 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 6, 0)` | **Jump +0** if bit 6 of register[1] is CLEAR (Fused) |
| 33 | rhost (merged 4 ops) | `Skip(8)` | **Skip 8 bytes** (unused field, optimization) |
| 34 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 5, 0)` | **Jump +0** if bit 5 of register[1] is CLEAR (Fused) |
| 35 | i034_110 (opt: unused) | `Skip(1)` | **Skip 1 bytes** (unused field, optimization) |
| 36 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 4, 0)` | **Jump +0** if bit 4 of register[1] is CLEAR (Fused) |
| 37 | hgt (merged 3 ops) | `Skip(8)` | **Skip 8 bytes** (unused field, optimization) |
| 38 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 3, 0)` | **Jump +0** if bit 3 of register[1] is CLEAR (Fused) |
| 39 | rng (merged 2 ops) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 40 | azm | `Ret` | **Return** (packet validation successful) |

## How It Works

The VM executes these instructions sequentially:

1. **Read operations** (`ReadU8`, `ReadU16Be`, etc.) load data from the packet into the accumulator
2. **Skip operations** advance the read pointer without loading data (optimization for unused fields)
3. **Store/Load** operations move data between the accumulator and registers
4. **Jump operations** implement conditional logic (optional fields, presence bitmaps)
5. **Loop operations** handle arrays and repetition structures
6. **Ret** indicates successful validation

### Performance Benefits

- **Zero recursion**: Linear instruction stream eliminates call stack overhead
- **Register-based**: O(1) field access vs HashMap lookups
- **Skip optimization**: Unused fields are skipped without reading (see `Skip` opcodes)
- **Compact**: Single-pass validation with minimal memory allocation


## Category 048

**Registers allocated:** 9

### Instruction Listing

| PC | Source Field | Opcode | Description |
|---:|:-------------|:-------|:------------|
| 0 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 1 | fspec | `StoreReg(0)` | Store accumulator → register[0] |
| 2 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 0, 7)` | **Jump +7** if bit 0 of register[0] is CLEAR (Fused) |
| 3 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 4 | fspec | `StoreReg(1)` | Store accumulator → register[1] |
| 5 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 0, 4)` | **Jump +4** if bit 0 of register[1] is CLEAR (Fused) |
| 6 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 7 | fspec | `StoreReg(2)` | Store accumulator → register[2] |
| 8 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 0, 1)` | **Jump +1** if bit 0 of register[2] is CLEAR (Fused) |
| 9 | fspec | `ReadU8` | Read 1 byte (u8) into accumulator |
| 10 | fspec | `StoreReg(3)` | Store accumulator → register[3] |
| 11 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 7, 0)` | **Jump +0** if bit 7 of register[0] is CLEAR (Fused) |
| 12 | sac (merged 2 ops) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 13 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 6, 0)` | **Jump +0** if bit 6 of register[0] is CLEAR (Fused) |
| 14 | tod | `Skip(3)` | **Skip 3 bytes** (unused field, optimization) |
| 15 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 5, 1)` | **Jump +1** if bit 5 of register[0] is CLEAR (Fused) |
| 16 | typ (opt: unused) (merged 5 ops) | `SkipBits(7)` | **Skip 7 bits** (unused field, optimization) |
| 17 | spare_fx | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 18 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 4, 0)` | **Jump +0** if bit 4 of register[0] is CLEAR (Fused) |
| 19 | rho (merged 2 ops) | `Skip(4)` | **Skip 4 bytes** (unused field, optimization) |
| 20 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 3, 2)` | **Jump +2** if bit 3 of register[0] is CLEAR (Fused) |
| 21 | v (opt: unused) (merged 3 ops) | `SkipBits(3)` | **Skip 3 bits** (unused field, optimization) |
| 22 | spare | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 23 | mode3a | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 24 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 2, 0)` | **Jump +0** if bit 2 of register[0] is CLEAR (Fused) |
| 25 | v (opt: unused) (merged 3 ops) | `SkipBits(18)` | **Skip 18 bits** (unused field, optimization) |
| 26 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(0, 1, 0)` | **Jump +0** if bit 1 of register[0] is CLEAR (Fused) |
| 27 | fspec (opt: unused) (merged 8 ops) | `Skip(8)` | **Skip 8 bytes** (unused field, optimization) |
| 28 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 7, 0)` | **Jump +0** if bit 7 of register[1] is CLEAR (Fused) |
| 29 | addr | `Skip(3)` | **Skip 3 bytes** (unused field, optimization) |
| 30 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 6, 0)` | **Jump +0** if bit 6 of register[1] is CLEAR (Fused) |
| 31 | c (merged 8 ops) | `Skip(8)` | **Skip 8 bytes** (unused field, optimization) |
| 32 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 5, 4)` | **Jump +4** if bit 5 of register[1] is CLEAR (Fused) |
| 33 | i048_250 | `ReadU8` | Read 1 byte (u8) into accumulator |
| 34 | i048_250 | `StoreReg(4)` | Store accumulator → register[4] |
| 35 | i048_250 | `JumpIfEq(0, 2)` | If accumulator == 0, jump forward 2 instructions |
| 36 | mbdata (merged 9 ops) | `Skip(9)` | **Skip 9 bytes** (unused field, optimization) |
| 37 | bds2 | `LoopDecNz(4, 2)` | Decrement register[4]; if > 0, jump back 2 instructions |
| 38 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 4, 1)` | **Jump +1** if bit 4 of register[1] is CLEAR (Fused) |
| 39 | spare | `ZeroBits(4)` | **Write 4 zero bits** (padding) |
| 40 | trn | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 41 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 3, 0)` | **Jump +0** if bit 3 of register[1] is CLEAR (Fused) |
| 42 | x (merged 2 ops) | `Skip(4)` | **Skip 4 bytes** (unused field, optimization) |
| 43 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 2, 0)` | **Jump +0** if bit 2 of register[1] is CLEAR (Fused) |
| 44 | gsp (merged 2 ops) | `Skip(4)` | **Skip 4 bytes** (unused field, optimization) |
| 45 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(1, 1, 2)` | **Jump +2** if bit 1 of register[1] is CLEAR (Fused) |
| 46 | cnf (opt: unused) (merged 10 ops) | `SkipBits(19)` | **Skip 19 bits** (unused field, optimization) |
| 47 | spare | `ZeroBits(3)` | **Write 3 zero bits** (padding) |
| 48 | spare2 | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 49 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 7, 0)` | **Jump +0** if bit 7 of register[2] is CLEAR (Fused) |
| 50 | sigx (merged 2 ops) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 51 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 6, 3)` | **Jump +3** if bit 6 of register[2] is CLEAR (Fused) |
| 52 | i048_030 | `ReadU8` | Read 1 byte (u8) into accumulator |
| 53 | i048_030 | `StoreReg(5)` | Store accumulator → register[5] |
| 54 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(5, 7, 1)` | **Jump +1** if bit 7 of register[5] is CLEAR (Fused) |
| 55 | i048_030 | `JumpBack(4)` | Jump back 4 instructions |
| 56 | i048_080 | `TestBit(2, 5)` | Test bit 5 of register[2] → accumulator (0 or 1) |
| 57 | i048_080 | `JumpIfEq(0, 2)` | If accumulator == 0, jump forward 2 instructions |
| 58 | spare | `ZeroBits(4)` | **Write 4 zero bits** (padding) |
| 59 | qa4 (opt: unused) (merged 12 ops) | `SkipBits(12)` | **Skip 12 bits** (unused field, optimization) |
| 60 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 4, 4)` | **Jump +4** if bit 4 of register[2] is CLEAR (Fused) |
| 61 | v (opt: unused) (merged 2 ops) | `SkipBits(2)` | **Skip 2 bits** (unused field, optimization) |
| 62 | spare | `ZeroBits(2)` | **Write 2 zero bits** (padding) |
| 63 | modec | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 64 | spare2 | `ZeroBits(4)` | **Write 4 zero bits** (padding) |
| 65 | qc1 (opt: unused) (merged 12 ops) | `SkipBits(12)` | **Skip 12 bits** (unused field, optimization) |
| 66 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 3, 0)` | **Jump +0** if bit 3 of register[2] is CLEAR (Fused) |
| 67 | i048_110 (opt: unused) | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 68 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 2, 2)` | **Jump +2** if bit 2 of register[2] is CLEAR (Fused) |
| 69 | d (opt: unused) | `SkipBits(1)` | **Skip 1 bits** (unused field, optimization) |
| 70 | spare | `ZeroBits(5)` | **Write 5 zero bits** (padding) |
| 71 | cal | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 72 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(2, 1, 3)` | **Jump +3** if bit 1 of register[2] is CLEAR (Fused) |
| 73 | com (opt: unused) (merged 4 ops) | `SkipBits(7)` | **Skip 7 bits** (unused field, optimization) |
| 74 | spare | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 75 | arc (opt: unused) (merged 4 ops) | `SkipBits(6)` | **Skip 6 bits** (unused field, optimization) |
| 76 | spare2 | `ZeroBits(2)` | **Write 2 zero bits** (padding) |
| 77 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(3, 7, 3)` | **Jump +3** if bit 7 of register[3] is CLEAR (Fused) |
| 78 | i048_260 | `ReadU8` | Read 1 byte (u8) into accumulator |
| 79 | i048_260 | `StoreReg(6)` | Store accumulator → register[6] |
| 80 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(6, 7, 1)` | **Jump +1** if bit 7 of register[6] is CLEAR (Fused) |
| 81 | i048_260 | `JumpBack(4)` | Jump back 4 instructions |
| 82 | i048_055 | `TestBit(3, 6)` | Test bit 6 of register[3] → accumulator (0 or 1) |
| 83 | i048_055 | `JumpIfEq(0, 1)` | If accumulator == 0, jump forward 1 instructions |
| 84 | v (opt: unused) (merged 4 ops) | `SkipBits(11)` | **Skip 11 bits** (unused field, optimization) |
| 85 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(3, 5, 2)` | **Jump +2** if bit 5 of register[3] is CLEAR (Fused) |
| 86 | v (opt: unused) (merged 3 ops) | `SkipBits(3)` | **Skip 3 bits** (unused field, optimization) |
| 87 | spare | `ZeroBits(1)` | **Write 1 zero bits** (padding) |
| 88 | mode2 | `Skip(2)` | **Skip 2 bytes** (unused field, optimization) |
| 89 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(3, 4, 1)` | **Jump +1** if bit 4 of register[3] is CLEAR (Fused) |
| 90 | spare | `ZeroBits(3)` | **Write 3 zero bits** (padding) |
| 91 | qa4 (opt: unused) (merged 5 ops) | `SkipBits(5)` | **Skip 5 bits** (unused field, optimization) |
| 92 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(3, 3, 1)` | **Jump +1** if bit 3 of register[3] is CLEAR (Fused) |
| 93 | spare | `ZeroBits(4)` | **Write 4 zero bits** (padding) |
| 94 | qa4 (opt: unused) (merged 12 ops) | `SkipBits(12)` | **Skip 12 bits** (unused field, optimization) |
| 95 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(3, 2, 3)` | **Jump +3** if bit 2 of register[3] is CLEAR (Fused) |
| 96 | i048_sp | `ReadU8` | Read 1 byte (u8) into accumulator |
| 97 | i048_sp | `StoreReg(7)` | Store accumulator → register[7] |
| 98 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(7, 7, 1)` | **Jump +1** if bit 7 of register[7] is CLEAR (Fused) |
| 99 | i048_sp | `JumpBack(4)` | Jump back 4 instructions |
| 100 | i048_re | `TestBit(3, 1)` | Test bit 1 of register[3] → accumulator (0 or 1) |
| 101 | i048_re | `JumpIfEq(0, 4)` | If accumulator == 0, jump forward 4 instructions |
| 102 | i048_re | `ReadU8` | Read 1 byte (u8) into accumulator |
| 103 | i048_re | `StoreReg(8)` | Store accumulator → register[8] |
| 104 | Fused TestBit+JumpIfEq(0) | `JumpIfBitClear(8, 7, 1)` | **Jump +1** if bit 7 of register[8] is CLEAR (Fused) |
| 105 | i048_re | `JumpBack(4)` | Jump back 4 instructions |
| 106 | i048_re | `Ret` | **Return** (packet validation successful) |

## How It Works

The VM executes these instructions sequentially:

1. **Read operations** (`ReadU8`, `ReadU16Be`, etc.) load data from the packet into the accumulator
2. **Skip operations** advance the read pointer without loading data (optimization for unused fields)
3. **Store/Load** operations move data between the accumulator and registers
4. **Jump operations** implement conditional logic (optional fields, presence bitmaps)
5. **Loop operations** handle arrays and repetition structures
6. **Ret** indicates successful validation

### Performance Benefits

- **Zero recursion**: Linear instruction stream eliminates call stack overhead
- **Register-based**: O(1) field access vs HashMap lookups
- **Skip optimization**: Unused fields are skipped without reading (see `Skip` opcodes)
- **Compact**: Single-pass validation with minimal memory allocation
