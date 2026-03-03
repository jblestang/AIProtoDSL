# AIProtoDSL Virtual Machine (VM)

The AIProtoDSL VM is a specialized, high-performance bytecode interpreter designed for **validating** and **walking** binary formats (like ASTERIX) without the overhead of full object decoding.

## Architecture

The VM is **register-based** but uses a central **accumulator** (`acc`) for most operations, similar to early 8-bit processors. This design keeps instructions compact and execution simple.

### State

- **`pc` (Program Counter)**: Index of the current instruction.
- **`pos` (Data Cursor)**: Current byte offset in the input buffer.
- **`bit_pos` (Bit Cursor)**: Current bit offset (0-7) within the current byte (for sub-byte reads).
- **`acc` (Accumulator)**: A 64-bit unsigned integer (`u64`) holding the result of the last Read or arithmetic operation.
- **`regs` (Registers)**: A bank of `u64` registers (typically 16) used to store loop counters, lengths, or values for later comparison.
- **`flags`**: Implicitly handled (e.g., comparison results affect control flow directly).

## Instruction Set

### 1. Data Access (Reads)

These instructions read data from the input buffer at `pos` into the Accumulator (`acc`) and advance `pos`.

| Opcode | Description |
|:-------|:------------|
| `ReadU8` | Read 1 byte into `acc`. |
| `ReadU16Be` / `ReadU16Le` | Read 2 bytes (Big/Little Endian) into `acc`. |
| `ReadU32Be` / `ReadU32Le` | Read 4 bytes (Big/Little Endian) into `acc`. |
| `ReadBits(n)` | Read `n` bits (1-64) into `acc`. Handles cross-byte boundaries. |

### 2. Scanning & Skipping

These instructions advance the data cursor `pos` without updating `acc`. Used for unused fields or fixed blobs.

| Opcode | Description |
|:-------|:------------|
| `Skip(n)` | Advance `pos` by `n` bytes. |
| `SkipBits(n)` | Advance cursor by `n` bits. Handles `bit_pos` and `pos`. |
| `ReadBytes(n)` | Conceptually "read" `n` bytes, effectively same as `Skip(n)` but semantically distinct (e.g., for `padding`). |
| `Align` | If `bit_pos != 0`, advance to the next byte boundary (`pos += 1, bit_pos = 0`). |

### 3. Registers

| Opcode | Description |
|:-------|:------------|
| `StoreReg(idx)` | Store `acc` into register `regs[idx]`. |
| `LoadReg(idx)` | Load `regs[idx]` into `acc`. |

### 4. Control Flow

| Opcode | Description |
|:-------|:------------|
| `JumpIfEq(val, offset)` | If `acc == val`, jump forward `offset` instructions. |
| `JumpIfNe(val, offset)` | If `acc != val`, jump forward `offset` instructions. |
| `JumpBack(offset)` | Jump backward `offset` instructions (unconditional). |
| `LoopDecNz(reg, offset)` | Decrement `regs[reg]`. If result > 0, jump back `offset` instructions. Used for `repeated` or `list`. |

### 5. Validation

These instructions verify constraints. If a check fails, the VM returns `Err(Validation)`.

| Opcode | Description |
|:-------|:------------|
| `CheckRange(min, max)` | Assert `min <= acc <= max`. |
| `CheckEnum(list)` | Assert `acc` is present in the provided list of valid values. |
| `TestBit(reg, bit)` | Check if `bit` is set in `regs[reg]`. result is 0 or 1. Used for presence maps. |

### 6. Mutation / Lifecycle

| Opcode | Description |
|:-------|:------------|
| `ZeroBytes(n)` | Write `n` bytes of zeros at `pos`, then advance `pos` by `n`. (Only in mutable mode). |
| `Ret` | Stop execution successfully. |
| `Fail` | Stop execution with error. |
