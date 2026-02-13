# Walk: saturating-range skip and throughput analysis

## Change summary

The walker was modified so that **range validation is skipped** for message-level fields whose constraint already **saturates** the type range (e.g. `u8 [0..255]`, `u16 [0..65535]`). Those fields are identified once at DSL load time and never validated during `validate_message` / `validate_message_in_place`.

### Implementation

1. **Range analysis (ast.rs, at resolve time)**
   - `type_spec_integer_range(spec)` returns `(min, max)` for numeric types: `Base` (u8, i8, u16, …), `Bitfield(n)`, `SizedInt(bt, n)`.
   - `constraint_saturates_range(c, type_min, type_max)` is true when the constraint is a single interval equal to the type range (e.g. `Range(vec![(0, 255)])` for u8).
   - During `resolve()`, each message’s fields are updated: `MessageField::saturating` is set to true when that field’s constraint saturates its type range (computed via `build_message_field_saturating` internally; the result is written onto the field, not stored in a side structure).

2. **ResolvedProtocol**
   - No separate `message_field_saturating` map: the saturation flag lives on each `MessageField` as `saturating: bool`.

3. **Walker (walk.rs)**
   - `validate_message_in_place(..., message_name)`; no extra argument. `validate_and_skip_message_fields` iterates message fields and for each uses `f.saturating`: if true (or no constraint), it only skips; otherwise it calls `validate_field_and_skip`.

### Effect

- **Extent-only walk** (`message_extent` / `skip_message`): unchanged; it never ran range checks.
- **Walk + validate** (`validate_message_in_place`): for messages with many full-range constraints (e.g. ASTERIX with lots of `u8 [0..255]`), fewer `validate_constraint_raw` calls and less work per record.

---

## Throughput (same pcap: 120 blocks, 6522 body bytes)

Benchmark: `cargo bench --bench walk_pcap -- --sample-size=15`.

| Strategy             | µs/pcap | records/s | MB/s   | Within 1 ms        |
|----------------------|---------|-----------|--------|---------------------|
| walk (extent only)   | ~76     | ~1.78 M/s | ~85    | ~13.1 pcaps, ~1779 rec |
| walk+validate        | ~113    | ~1.21 M/s | ~58    | ~8.9 pcaps, ~1212 rec  |
| walk+validate+zero   | ~55     | ~2.46 M/s | ~118   | ~18.1 pcaps, ~2461 rec  |
| decode               | ~3060   | ~0.06 M/s | ~2.1   | 0.3 pcaps, ~56 rec   |
| decode+encode        | ~3910   | ~0.04 M/s | ~1.7   | 0.3 pcaps, ~44 rec   |

- **Walk (extent only)** benefits from the **Optional** hot-path optimization: when presence is consecutive (8 bits per byte, ASTERIX FSPEC), the walker uses `BitmapPresenceConsecutive` so no division/modulo per optional.
- **Walk+validate** uses each field’s `saturating` flag (set at resolve). Criterion ~113 µs; see below for sustainable-table variance.
- **Walk+validate+zero** uses **one pass per record** (`validate_and_zero_message_in_place`): validate constrained fields and zero padding/reserved in a single traversal. Faster than walk+validate alone because it does one walk instead of two (no separate extent then validate+zero). Benchmark clones block bodies per iteration so data is fresh for zeroing.
- Decode and decode+encode absolute times may vary run-to-run.

### Sustainable data rate vs criterion

The bench prints **criterion** timings (per-strategy, 3 s warmup, 15 samples) and a **sustainable data rate** table (fixed iterations, no per-strategy warmup). Walk+validate can show higher µs in the sustainable batch when that run is cold; use criterion (~113 µs) as the reference. The table remains useful for relative comparison and “within 1 ms” counts.

### Overhead of walk+validate over walk (extent only)

Walk+validate is slower than extent-only because it does extra work on top of the same structure traversal:

1. **Same traversal**  
   Both paths walk the same bytes with the same `skip_type_spec` recursion (Optional, StructRef, RepList, etc.). For most fields, walk+validate also calls `skip_type_spec` and only advances `pos`; it does not decode or allocate.

2. **Per message-level field (validate path)**  
   Instead of a single loop that always calls `skip_type_spec`, walk+validate uses `validate_and_skip_message_fields`, which for **every** message-level field:
   - evaluates any `condition` (e.g. FSPEC-based),
   - reads `f.saturating` and branches: if true or no constraint → `skip_type_spec`; else → `validate_field_and_skip`.

   So each such field pays for one field read and a branch. With many top-level fields (e.g. ASTERIX), that adds up even though each step is cheap.

3. **Non-saturating constrained fields**  
   For the few fields that have a constraint and are **not** saturating (e.g. an enum or a narrow range), walk+validate calls `validate_field_and_skip` instead of `skip_type_spec`. That path:
   - uses `read_i64_slice` to read the value (same bytes as a skip would pass over) and advance `pos`,
   - then runs `validate_constraint_raw` (interval or enum check).

   So we pay for the general “read as i64” path and the constraint check. In the ASTERIX benchmark this shows up as only ~0.4% in the hotspot (**ValidateField**) because most constrained fields are saturating and take the skip branch.

**Summary:** The extra time is mainly from the per-field logic in the validate path (`f.saturating` check + branch) over many message-level fields, plus a small contribution from the few fields that actually run the range/enum check.

---

## Slow path (walk + validate)

Run `cargo bench --bench walk_pcap --features walk_profile` to get a hotspot breakdown. The **walk_validate_pcap** section shows where time is spent for extent + validate on the same pcap.

Measured breakdown (one full pcap, walk+validate; total ~1.69 ms with profile enabled):

| Label             | ns      | % of total | Role |
|-------------------|---------|------------|------|
| Optional          | 835 273 | 49.3%      | Presence bit + recursive skip; consecutive FSPEC uses `BitmapPresenceConsecutive` (no div/mod per optional). |
| StructRef         | 578 548 | 34.2%      | Nested struct fields. |
| RepList           | 144 497 | 8.5%       | Repeated list (count byte + loop). |
| BitfieldSizedInt  | 63 941  | 3.8%       | Sized int / bitfield. |
| Base              | 44 319  | 2.6%       | Fixed-size base types. |
| BitmapPresence    | 13 771  | 0.8%       | FSPEC / presence bitmap read. |
| PaddingBits       | 8 172   | 0.5%       | Padding bits. |
| **ValidateField** | 4 671   | 0.3%       | Range/enum check (only for non-saturating constrained fields). |
| OctetsFx          | 42      | &lt;0.1%     | Variable-length octets. |
| **TOTAL**         | 1 693 234 | 100%     | |

Extent-only (same pcap, for comparison): Optional 48.3%, StructRef 33.8%, RepList 10.0%; total ~1.28 ms.

So the slow path is **structure traversal** (Optional, StructRef, RepList); **ValidateField** is a small fraction because most constrained fields in this DSL are saturating and are skipped without a range check.

### Map lookups in the slow path

Yes. The following **HashMap** lookups can happen during walk/validate:

| Where | Map | When |
|-------|-----|------|
| `resolved.get_message(message_name)` | `messages_by_name` | Once per record at `validate_message` / `skip_message` entry. |
| `resolved.get_struct(name)` | `structs_by_name` | **Every StructRef**: each time we recurse into a struct (~34% of time). One lookup per struct reference. |
| `ctx.get(cond.field)` | `WalkContext.values` | **Every field with a condition** (e.g. `if com == 1`): one lookup per such message/struct field. |
| `ctx.get(field)` | `WalkContext.values` | When handling `Array` with `ArrayLen::FieldRef(field)` (length/count from another field). |
| `ctx.set(name, v)` | `WalkContext.values` | When we read a `length_of` / `count_of` field (insert for later `ctx.get`). |

So the hot path pays for: **one `get_message` per record**; **one `get_struct` per struct reference** (many per pcap); **one `ctx.get` per conditional field** (and per Array with field-ref length). No map lookup per optional or per base type—only at message/struct boundaries and for conditions/array length.

---

## Conclusion

- Saturating-range analysis is done **once at resolve time**: each `MessageField` gets its `saturating` flag set, so validation just reads the field; no separate lookup or allocation.
- **Walk+validate** throughput improved significantly after switching from HashSet lookup to the in-field flag (and then to the flag on the field itself).
- **Walk+validate+zero** uses a single pass per record (`validate_and_zero_message_in_place`), so it is faster than doing extent + validate + zero in three passes; typical criterion time ~55 µs/pcap, ~2.46 M records/s on the same pcap.
