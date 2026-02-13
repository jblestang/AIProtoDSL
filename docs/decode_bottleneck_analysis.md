# Decode bottleneck analysis

## Measured profile (one full pcap decode, `codec_decode_profile` feature)

Run: `cargo bench --bench walk_pcap --features codec_decode_profile -- --sample-size=20`

```
decode hotspot (one full pcap decode, codec_decode_profile feature):
  Optional                  2618508 ns   52.0%
  StructRef                 2010292 ns   39.9%
  RepList                    228912 ns    4.5%
  Bitfield                    57219 ns    1.1%
  SizedInt                    46935 ns    0.9%
  Base                        38913 ns    0.8%
  BitmapPresence              22739 ns    0.5%
  PaddingBits                 14001 ns    0.3%
  TOTAL                     5037519 ns  100.0%
```

**Conclusion:** ~92% of decode time is in **Optional** (52%) and **StructRef** (39.9%). RepList is a distant third (4.5%). Base types, bitfields, and presence are negligible.

---

## Why decode is ~40× slower than walk

| Aspect | Walk | Decode |
|--------|------|--------|
| **Optional** | Read presence bit, if absent skip; if present recurse (no value built) | Same recursion, but: clone `current_message_name` / `current_field_name`, HashMap lookup for bitmap mapping, build `Value` (often `Struct`/`List`), `ctx.set(name.clone(), v.clone())`, `out.insert(name.clone(), v)` |
| **StructRef** | Resolve struct, recurse over fields (advance `pos` only) | New `HashMap` for struct, for each field recurse and `out.insert(f.name.clone(), value)` |
| **Allocation** | None (slice + position) | Every struct = one `HashMap`, every list = one `Vec`, every key = `String` clone |

So the “weird” result (decode ~3 ms vs walk ~74 µs) is expected:

1. **Optional is the hottest path** (52%). Each optional does:
   - Two `Option<String>::clone()` for message/field name (for mapping lookup).
   - `presence_stack.last_mut()` and a match.
   - At message level: `bitmap_presence_mapping_message(msg_name)` (HashMap) and `bit_for_field(field_name)` (search).
   - If present: full decode of the inner type → more Optionals and StructRefs, and construction of `Value` (Struct/List/etc.).

2. **StructRef is second** (40%). Each struct:
   - Allocates a new `HashMap`.
   - For each field: `decode_type_spec` (often Optional again) and `insert(f.name.clone(), v)` (string clone + value clone).

3. **No corresponding cost in walk:** Walk only advances a byte offset and reads the minimum (length, presence bits) to skip; it never builds `Value` or does HashMap insert.

---

## Possible optimizations (for reference)

- **Optional:** Avoid cloning message/field name every time (e.g. pass `&str` from context or use indices). Cache bitmap mapping lookup per message. Consider a “decode to minimal value” path (e.g. skip nested structs when not needed).
- **StructRef:** Reuse or pool HashMaps; avoid per-field `String` clone (e.g. intern keys or use `&str` where possible).
- **General:** Reduce `Value` cloning (e.g. move into `ctx.set`/insert instead of clone), or offer a zero-copy / lazy-decode mode that only builds values for requested fields.

These are not implemented; the profile confirms where time is spent.
