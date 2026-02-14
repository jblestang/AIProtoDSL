//! Parser fuzz target: feed arbitrary bytes to the DSL parser.
//! The parser must not panic; it should return Ok(Protocol) or Err(String).
//! Build with: cargo fuzz run parser_fuzz (requires nightly and cargo fuzz).

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(x) => x,
        Err(_) => return,
    };
    let _ = aiprotodsl::parse(s);
});

#[cfg(not(fuzzing))]
fn main() {
    eprintln!("Build with: cargo fuzz run parser_fuzz");
}
