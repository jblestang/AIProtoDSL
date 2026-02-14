//! EGUI binary: PCAP + DSL viewer.
//! Build: cargo run --bin decode_pcap_gui --features gui

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("Decode PCAP GUI: build with --features gui");
    eprintln!("  cargo run --bin decode_pcap_gui --features gui");
    std::process::exit(1);
}

#[cfg(feature = "gui")]
fn main() -> eframe::Result<()> {
    aiprotodsl::gui::run_native()
}
