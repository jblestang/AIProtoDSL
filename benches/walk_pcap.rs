//! Benchmark: compare walk vs decode vs decode+encode for processing all ASTERIX
//! record payloads in cat_034_048.pcap. Walk uses message_extent only (no decode);
//! walk+validate uses extent then validate_message_in_place (saturation is on each MessageField at resolve);
//! walk+validate+zero uses validate_and_zero_message_in_place (one walk per record; mutates buffer; bench clones blocks per iter).
//! Decode and decode+encode round-trip.

use aiprotodsl::{message_extent, parse, validate_message_in_place, validate_and_zero_message_in_place, Codec, Endianness, ResolvedProtocol};
#[cfg(feature = "walk_profile")]
use aiprotodsl::{get_walk_profile, reset_walk_profile};
#[cfg(feature = "codec_decode_profile")]
use aiprotodsl::{get_decode_profile, reset_decode_profile};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pcap_parser::pcap::LegacyPcapReader;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Linktype, PcapBlockOwned, PcapError};
use std::fs::File;
use std::path::PathBuf;

fn ethernet_l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let mut off = 12usize;
    let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    off += 2;
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < off + 4 + 2 {
            return None;
        }
        off += 4;
        ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
        off += 2;
    }
    match ethertype {
        0x0800 => Some(&frame[off..]),
        _ => None,
    }
}

fn ipv4_udp_payload(l3: &[u8]) -> Option<&[u8]> {
    if l3.len() < 20 {
        return None;
    }
    let ver_ihl = l3[0];
    if (ver_ihl >> 4) != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
    let l3_trunc = if total_len <= l3.len() { &l3[..total_len] } else { l3 };
    if l3_trunc.len() < ihl + 8 || l3_trunc[9] != 17 {
        return None;
    }
    let udp = &l3_trunc[ihl..];
    if udp.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    Some(&udp[8..udp_len])
}

fn udp_payload(linktype: Linktype, frame: &[u8]) -> Option<&[u8]> {
    let l3 = match linktype.0 {
        1 => ethernet_l3(frame)?,
        101 => frame,
        113 => {
            if frame.len() < 16 {
                return None;
            }
            if u16::from_be_bytes([frame[14], frame[15]]) != 0x0800 {
                return None;
            }
            &frame[16..]
        }
        _ => return None,
    };
    ipv4_udp_payload(l3)
}

/// Walk one block body: repeatedly message_extent until consumed or error (no decode).
fn walk_block_body(
    body: &[u8],
    msg_name: &str,
    resolved: &ResolvedProtocol,
    endianness: aiprotodsl::WalkEndianness,
) -> usize {
    let mut pos = 0usize;
    let mut records = 0usize;
    while pos < body.len() {
        match message_extent(body, pos, resolved, endianness, msg_name) {
            Ok(consumed) => {
                pos += consumed;
                records += 1;
            }
            Err(_) => break,
        }
    }
    records
}

/// Walk then validate each record (extent + validate_message_in_place). Saturating flag is on each MessageField.
fn walk_validate_block_body(
    body: &[u8],
    msg_name: &str,
    resolved: &ResolvedProtocol,
    endianness: aiprotodsl::WalkEndianness,
) -> usize {
    let mut pos = 0usize;
    let mut records = 0usize;
    while pos < body.len() {
        match message_extent(body, pos, resolved, endianness, msg_name) {
            Ok(consumed) => {
                let _ = validate_message_in_place(body, pos, resolved, endianness, msg_name);
                pos += consumed;
                records += 1;
            }
            Err(_) => break,
        }
    }
    records
}

/// Walk, validate and zeroize padding/reserved in one pass per record (validate_and_zero_message_in_place). Mutates body.
fn walk_validate_zero_block_body(
    body: &mut [u8],
    msg_name: &str,
    resolved: &ResolvedProtocol,
    endianness: aiprotodsl::WalkEndianness,
) -> usize {
    let mut pos = 0usize;
    let mut records = 0usize;
    while pos < body.len() {
        match validate_and_zero_message_in_place(body, pos, resolved, endianness, msg_name) {
            Ok(consumed) => {
                pos += consumed;
                records += 1;
            }
            Err(_) => break,
        }
    }
    records
}

/// Decode one block body: repeatedly decode_message_with_extent until consumed or no progress.
fn decode_block_body(body: &[u8], msg_name: &str, codec: &Codec) -> usize {
    let mut offset = 0usize;
    let mut records = 0usize;
    while offset < body.len() {
        let (consumed, _) = codec.decode_message_with_extent(msg_name, &body[offset..]);
        if consumed == 0 {
            break;
        }
        offset += consumed;
        records += 1;
    }
    records
}

/// Decode then encode each record (round-trip). Same record count as decode.
fn decode_encode_block_body(body: &[u8], msg_name: &str, codec: &Codec) -> usize {
    let mut offset = 0usize;
    let mut records = 0usize;
    while offset < body.len() {
        let (consumed, result) = codec.decode_message_with_extent(msg_name, &body[offset..]);
        if consumed == 0 {
            break;
        }
        if let Ok(values) = result {
            let _ = codec.encode_message(msg_name, &values);
        }
        offset += consumed;
        records += 1;
    }
    records
}

fn load_pcap_blocks(
    pcap_path: &std::path::Path,
    codec: &Codec,
    resolved: &ResolvedProtocol,
) -> Vec<(String, Vec<u8>)> {
    let mut file = File::open(pcap_path).expect("open pcap");
    let mut reader = LegacyPcapReader::new(1 << 20, &mut file).expect("pcap reader");
    let mut linktype = Linktype(1);
    let mut out = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::LegacyHeader(h) = block {
                    linktype = h.network;
                } else if let PcapBlockOwned::Legacy(b) = block {
                    if let Some(payload) = udp_payload(linktype, b.data) {
                        let mut off = 0usize;
                        while off + 3 <= payload.len() {
                            let block_len =
                                u16::from_be_bytes([payload[off + 1], payload[off + 2]]) as usize;
                            if block_len < 3 || off + block_len > payload.len() {
                                break;
                            }
                            let block = &payload[off..off + block_len];
                            if let Ok(tv) = codec.decode_transport(block) {
                                if let Some(msg_name) = resolved.message_for_transport_values(&tv) {
                                    out.push((
                                        msg_name.to_string(),
                                        block[3..].to_vec(),
                                    ));
                                }
                            }
                            off += block_len;
                        }
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("refill");
            }
            Err(e) => panic!("pcap error: {:?}", e),
        }
    }
    out
}

fn bench_walk_pcap(c: &mut Criterion) {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dsl_path = manifest.join("examples/asterix_family.dsl");
    let pcap_path = manifest.join("assets/cat_034_048.pcap");

    let dsl_src = std::fs::read_to_string(&dsl_path).expect("read dsl");
    let protocol = parse(&dsl_src).expect("parse dsl");
    let resolved = ResolvedProtocol::resolve(protocol).expect("resolve");
    let codec = Codec::new(resolved.clone(), Endianness::Big);
    let endianness = Endianness::Big.into();

    if !pcap_path.exists() {
        eprintln!("skip bench: {} not found", pcap_path.display());
        return;
    }

    let blocks = load_pcap_blocks(&pcap_path, &codec, &resolved);
    let total_records: usize = blocks
        .iter()
        .map(|(name, body)| walk_block_body(body, name, &resolved, endianness))
        .sum();
    let total_body_bytes: usize = blocks.iter().map(|(_, body)| body.len()).sum();
    eprintln!(
        "walk_pcap: {} blocks, {} records, {} body bytes (one warm-up pass)",
        blocks.len(),
        total_records,
        total_body_bytes
    );

    c.bench_function("walk_cat_034_048_pcap", |b| {
        b.iter(|| {
            let mut records = 0usize;
            for (msg_name, body) in &blocks {
                let n = walk_block_body(
                    black_box(body),
                    black_box(msg_name),
                    &resolved,
                    endianness,
                );
                records += n;
            }
            black_box(records)
        });
    });

    c.bench_function("walk_cat_034_048_pcap_per_record", |b| {
        b.iter(|| {
            for (msg_name, body) in &blocks {
                let mut pos = 0usize;
                while pos < body.len() {
                    if let Ok(consumed) =
                        message_extent(black_box(body), pos, &resolved, endianness, msg_name)
                    {
                        pos += consumed;
                    } else {
                        break;
                    }
                }
            }
        });
    });

    let total_decode_records: usize = blocks
        .iter()
        .map(|(name, body)| decode_block_body(body, name, &codec))
        .sum();
    eprintln!(
        "decode: {} records (one warm-up pass)",
        total_decode_records
    );

    c.bench_function("decode_cat_034_048_pcap", |b| {
        b.iter(|| {
            let mut records = 0usize;
            for (msg_name, body) in &blocks {
                records += decode_block_body(black_box(body), black_box(msg_name), &codec);
            }
            black_box(records)
        });
    });

    c.bench_function("decode_encode_cat_034_048_pcap", |b| {
        b.iter(|| {
            let mut records = 0usize;
            for (msg_name, body) in &blocks {
                records += decode_encode_block_body(black_box(body), black_box(msg_name), &codec);
            }
            black_box(records)
        });
    });

    c.bench_function("walk_validate_cat_034_048_pcap", |b| {
        b.iter(|| {
            let mut records = 0usize;
            for (msg_name, body) in &blocks {
                records += walk_validate_block_body(
                    black_box(body),
                    black_box(msg_name),
                    &resolved,
                    endianness,
                );
            }
            black_box(records)
        });
    });

    c.bench_function("walk_validate_zero_cat_034_048_pcap", |b| {
        b.iter(|| {
            let mut copies: Vec<(String, Vec<u8>)> = blocks
                .iter()
                .map(|(n, body)| (n.clone(), body.to_vec()))
                .collect();
            let mut records = 0usize;
            for (msg_name, body) in &mut copies {
                records += walk_validate_zero_block_body(body, msg_name, &resolved, endianness);
            }
            black_box(records)
        });
    });

    // Sustainable data rate: timed runs for walk, walk+validate, decode, decode+encode
    const ITERS: u32 = 10_000;
    let latency_budget_ms = 1.0;
    let us_per_budget = latency_budget_ms * 1000.0;

    let start = std::time::Instant::now();
    for _ in 0..ITERS {
        for (msg_name, body) in &blocks {
            walk_block_body(body, msg_name, &resolved, endianness);
        }
    }
    let walk_ns = start.elapsed().as_nanos() / (ITERS as u128);
    let walk_us = walk_ns as f64 / 1000.0;
    let walk_records_per_sec = (total_records as f64) / (walk_ns as f64 / 1e9);
    let walk_mb_per_sec = (total_body_bytes as f64) / (walk_ns as f64 / 1e9) / 1e6;

    const WALK_VALIDATE_ITERS: u32 = 2_000;
    let start = std::time::Instant::now();
    for _ in 0..WALK_VALIDATE_ITERS {
        for (msg_name, body) in &blocks {
            walk_validate_block_body(body, msg_name, &resolved, endianness);
        }
    }
    let walk_val_ns = start.elapsed().as_nanos() / (WALK_VALIDATE_ITERS as u128);
    let walk_val_us = walk_val_ns as f64 / 1000.0;
    let walk_val_records_per_sec = (total_records as f64) / (walk_val_ns as f64 / 1e9);
    let walk_val_mb_per_sec = (total_body_bytes as f64) / (walk_val_ns as f64 / 1e9) / 1e6;

    const WALK_VALIDATE_ZERO_ITERS: u32 = 1_000;
    let start = std::time::Instant::now();
    for _ in 0..WALK_VALIDATE_ZERO_ITERS {
        let mut copies: Vec<(String, Vec<u8>)> = blocks
            .iter()
            .map(|(n, body)| (n.clone(), body.to_vec()))
            .collect();
        for (msg_name, body) in &mut copies {
            walk_validate_zero_block_body(body, msg_name, &resolved, endianness);
        }
    }
    let walk_val_zero_ns = start.elapsed().as_nanos() / (WALK_VALIDATE_ZERO_ITERS as u128);
    let walk_val_zero_us = walk_val_zero_ns as f64 / 1000.0;
    let walk_val_zero_records_per_sec = (total_records as f64) / (walk_val_zero_ns as f64 / 1e9);
    let walk_val_zero_mb_per_sec = (total_body_bytes as f64) / (walk_val_zero_ns as f64 / 1e9) / 1e6;

    let start = std::time::Instant::now();
    for _ in 0..ITERS {
        for (msg_name, body) in &blocks {
            decode_block_body(body, msg_name, &codec);
        }
    }
    let decode_ns = start.elapsed().as_nanos() / (ITERS as u128);
    let decode_us = decode_ns as f64 / 1000.0;
    let decode_records_per_sec = (total_decode_records as f64) / (decode_ns as f64 / 1e9);
    let decode_mb_per_sec = (total_body_bytes as f64) / (decode_ns as f64 / 1e9) / 1e6;

    let start = std::time::Instant::now();
    for _ in 0..ITERS {
        for (msg_name, body) in &blocks {
            decode_encode_block_body(body, msg_name, &codec);
        }
    }
    let de_en_ns = start.elapsed().as_nanos() / (ITERS as u128);
    let de_en_us = de_en_ns as f64 / 1000.0;
    let de_en_records_per_sec = (total_decode_records as f64) / (de_en_ns as f64 / 1e9);
    let de_en_mb_per_sec = (total_body_bytes as f64) / (de_en_ns as f64 / 1e9) / 1e6;

    eprintln!();
    eprintln!("--- Sustainable data rate comparison (same pcap, {} blocks, {} body bytes) ---", blocks.len(), total_body_bytes);
    eprintln!("  Strategy           |  µs/pcap |  records/s  |  MB/s  |  within 1 ms");
    eprintln!("  ------------------+----------+-------------+--------+------------------");
    eprintln!(
        "  walk (extent only) | {:>8.2} | ~{:.2} M/s   | {:>6.2} | {:.1} pcaps, {:.0} rec",
        walk_us,
        walk_records_per_sec / 1e6,
        walk_mb_per_sec,
        us_per_budget / walk_us,
        us_per_budget / walk_us * (total_records as f64)
    );
    eprintln!(
        "  walk+validate      | {:>8.2} | ~{:.2} M/s   | {:>6.2} | {:.1} pcaps, {:.0} rec",
        walk_val_us,
        walk_val_records_per_sec / 1e6,
        walk_val_mb_per_sec,
        us_per_budget / walk_val_us,
        us_per_budget / walk_val_us * (total_records as f64)
    );
    eprintln!(
        "  walk+validate+zero | {:>8.2} | ~{:.2} M/s   | {:>6.2} | {:.1} pcaps, {:.0} rec",
        walk_val_zero_us,
        walk_val_zero_records_per_sec / 1e6,
        walk_val_zero_mb_per_sec,
        us_per_budget / walk_val_zero_us,
        us_per_budget / walk_val_zero_us * (total_records as f64)
    );
    eprintln!(
        "  decode             | {:>8.2} | ~{:.2} M/s   | {:>6.2} | {:.1} pcaps, {:.0} rec",
        decode_us,
        decode_records_per_sec / 1e6,
        decode_mb_per_sec,
        us_per_budget / decode_us,
        us_per_budget / decode_us * (total_decode_records as f64)
    );
    eprintln!(
        "  decode+encode      | {:>8.2} | ~{:.2} M/s   | {:>6.2} | {:.1} pcaps, {:.0} rec",
        de_en_us,
        de_en_records_per_sec / 1e6,
        de_en_mb_per_sec,
        us_per_budget / de_en_us,
        us_per_budget / de_en_us * (total_decode_records as f64)
    );
    eprintln!("---");

    // With walk_profile feature: walk-only and walk+validate hotspot breakdown
    #[cfg(feature = "walk_profile")]
    {
        reset_walk_profile();
        for (msg_name, body) in &blocks {
            walk_block_body(body, msg_name, &resolved, endianness);
        }
        let profile = get_walk_profile();
        let total_ns: u64 = profile.values().sum();
        eprintln!("walk_pcap hotspot (extent only, walk_profile feature):");
        let mut by_label: Vec<_> = profile.into_iter().collect();
        by_label.sort_by(|a, b| b.1.cmp(&a.1));
        for (label, ns) in &by_label {
            let pct = if total_ns > 0 { *ns as f64 / total_ns as f64 * 100.0 } else { 0.0 };
            eprintln!("  {:20} {:>12} ns  {:5.1}%", label, ns, pct);
        }
        eprintln!("  {:20} {:>12} ns  100.0%", "TOTAL", total_ns);

        reset_walk_profile();
        for (msg_name, body) in &blocks {
            walk_validate_block_body(body, msg_name, &resolved, endianness);
        }
        let profile = get_walk_profile();
        let total_ns: u64 = profile.values().sum();
        eprintln!();
        eprintln!("walk_validate_pcap hotspot (extent + validate, walk_profile feature):");
        let mut by_label: Vec<_> = profile.into_iter().collect();
        by_label.sort_by(|a, b| b.1.cmp(&a.1));
        for (label, ns) in &by_label {
            let pct = if total_ns > 0 { *ns as f64 / total_ns as f64 * 100.0 } else { 0.0 };
            eprintln!("  {:20} {:>12} ns  {:5.1}%", label, ns, pct);
        }
        eprintln!("  {:20} {:>12} ns  100.0%", "TOTAL", total_ns);
    }

    // With codec_decode_profile feature: one decode run and print hotspot breakdown
    #[cfg(feature = "codec_decode_profile")]
    {
        reset_decode_profile();
        for (msg_name, body) in &blocks {
            decode_block_body(body, msg_name, &codec);
        }
        let profile = get_decode_profile();
        let total_ns: u64 = profile.values().sum();
        eprintln!();
        eprintln!("decode hotspot (one full pcap decode, codec_decode_profile feature):");
        let mut by_label: Vec<_> = profile.into_iter().collect();
        by_label.sort_by(|a, b| b.1.cmp(&a.1));
        for (label, ns) in &by_label {
            let pct = if total_ns > 0 { *ns as f64 / total_ns as f64 * 100.0 } else { 0.0 };
            eprintln!("  {:20} {:>12} ns  {:5.1}%", label, ns, pct);
        }
        eprintln!("  {:20} {:>12} ns  100.0%", "TOTAL", total_ns);
    }
}

criterion_group!(benches, bench_walk_pcap);
criterion_main!(benches);
