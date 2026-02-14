use aiprotodsl::frame::decode_frame;
use aiprotodsl::value::Value;
use aiprotodsl::{parse, Codec, Endianness, ResolvedProtocol};
use pcap_parser::pcapng::Block as PcapNgBlock;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{Linktype, PcapBlockOwned, PcapError};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

/// Parse quantum string (e.g. "1/256 NM", "360/65536 °", "2^(-10) NM/s", "0.25 FL") into (scale, unit).
fn parse_quantum(quantum_str: &str) -> Option<(f64, String)> {
    let s = quantum_str.trim();
    let (scale_str, unit) = match s.find(' ') {
        Some(i) => (s[..i].trim(), s[i + 1..].trim().to_string()),
        None => (s, String::new()),
    };
    let scale = parse_scale_expr(scale_str)?;
    Some((scale, unit))
}

fn parse_scale_expr(s: &str) -> Option<f64> {
    let s = s.trim();
    // "num/denom" or "num/2^exp"
    if let Some(slash) = s.find('/') {
        let num_str = s[..slash].trim();
        let denom_str = s[slash + 1..].trim();
        let num: f64 = num_str.parse().ok()?;
        let denom: f64 = if let Some(exp_str) = denom_str.strip_prefix("2^") {
            let exp_str = exp_str.trim_matches(|c| c == '(' || c == ')');
            let exp: i32 = exp_str.parse().ok()?;
            if exp >= 0 {
                (1u64 << exp) as f64
            } else {
                1.0 / (1u64 << (-exp) as u32) as f64
            }
        } else {
            denom_str.parse().ok()?
        };
        return Some(num / denom);
    }
    // "2^exp" or "2^(-exp)"
    if let Some(exp_str) = s.strip_prefix("2^") {
        let exp_str = exp_str.trim_matches(|c| c == '(' || c == ')');
        let exp: i32 = exp_str.parse().ok()?;
        return Some(if exp >= 0 {
            (1u64 << exp) as f64
        } else {
            1.0 / (1u64 << (-exp) as u32) as f64
        });
    }
    s.parse::<f64>().ok()
}

/// Format a scalar value with optional quantum (scale + unit). Raw value is shown if conversion fails.
fn format_scalar_with_quantum(v: &Value, quantum: Option<&str>) -> String {
    let (scale, unit) = match quantum.and_then(parse_quantum) {
        Some((s, u)) => (s, u),
        None => return format_scalar_raw(v),
    };
    let raw = match v {
        Value::U8(x) => *x as f64,
        Value::U16(x) => *x as f64,
        Value::U32(x) => *x as f64,
        Value::U64(x) => *x as f64,
        Value::I8(x) => *x as f64,
        Value::I16(x) => *x as f64,
        Value::I32(x) => *x as f64,
        Value::I64(x) => *x as f64,
        Value::Float(x) => *x as f64,
        Value::Double(x) => *x,
        _ => return format_scalar_raw(v),
    };
    let physical = raw * scale;
    if unit.is_empty() {
        format!("{} ({})", physical, format_scalar_raw(v))
    } else {
        format!("{} {} ({})", physical, unit, format_scalar_raw(v))
    }
}

fn format_scalar_raw(v: &Value) -> String {
    match v {
        Value::U8(x) => format!("{}", x),
        Value::U16(x) => format!("{}", x),
        Value::U32(x) => format!("{}", x),
        Value::U64(x) => format!("{}", x),
        Value::I8(x) => format!("{}", x),
        Value::I16(x) => format!("{}", x),
        Value::I32(x) => format!("{}", x),
        Value::I64(x) => format!("{}", x),
        Value::Bool(x) => format!("{}", x),
        Value::Float(x) => format!("{}", x),
        Value::Double(x) => format!("{}", x),
        _ => format!("{:?}", v),
    }
}

/// Format a Value for text dump (compact). Uses resolved protocol to show quantum/units when available.
fn value_to_dump(
    resolved: &ResolvedProtocol,
    container_name: &str,
    field_name: &str,
    v: &Value,
    indent: usize,
) -> String {
    let pad = "  ".repeat(indent);
    match v {
        Value::U8(_) | Value::U16(_) | Value::U32(_) | Value::U64(_)
        | Value::I8(_) | Value::I16(_) | Value::I32(_) | Value::I64(_)
        | Value::Bool(_) | Value::Float(_) | Value::Double(_) => {
            let (quantum, _) = resolved.field_quantum_and_child(container_name, field_name);
            format!("{}{}", pad, format_scalar_with_quantum(v, quantum))
        }
        Value::Bytes(b) => format!("{}hex({})", pad, hex_string(b)),
        Value::Struct(m) => {
            let (_, child_container) = resolved.field_quantum_and_child(container_name, field_name);
            let container = child_container.unwrap_or(container_name);
            let mut lines: Vec<String> = vec![format!("{}struct {{", pad)];
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort();
            for k in keys {
                let sub = value_to_dump(resolved, container, k, m.get(k).unwrap(), indent + 1);
                lines.push(format!("  {}: {}", k, sub.trim_start()));
            }
            lines.push(format!("{}}}", pad));
            lines.join("\n")
        }
        Value::List(lst) => {
            let (_, child_container) = resolved.field_quantum_and_child(container_name, field_name);
            let elem_container = child_container.unwrap_or(container_name);
            if lst.is_empty() {
                format!("{}[]", pad)
            } else if lst.len() == 1 {
                value_to_dump(resolved, elem_container, field_name, &lst[0], indent)
            } else {
                let mut lines: Vec<String> = vec![format!("{}[", pad)];
                for (i, item) in lst.iter().enumerate() {
                    let sub = value_to_dump(resolved, elem_container, &format!("[{}]", i), item, indent + 1);
                    lines.push(format!("  [{}] {}", i, sub.trim_start()));
                }
                lines.push(format!("{}]", pad));
                lines.join("\n")
            }
        }
        Value::Padding => format!("{}<padding>", pad),
    }
}

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ")
}

/// Write record bytes (block without 3-byte transport) with data offset (0 = first byte of record).
fn write_record_hex_with_offset(w: &mut dyn Write, block: &[u8]) -> std::io::Result<()> {
    if block.len() <= 3 {
        return Ok(());
    }
    let record = &block[3..];
    const COLS: usize = 16;
    for (i, chunk) in record.chunks(COLS).enumerate() {
        let start = i * COLS;
        let hex_line = chunk.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        writeln!(w, "  offset {:3}: {}", start, hex_line)?;
    }
    Ok(())
}
 
fn main() -> anyhow::Result<()> {
    let mut raw_args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = if let Some(pos) = raw_args.iter().position(|a| a == "--verbose" || a == "-v") {
        raw_args.remove(pos);
        true
    } else {
        false
    };
    let dump_path: Option<PathBuf> = raw_args
        .iter()
        .position(|a| a.starts_with("--dump"))
        .and_then(|pos| {
            let arg = raw_args.remove(pos);
            if arg == "--dump" {
                Some(PathBuf::from("-"))
            } else if let Some(p) = arg.strip_prefix("--dump=") {
                Some(PathBuf::from(p))
            } else {
                None
            }
        });
    let frame_filter: Option<u64> = raw_args
        .iter()
        .position(|a| a.starts_with("--frame="))
        .and_then(|pos| {
            let arg = raw_args.remove(pos);
            arg.strip_prefix("--frame=").and_then(|s| s.parse().ok())
        });
    let mut args = raw_args.into_iter();
    let pcap_path: PathBuf = args.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("assets/asterix.pcap"));
    let dsl_path: PathBuf = args.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("examples/asterix_family.dsl"));
 
    let src = std::fs::read_to_string(&dsl_path)?;
    let protocol = parse(&src).map_err(|e| anyhow::anyhow!(e))?;
    let resolved = ResolvedProtocol::resolve(protocol).map_err(|e| anyhow::anyhow!(e))?;
    let codec = Codec::new(resolved.clone(), Endianness::Big);
 
    let mut pkt_count: u64 = 0;
    let mut udp_count: u64 = 0;
    let mut block_count: u64 = 0;
    let mut decoded_records: u64 = 0;
    let mut removed_records: u64 = 0;
    let mut unknown_categories: HashMap<u8, u64> = HashMap::new();
    let mut known_categories: HashMap<u8, (u64, u64, u64)> = HashMap::new(); // cat -> (blocks, decoded, removed)
    let mut first_errors: HashMap<u8, String> = HashMap::new();

    let mut dump_writer: Option<Box<dyn Write>> = dump_path.as_ref().map(|p| {
        if p.as_os_str() == "-" {
            Box::new(std::io::stdout()) as Box<dyn Write>
        } else {
            Box::new(File::create(p).expect("create dump file")) as Box<dyn Write>
        }
    });

    // Probe file type (pcap vs pcapng) (pcap vs pcapng) using the magic at start of file.
    let mut probe = [0u8; 4];
    {
        let mut f = File::open(&pcap_path)?;
        f.read_exact(&mut probe)?;
    }
    let is_pcapng = probe == [0x0a, 0x0d, 0x0d, 0x0a];
    if is_pcapng {
        let file = File::open(&pcap_path)?;
        run_pcapng(
            file,
            &codec,
            &resolved,
            verbose,
            &mut dump_writer,
            frame_filter,
            &mut pkt_count,
            &mut udp_count,
            &mut block_count,
            &mut decoded_records,
            &mut removed_records,
            &mut unknown_categories,
            &mut known_categories,
            &mut first_errors,
        )?;
    } else {
        let file = File::open(&pcap_path)?;
        run_legacy_pcap(
            file,
            &codec,
            &resolved,
            verbose,
            &mut dump_writer,
            frame_filter,
            &mut pkt_count,
            &mut udp_count,
            &mut block_count,
            &mut decoded_records,
            &mut removed_records,
            &mut unknown_categories,
            &mut known_categories,
            &mut first_errors,
        )?;
    }
 
    eprintln!("pcap: {}", pcap_path.display());
    eprintln!("dsl:  {}", dsl_path.display());
    eprintln!("packets: {}", pkt_count);
    eprintln!("udp payloads: {}", udp_count);
    eprintln!("asterix blocks (from length field): {}", block_count);
    eprintln!("decoded records: {}", decoded_records);
    eprintln!("removed (validation/decoding errors): {}", removed_records);
    if !known_categories.is_empty() {
        let mut cats: Vec<_> = known_categories.into_iter().collect();
        cats.sort_by_key(|(c, _)| *c);
        eprintln!("known categories summary:");
        for (cat, (blocks, decoded, removed)) in cats {
            eprintln!("  CAT{:03}: blocks={}, decoded={}, removed={}", cat, blocks, decoded, removed);
            if let Some(err) = first_errors.get(&cat) {
                eprintln!("    first error: {}", err);
            }
        }
    }
    if !unknown_categories.is_empty() {
        let mut cats: Vec<_> = unknown_categories.into_iter().collect();
        cats.sort_by_key(|(c, _)| *c);
        eprintln!("unknown categories (skipped):");
        for (cat, n) in cats {
            eprintln!("  CAT{:03}: {}", cat, n);
        }
    }
 
    Ok(())
}

fn run_legacy_pcap<R: Read>(
    file: R,
    codec: &Codec,
    resolved: &ResolvedProtocol,
    verbose: bool,
    dump: &mut Option<Box<dyn Write>>,
    frame_filter: Option<u64>,
    pkt_count: &mut u64,
    udp_count: &mut u64,
    block_count: &mut u64,
    decoded_records: &mut u64,
    removed_records: &mut u64,
    unknown_categories: &mut HashMap<u8, u64>,
    known_categories: &mut HashMap<u8, (u64, u64, u64)>,
    first_errors: &mut HashMap<u8, String>,
) -> anyhow::Result<()> {
    let mut reader = pcap_parser::pcap::LegacyPcapReader::new(1 << 20, file)?;
    let mut linktype: Option<Linktype> = None;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => linktype = Some(h.network),
                    PcapBlockOwned::Legacy(b) => {
                        *pkt_count += 1;
                        let lt = linktype.unwrap_or(Linktype(1));
                        if let Some(udp_payload) = udp_payload_from_linktype(lt, b.data) {
                            *udp_count += 1;
                            process_udp_payload(
                                codec,
                                resolved,
                                udp_payload,
                                *pkt_count,
                                verbose,
                                dump,
                                frame_filter,
                                block_count,
                                decoded_records,
                                removed_records,
                                unknown_categories,
                                known_categories,
                                first_errors,
                            );
                        }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| anyhow::anyhow!("pcap refill error: {:?}", e))?;
            }
            Err(e) => return Err(anyhow::anyhow!("pcap read error: {:?}", e)),
        }
    }
    Ok(())
}

fn run_pcapng<R: Read>(
    file: R,
    codec: &Codec,
    resolved: &ResolvedProtocol,
    verbose: bool,
    dump: &mut Option<Box<dyn Write>>,
    frame_filter: Option<u64>,
    pkt_count: &mut u64,
    udp_count: &mut u64,
    block_count: &mut u64,
    decoded_records: &mut u64,
    removed_records: &mut u64,
    unknown_categories: &mut HashMap<u8, u64>,
    known_categories: &mut HashMap<u8, (u64, u64, u64)>,
    first_errors: &mut HashMap<u8, String>,
) -> anyhow::Result<()> {
    let mut reader = pcap_parser::pcapng::PcapNGReader::new(1 << 20, file)?;
    let mut if_linktypes: Vec<Linktype> = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(b) = block {
                    match &b {
                        PcapNgBlock::InterfaceDescription(idb) => if_linktypes.push(idb.linktype),
                        PcapNgBlock::EnhancedPacket(epb) => {
                            *pkt_count += 1;
                            let lt = if_linktypes.get(epb.if_id as usize).copied().unwrap_or(Linktype(1));
                            let frame = epb.packet_data();
                            if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                *udp_count += 1;
                                process_udp_payload(
                                    codec,
                                    resolved,
                                    udp_payload,
                                    *pkt_count,
                                    verbose,
                                    dump,
                                    frame_filter,
                                    block_count,
                                    decoded_records,
                                    removed_records,
                                    unknown_categories,
                                    known_categories,
                                    first_errors,
                                );
                            }
                        }
                        PcapNgBlock::SimplePacket(spb) => {
                            *pkt_count += 1;
                            let lt = if_linktypes.first().copied().unwrap_or(Linktype(1));
                            let frame = spb.packet_data();
                            if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                *udp_count += 1;
                                process_udp_payload(
                                    codec,
                                    resolved,
                                    udp_payload,
                                    *pkt_count,
                                    verbose,
                                    dump,
                                    frame_filter,
                                    block_count,
                                    decoded_records,
                                    removed_records,
                                    unknown_categories,
                                    known_categories,
                                    first_errors,
                                );
                            }
                        }
                        _ => {}
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| anyhow::anyhow!("pcapng refill error: {:?}", e))?;
            }
            Err(e) => return Err(anyhow::anyhow!("pcapng read error: {:?}", e)),
        }
    }
    Ok(())
}
 
fn process_udp_payload(
    codec: &Codec,
    resolved: &ResolvedProtocol,
    udp_payload: &[u8],
    packet_index: u64,
    verbose: bool,
    dump: &mut Option<Box<dyn Write>>,
    frame_filter: Option<u64>,
    block_count: &mut u64,
    decoded_records: &mut u64,
    removed_records: &mut u64,
    unknown_categories: &mut HashMap<u8, u64>,
    known_categories: &mut HashMap<u8, (u64, u64, u64)>,
    first_errors: &mut HashMap<u8, String>,
) {
    // UDP payload may contain multiple ASTERIX data blocks.
    // Length field = total block size (Category + Length + record data); per Wireshark/commonly used.
    let mut off = 0usize;
    let mut any_block = false;
    while off + 3 <= udp_payload.len() {
        let cat = udp_payload[off];
        let block_len = u16::from_be_bytes([udp_payload[off + 1], udp_payload[off + 2]]) as usize;
        if block_len < 3 || off + block_len > udp_payload.len() {
            break;
        }
        let block = &udp_payload[off..off + block_len];
        *block_count += 1;
        any_block = true;
 
        match codec.decode_transport(block) {
            Ok(transport_values) => {
                if let Some(msg_name) = resolved.message_for_transport_values(&transport_values) {
                    // decode_frame will skip 3-byte transport header.
                    match decode_frame(codec, msg_name, block, Some(3)) {
                        Ok(res) => {
                            *decoded_records += res.messages.len() as u64;
                            *removed_records += res.removed.len() as u64;
                            let entry = known_categories.entry(cat).or_insert((0, 0, 0));
                            entry.0 += 1;
                            entry.1 += res.messages.len() as u64;
                            entry.2 += res.removed.len() as u64;
                            if first_errors.get(&cat).is_none() {
                                if let Some(rm) = res.removed.first() {
                                    first_errors.insert(cat, rm.reason.clone());
                                }
                            }
                            if let Some(w) = dump.as_mut() {
                                if frame_filter.map(|f| f != packet_index).unwrap_or(false) {
                                    // skip dump for this packet
                                } else {
                                    let _ = writeln!(w, "=== packet {}  udp_offset {}  block cat {}  len {} ===", packet_index, off, cat, block_len);
                                    let _ = writeln!(w, "  data (offset 0 = first byte of record, after 3-byte transport):");
                                    let _ = write_record_hex_with_offset(&mut **w, block);
                                    for msg in &res.messages {
                                        let (a, b) = msg.byte_range;
                                        let _ = writeln!(w, "  record bytes [{}-{}]  DECODED {}", a, b, msg.name);
                                        let mut keys: Vec<_> = msg.values.keys().collect();
                                        keys.sort();
                                        for k in keys {
                                            let v = msg.values.get(k).unwrap();
                                            let txt = value_to_dump(resolved, &msg.name, k, v, 0);
                                            let mut lines = txt.lines();
                                            if let Some(first) = lines.next() {
                                                let _ = writeln!(w, "    {}: {}", k, first.trim_start());
                                                for line in lines {
                                                    let _ = writeln!(w, "      {}", line);
                                                }
                                            }
                                        }
                                    }
                                    for rm in &res.removed {
                                        let (a, b) = rm.byte_range;
                                        let _ = writeln!(w, "  record bytes [{}-{}]  REMOVED: {}", a, b, rm.reason);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            *removed_records += 1;
                            let entry = known_categories.entry(cat).or_insert((0, 0, 0));
                            entry.0 += 1;
                            entry.2 += 1;
                            first_errors.entry(cat).or_insert_with(|| e.to_string());
                            if let Some(w) = dump.as_mut() {
                                if frame_filter.map(|f| f != packet_index).unwrap_or(false) {}
                                else {
                                    let _ = writeln!(w, "=== packet {}  udp_offset {}  block cat {}  len {} ===", packet_index, off, cat, block_len);
                                    let _ = writeln!(w, "  data (offset 0 = first byte of record):");
                                    let _ = write_record_hex_with_offset(&mut **w, block);
                                    let _ = writeln!(w, "  block decode error: {}", e);
                                }
                            }
                        }
                    }
                } else {
                    *unknown_categories.entry(cat).or_insert(0) += 1;
                    if let Some(w) = dump.as_mut() {
                        if !frame_filter.map(|f| f != packet_index).unwrap_or(false) {
                            let _ = writeln!(w, "=== packet {}  udp_offset {}  block cat {}  len {}  (unknown category, skipped) ===", packet_index, off, cat, block_len);
                            let _ = write_record_hex_with_offset(&mut **w, block);
                        }
                    }
                }
            }
            Err(_) => {
                *unknown_categories.entry(cat).or_insert(0) += 1;
                if let Some(w) = dump.as_mut() {
                    if !frame_filter.map(|f| f != packet_index).unwrap_or(false) {
                        let _ = writeln!(w, "=== packet {}  udp_offset {}  block cat {}  len {}  (transport decode failed) ===", packet_index, off, cat, block_len);
                        let _ = write_record_hex_with_offset(&mut **w, block);
                    }
                }
            }
        }
 
        off += block_len;
    }
    if verbose && !any_block && !udp_payload.is_empty() {
        let show = udp_payload.len().min(16);
        eprintln!(
            "note: udp payload had no ASTERIX blocks (first {} bytes: {:02x?})",
            show,
            &udp_payload[..show]
        );
    }
}
 
/// Extract UDP payload bytes from a captured frame, using linktype and IPv4/UDP length fields.
/// This avoids including Ethernet padding in short frames.
fn udp_payload_from_linktype(linktype: Linktype, frame: &[u8]) -> Option<&[u8]> {
    let l3 = match linktype.0 {
        1 => ethernet_l3(frame)?,      // DLT_EN10MB
        101 => frame,                  // DLT_RAW
        113 => linux_sll_l3(frame)?,   // DLT_LINUX_SLL
        _ => return None,
    };
    ipv4_udp_payload(l3)
}
 
fn ethernet_l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let mut off = 12usize;
    let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    off += 2;
    // VLAN tags (802.1Q / 802.1ad): skip tag (4 bytes) and read next ethertype.
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < off + 4 + 2 {
            return None;
        }
        off += 4; // TCI + inner ethertype starts after 4 bytes
        ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
        off += 2;
    }
    match ethertype {
        0x0800 => Some(&frame[off..]), // IPv4
        _ => None,
    }
}
 
fn linux_sll_l3(frame: &[u8]) -> Option<&[u8]> {
    // Linux cooked capture v1 (SLL): 16-byte header, protocol at bytes 14..16
    if frame.len() < 16 {
        return None;
    }
    let proto = u16::from_be_bytes([frame[14], frame[15]]);
    match proto {
        0x0800 => Some(&frame[16..]), // IPv4
        _ => None,
    }
}
 
fn ipv4_udp_payload(l3: &[u8]) -> Option<&[u8]> {
    if l3.len() < 20 {
        return None;
    }
    let ver_ihl = l3[0];
    let version = ver_ihl >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 || l3.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
    if total_len < ihl {
        return None;
    }
    let l3_trunc = if total_len <= l3.len() { &l3[..total_len] } else { l3 };
    if l3_trunc.len() < ihl + 8 {
        return None;
    }
    let proto = l3_trunc[9];
    if proto != 17 {
        return None; // not UDP
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

