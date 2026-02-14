//! GUI app for the decode_pcap_gui binary. Load PCAP + DSL and display decoded records in a tree view with @doc tooltips.

#![cfg(feature = "gui")]

use eframe::egui;
use pcap_parser::Linktype;

pub struct DecodedRecord {
    pub packet_index: u64,
    pub block_offset: usize,
    pub category: u8,
    pub message_name: String,
    pub values: std::collections::HashMap<String, crate::Value>,
}

/// Load from in-memory PCAP bytes and DSL text. Used by load_pcap_and_dsl.
fn load_pcap_and_dsl_from_memory(
    pcap_bytes: &[u8],
    dsl_text: &str,
) -> Result<(Vec<DecodedRecord>, crate::ResolvedProtocol), Box<dyn std::error::Error + Send + Sync>> {
    use crate::{parse, Codec, Endianness, ResolvedProtocol};
    use pcap_parser::pcapng::Block as PcapNgBlock;
    use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
    use pcap_parser::{PcapBlockOwned, PcapError};
    use std::io::Read;

    let protocol = parse(dsl_text).map_err(|e| format!("DSL parse: {}", e))?;
    let resolved = ResolvedProtocol::resolve(protocol).map_err(|e| format!("Resolve: {}", e))?;
    let codec = Codec::new(resolved.clone(), Endianness::Big);

    let mut records = Vec::new();
    let mut cursor = std::io::Cursor::new(pcap_bytes);
    let mut probe = [0u8; 4];
    cursor.read_exact(&mut probe)?;
    let is_pcapng = probe == [0x0a, 0x0d, 0x0d, 0x0a];

    let mut pkt_count: u64 = 0;
    let mut linktype = Linktype(1);
    let mut if_linktypes: Vec<Linktype> = vec![];

    if is_pcapng {
        let mut reader = pcap_parser::pcapng::PcapNGReader::new(1 << 20, std::io::Cursor::new(pcap_bytes))
            .map_err(|e| format!("PcapNGReader: {:?}", e))?;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    if let PcapBlockOwned::NG(b) = block {
                        match &b {
                            PcapNgBlock::InterfaceDescription(idb) => if_linktypes.push(idb.linktype),
                            PcapNgBlock::EnhancedPacket(epb) => {
                                pkt_count += 1;
                                let lt = if_linktypes.get(epb.if_id as usize).copied().unwrap_or(Linktype(1));
                                let frame = epb.packet_data();
                                if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                    process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                                }
                            }
                            PcapNgBlock::SimplePacket(spb) => {
                                pkt_count += 1;
                                let lt = if_linktypes.first().copied().unwrap_or(Linktype(1));
                                let frame = spb.packet_data();
                                if let Some(udp_payload) = udp_payload_from_linktype(lt, frame) {
                                    process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                                }
                            }
                            _ => {}
                        }
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| format!("refill: {:?}", e))?,
                Err(e) => return Err(format!("pcapng: {:?}", e).into()),
            }
        }
    } else {
        let mut reader = pcap_parser::pcap::LegacyPcapReader::new(1 << 20, std::io::Cursor::new(pcap_bytes))
            .map_err(|e| format!("LegacyPcapReader: {:?}", e))?;
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(h) => linktype = h.network,
                        PcapBlockOwned::Legacy(b) => {
                            pkt_count += 1;
                            let lt = linktype;
                            if let Some(udp_payload) = udp_payload_from_linktype(lt, b.data) {
                                process_udp(&codec, &resolved, udp_payload, pkt_count, &mut records);
                            }
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => reader.refill().map_err(|e| format!("refill: {:?}", e))?,
                Err(e) => return Err(format!("pcap: {:?}", e).into()),
            }
        }
    }

    Ok((records, resolved))
}

pub fn load_pcap_and_dsl(
    pcap_path: &str,
    dsl_path: &str,
) -> Result<(Vec<DecodedRecord>, crate::ResolvedProtocol), Box<dyn std::error::Error + Send + Sync>> {
    let pcap_bytes = std::fs::read(pcap_path)?;
    let dsl_text = std::fs::read_to_string(dsl_path)?;
    load_pcap_and_dsl_from_memory(&pcap_bytes, &dsl_text)
}

fn process_udp(
    codec: &crate::Codec,
    resolved: &crate::ResolvedProtocol,
    udp_payload: &[u8],
    packet_index: u64,
    records: &mut Vec<DecodedRecord>,
) {
    let mut off = 0usize;
    while off + 3 <= udp_payload.len() {
        let cat = udp_payload[off];
        let block_len = u16::from_be_bytes([udp_payload[off + 1], udp_payload[off + 2]]) as usize;
        if block_len < 3 || off + block_len > udp_payload.len() {
            break;
        }
        let block = &udp_payload[off..off + block_len];
        if let Ok(transport_values) = codec.decode_transport(block) {
            if let Some(msg_name) = resolved.message_for_transport_values(&transport_values) {
                if let Ok(res) = crate::frame::decode_frame(codec, msg_name, block, Some(3)) {
                    for msg in res.messages {
                        records.push(DecodedRecord {
                            packet_index,
                            block_offset: off,
                            category: cat,
                            message_name: msg.name,
                            values: msg.values,
                        });
                    }
                }
            }
        }
        off += block_len;
    }
}

fn udp_payload_from_linktype(linktype: Linktype, frame: &[u8]) -> Option<&[u8]> {
    let l3 = match linktype.0 {
        1 => ethernet_l3(frame)?,
        101 => frame,
        113 => linux_sll_l3(frame)?,
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
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < off + 6 {
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

fn linux_sll_l3(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 16 {
        return None;
    }
    let proto = u16::from_be_bytes([frame[14], frame[15]]);
    match proto {
        0x0800 => Some(&frame[16..]),
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
    if l3_trunc[9] != 17 {
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

// --- GuiApp ---

pub struct GuiApp {
    pub pcap_path: String,
    pub dsl_path: String,
    pub records: Vec<DecodedRecord>,
    pub resolved: Option<crate::ResolvedProtocol>,
    pub selected_index: Option<usize>,
    pub load_error: Option<String>,
    pub _default_pcap: String,
    pub _default_dsl: String,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        for (_key, font_id) in style.text_styles.iter_mut() {
            font_id.size = (font_id.size * 1.35).round().max(16.0);
        }
        cc.egui_ctx.set_style(style);

        let default_pcap = std::path::PathBuf::from("assets/cat_034_048.pcap")
            .canonicalize()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "assets/cat_034_048.pcap".to_string());
        let default_dsl = std::path::PathBuf::from("examples/asterix_family.dsl")
            .canonicalize()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "examples/asterix_family.dsl".to_string());

        GuiApp {
            pcap_path: default_pcap.clone(),
            dsl_path: default_dsl.clone(),
            records: Vec::new(),
            resolved: None,
            selected_index: None,
            load_error: None,
            _default_pcap: default_pcap,
            _default_dsl: default_dsl,
        }
    }

    pub fn load(&mut self) {
        self.load_error = None;
        self.records.clear();
        self.resolved = None;
        self.selected_index = None;

        match load_pcap_and_dsl(&self.pcap_path, &self.dsl_path) {
            Ok((records, resolved)) => {
                self.records = records;
                self.resolved = Some(resolved);
            }
            Err(e) => self.load_error = Some(e.to_string()),
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui: &mut egui::Ui| {
            ui.horizontal(|ui: &mut egui::Ui| {
                ui.label("PCAP:");
                ui.text_edit_singleline(&mut self.pcap_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.pcap_path = p.display().to_string();
                    }
                }
                ui.label("DSL:");
                ui.text_edit_singleline(&mut self.dsl_path);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.dsl_path = p.display().to_string();
                    }
                }
                if ui.button("Load").clicked() {
                    self.load();
                }
            });
            if let Some(ref err) = self.load_error {
                ui.colored_label(egui::Color32::RED, err);
            } else if !self.records.is_empty() {
                ui.label(format!("{} decoded record(s)", self.records.len()));
            }
        });

        egui::SidePanel::left("records")
            .resizable(true)
            .default_width(220.0)
            .show(ctx, |ui: &mut egui::Ui| {
                ui.heading("Records");
                ui.separator();
                let mut by_packet: std::collections::BTreeMap<u64, Vec<usize>> = std::collections::BTreeMap::new();
                for (idx, r) in self.records.iter().enumerate() {
                    by_packet.entry(r.packet_index).or_default().push(idx);
                }
                egui::ScrollArea::vertical().show(ui, |ui: &mut egui::Ui| {
                    for (pkt, indices) in by_packet {
                        let label = format!("Packet {}", pkt);
                        let id = egui::Id::new(("packet", pkt));
                        egui::CollapsingHeader::new(label)
                            .id_salt(id)
                            .default_open(pkt <= 2)
                            .show(ui, |ui| {
                                for idx in indices {
                                    let r = &self.records[idx];
                                    let label = format!("Cat{:03} #{}", r.category, idx);
                                    let sel = self.selected_index == Some(idx);
                                    if ui.selectable_label(sel, label).clicked() {
                                        self.selected_index = Some(idx);
                                    }
                                }
                            });
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui: &mut egui::Ui| {
            if let (Some(idx), Some(resolved)) = (self.selected_index, self.resolved.as_ref()) {
                if let Some(record) = self.records.get(idx) {
                    ui.heading(format!(
                        "{} — packet {}, block offset {}",
                        record.message_name, record.packet_index, record.block_offset
                    ));
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        tree_ui(ui, &record.message_name, &record.values, resolved);
                    });
                }
            } else if !self.records.is_empty() {
                ui.label("Select a record from the list.");
            }
        });
    }
}

fn tree_ui(
    ui: &mut egui::Ui,
    container: &str,
    values: &std::collections::HashMap<String, crate::Value>,
    resolved: &crate::ResolvedProtocol,
) {
    let mut keys: Vec<_> = values.keys().collect();
    keys.sort();
    for k in keys {
        let v = values.get(k).unwrap();
        if let crate::Value::List(lst) = v {
            if lst.is_empty() {
                continue;
            }
        }
        value_tree_ui(ui, resolved, container, k, v);
    }
}

fn value_tree_ui(
    ui: &mut egui::Ui,
    resolved: &crate::ResolvedProtocol,
    container: &str,
    field_name: &str,
    v: &crate::Value,
) {
    use crate::value_summary_line;
    use crate::Value;

    let summary = value_summary_line(resolved, container, field_name, v);
    match v {
        Value::Struct(m) => {
            let (_, child_container) = resolved.field_quantum_and_child(container, field_name);
            let child_container = child_container.unwrap_or(container);
            let id = egui::Id::new(("struct", container, field_name));
            let doc = resolved.field_doc(container, field_name);
            ui.push_id(id, |ui| {
                let resp = egui::CollapsingHeader::new(format!("{}: struct", field_name))
                    .id_salt(id)
                    .default_open(false)
                    .show(ui, |ui| {
                        if let Some(d) = doc {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                                )
                                .wrap(),
                            );
                        }
                        let mut keys: Vec<_> = m.keys().collect();
                        keys.sort();
                        for k in keys {
                            let val = m.get(k).unwrap();
                            if let Value::List(lst) = val {
                                if lst.is_empty() {
                                    continue;
                                }
                            }
                            value_tree_ui(ui, resolved, child_container, k, val);
                        }
                    });
                if let Some(d) = doc {
                    resp.header_response.on_hover_text(d);
                }
            });
        }
        Value::List(lst) => {
            if lst.is_empty() {
                return;
            }
            let (_, child_container) = resolved.field_quantum_and_child(container, field_name);
            let elem_container = child_container.unwrap_or(container);
            if lst.len() == 1 {
                value_tree_ui(ui, resolved, elem_container, field_name, &lst[0]);
            } else {
                let id = egui::Id::new(("list", container, field_name));
                let doc = resolved.field_doc(container, field_name);
                ui.push_id(id, |ui| {
                    let resp = egui::CollapsingHeader::new(format!("{}: [{} items]", field_name, lst.len()))
                        .id_salt(id)
                        .default_open(false)
                        .show(ui, |ui| {
                            if let Some(d) = doc {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                                    )
                                    .wrap(),
                                );
                            }
                            for (i, item) in lst.iter().enumerate() {
                                value_tree_ui(ui, resolved, elem_container, &format!("[{}]", i), item);
                            }
                        });
                    if let Some(d) = doc {
                        resp.header_response.on_hover_text(d);
                    }
                });
            }
        }
        _ => {
            let doc = resolved.field_doc(container, field_name);
            let inner = ui.horizontal(|ui: &mut egui::Ui| {
                ui.monospace(field_name);
                ui.label("→");
                ui.label(&summary);
            });
            if let Some(d) = doc {
                inner.response.on_hover_text(d);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(d).small().color(ui.visuals().weak_text_color()),
                    )
                    .wrap(),
                );
            }
        }
    }
}

/// Entry point for the native binary.
pub fn run_native() -> eframe::Result<()> {
    eframe::run_native(
        "AIProtoDSL — PCAP + DSL viewer",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}
